"""PCAP/network capture analyzer for Harvest-Now-Decrypt-Later (HNDL) exposure scoring.

Pure-stdlib engine (no dpkt/scapy required) that parses PCAP and PCAPNG captures,
reassembles TCP streams (reassembly-lite), extracts real TLS handshake parameters
(ClientHello/ServerHello: cipher suites, supported groups, signature algorithms,
SNI), and scores each flow's HNDL exposure using V x S x R x E fed by the actual
negotiated cryptography instead of worst-case defaults.

V = quantum-vulnerability factor derived from the negotiated cipher suite/group
S = Sensitivity (classification level)
R = Retention (how long data is kept)
E = Exposure (time window of capture)

Also ingests Zeek ssl.log (TSV and JSON variants) and Suricata EVE JSON (tls events),
normalizing them into the same flow-record shape.
"""
from __future__ import annotations

import json
import re
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from .tls_probe import TLS_SIGALG_CODEPOINTS, TLS_GROUP_CODEPOINTS


class FlowProtocol(str, Enum):
    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"
    SSH = "SSH"
    UNKNOWN = "UNKNOWN"


class QuantumVulnerability(str, Enum):
    BROKEN = "BROKEN"          # RSA, ECDSA, ECDH, DH, DSA - broken by Shor's
    WEAKENED = "WEAKENED"      # AES-128, 3DES, SHA-1, MD5 - weakened by Grover's
    SAFE = "SAFE"              # AES-256, SHA-256/384/512, ChaCha20
    PQC_READY = "PQC_READY"    # ML-KEM, ML-DSA, SLH-DSA, HQC
    HYBRID = "HYBRID"          # X25519+ML-KEM, etc.


MAX_PACKETS_DEFAULT = 200_000
MAX_BYTES_DEFAULT = 256 * 1024 * 1024
MAX_STREAM_BYTES = 64 * 1024
MAX_CONNS = 100_000
MAX_PENDING_SEGMENTS = 256

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW_LINUX = 101
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
RAW_LINK_TYPES = {DLT_RAW_BSD, DLT_RAW_LINUX, DLT_IPV4, DLT_IPV6}

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100, 0x9200}

GREASE_CHECK = lambda v: (v & 0x0F0F) == 0x0A0A  # noqa: E731

GROUP_NAMES: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0016: "secp256k1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x11E4: "SecP256r1MLKEM768",
    0x11E5: "X25519Kyber768",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft01",
    0x639B: "MLKEM512",
    0x639C: "MLKEM768",
    0x639D: "MLKEM1024",
}
for _g_code, _g_name in TLS_GROUP_CODEPOINTS.items():
    GROUP_NAMES.setdefault(_g_code, _g_name)

SIGALG_NAMES: dict[int, str] = dict(TLS_SIGALG_CODEPOINTS)

_CIPHER_SUITE_TABLE: dict[int, dict[str, Any]] = {
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "kex": "TLS1.3-(EC)DHE", "enc": "AES-128-GCM"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "kex": "TLS1.3-(EC)DHE", "enc": "AES-256-GCM"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "kex": "TLS1.3-(EC)DHE", "enc": "ChaCha20-Poly1305"},
    0x1304: {"name": "TLS_AES_128_CCM_SHA256", "kex": "TLS1.3-(EC)DHE", "enc": "AES-128-CCM"},
    0x1305: {"name": "TLS_AES_128_CCM_8_SHA256", "kex": "TLS1.3-(EC)DHE", "enc": "AES-128-CCM-8"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kex": "ECDHE-RSA", "enc": "AES-256-GCM"},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE-RSA", "enc": "AES-128-GCM"},
    0xC02E: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE-ECDSA", "enc": "AES-128-GCM"},
    0xC02C: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "kex": "ECDHE-ECDSA", "enc": "AES-256-GCM"},
    0xC02B: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE-ECDSA", "enc": "AES-128-GCM"},
    0xC02D: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "ECDHE-ECDSA", "enc": "ChaCha20-Poly1305"},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "ECDHE-ECDSA", "enc": "ChaCha20-Poly1305"},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "ECDHE-RSA", "enc": "ChaCha20-Poly1305"},
    0xC028: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "kex": "ECDHE-RSA", "enc": "AES-256-CBC"},
    0xC027: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "kex": "ECDHE-RSA", "enc": "AES-128-CBC"},
    0xC024: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "kex": "ECDHE-ECDSA", "enc": "AES-256-CBC"},
    0xC023: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "kex": "ECDHE-ECDSA", "enc": "AES-128-CBC"},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "kex": "ECDHE-RSA", "enc": "AES-256-CBC"},
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "kex": "ECDHE-RSA", "enc": "AES-128-CBC"},
    0xC00A: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "kex": "ECDHE-ECDSA", "enc": "AES-256-CBC"},
    0xC009: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "kex": "ECDHE-ECDSA", "enc": "AES-128-CBC"},
    0x009F: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "kex": "DHE-RSA", "enc": "AES-256-GCM"},
    0x009E: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kex": "DHE-RSA", "enc": "AES-128-GCM"},
    0x00AA: {"name": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "DHE-RSA", "enc": "ChaCha20-Poly1305"},
    0x006B: {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "kex": "DHE-RSA", "enc": "AES-256-CBC"},
    0x0067: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "kex": "DHE-RSA", "enc": "AES-128-CBC"},
    0x0039: {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "kex": "DHE-RSA", "enc": "AES-256-CBC"},
    0x0033: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "kex": "DHE-RSA", "enc": "AES-128-CBC"},
    0x009D: {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "kex": "RSA", "enc": "AES-256-GCM"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "kex": "RSA", "enc": "AES-128-GCM"},
    0x003D: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA256", "kex": "RSA", "enc": "AES-256-CBC"},
    0x003C: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA256", "kex": "RSA", "enc": "AES-128-CBC"},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kex": "RSA", "enc": "AES-256-CBC"},
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kex": "RSA", "enc": "AES-128-CBC"},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kex": "RSA", "enc": "3DES-CBC"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "kex": "RSA", "enc": "RC4"},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "kex": "RSA", "enc": "RC4"},
    0x00FF: {"name": "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "kex": "", "enc": ""},
}

CIPHER_SUITE_NAMES: dict[int, str] = {
    code: meta["name"] for code, meta in _CIPHER_SUITE_TABLE.items()
}

CIPHER_SUITE_DB: dict[str, dict[str, Any]] = {
    meta["name"]: {"kex": meta["kex"], "enc": meta["enc"], "code": code}
    for code, meta in _CIPHER_SUITE_TABLE.items()
}

OPENSSL_NAME_ALIASES: dict[str, str] = {
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-AES256-SHA256": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "DHE-RSA-AES128-SHA256": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "DHE-RSA-AES256-SHA": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES128-SHA": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
    "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
}

VERSION_LABELS: dict[str, str] = {
    "TLSv10": "TLSv1.0",
    "TLSv11": "TLSv1.1",
    "TLSv12": "TLSv1.2",
    "TLSv13": "TLSv1.3",
    "TLS 1.0": "TLSv1.0",
    "TLS 1.1": "TLSv1.1",
    "TLS 1.2": "TLSv1.2",
    "TLS 1.3": "TLSv1.3",
}

# Port-based sensitivity scoring (data value weighting retained from v1)
PORT_SENSITIVITY: dict[int, float] = {
    443: 0.8,
    8443: 0.8,
    993: 0.9,
    995: 0.9,
    465: 0.9,
    587: 0.85,
    22: 0.95,
    2222: 0.95,
    3389: 0.9,
    5432: 0.95,
    3306: 0.95,
    6379: 0.9,
    27017: 0.9,
    8080: 0.7,
    80: 0.6,
    21: 0.8,
    25: 0.7,
    110: 0.7,
    143: 0.7,
    53: 0.5,
}


@dataclass
class TLSFlow:
    """A parsed TLS flow from capture or log data."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: FlowProtocol
    cipher_suite: str = ""
    negotiated_group: str = ""
    key_exchange: str = ""
    signature_algorithm: str = ""
    certificate_alg: str = ""
    certificate_key_size: int = 0
    sni: str = ""
    tls_version: str = ""
    pq_hybrid: bool = False
    cipher_extraction: bool = False
    source: str = "pcap"
    supported_groups: list[str] = field(default_factory=list)
    offered_ciphers: list[str] = field(default_factory=list)
    signature_algorithms: list[str] = field(default_factory=list)
    validation_status: str = ""
    ja3_hash: str = ""
    hndl_score: float = 0.0
    vulnerability: QuantumVulnerability = QuantumVulnerability.BROKEN
    risk_level: str = "CRITICAL"
    recommendations: list[str] = field(default_factory=list)


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


def _group_name(code: int) -> str:
    return GROUP_NAMES.get(code, f"0x{code:04X}")


def _sigalg_name(code: int) -> str:
    return SIGALG_NAMES.get(code, f"0x{code:04X}")


def _cipher_name(code: int) -> tuple[str, dict[str, Any]]:
    meta = _CIPHER_SUITE_TABLE.get(code)
    if meta is None:
        return f"0x{code:04X}", {}
    return meta["name"], meta


def _normalize_cipher_name(raw: str) -> str:
    if not raw:
        return ""
    if raw.startswith("0x"):
        return raw
    return OPENSSL_NAME_ALIASES.get(raw, raw)


def _suite_meta_by_name(name: str) -> dict[str, Any]:
    return CIPHER_SUITE_DB.get(name, {})


def _group_is_pqc(group: str) -> bool:
    upper = group.upper().replace("-", "").replace("_", "")
    return "MLKEM" in upper or "KYBER" in upper


def _group_is_hybrid(group: str) -> bool:
    if not _group_is_pqc(group):
        return False
    upper = group.upper()
    tokens = ("X25519", "SECP", "P256", "P384", "P521")
    return any(t in upper for t in tokens)


def _iter_tls_records(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    pos = 0
    n = len(data)
    while pos + 5 <= n:
        ctype = data[pos]
        version = int.from_bytes(data[pos + 1:pos + 3], "big")
        rlen = int.from_bytes(data[pos + 3:pos + 5], "big")
        if ctype not in (20, 21, 22, 23):
            return
        if not (0x0300 <= version <= 0x0304):
            return
        if rlen > MAX_STREAM_BYTES * 4:
            return
        body = data[pos + 5:pos + 5 + rlen]
        if len(body) < rlen:
            return
        yield ctype, version, body
        pos += 5 + rlen


def _walk_handshake_messages(handshake_stream: bytes) -> Iterator[tuple[int, bytes]]:
    pos = 0
    n = len(handshake_stream)
    while pos + 4 <= n:
        htype = handshake_stream[pos]
        hlen = int.from_bytes(handshake_stream[pos + 1:pos + 4], "big")
        if hlen > MAX_STREAM_BYTES * 4:
            return
        msg = handshake_stream[pos + 4:pos + 4 + hlen]
        if len(msg) < hlen:
            return
        yield htype, msg
        pos += 4 + hlen


def _read_u16(buf: bytes, pos: int) -> tuple[int, int]:
    if pos + 2 > len(buf):
        return -1, pos
    return int.from_bytes(buf[pos:pos + 2], "big"), pos + 2


def _parse_client_hello(msg: bytes) -> dict[str, Any] | None:
    try:
        if len(msg) < 35:
            return None
        out: dict[str, Any] = {
            "version": int.from_bytes(msg[0:2], "big"),
            "cipher_suites": [],
            "sni": "",
            "groups": [],
            "key_share_groups": [],
            "sigalgs": [],
            "supported_versions": [],
        }
        pos = 2 + 32
        sid_len = msg[pos]
        pos += 1 + sid_len
        cs_len, pos = _read_u16(msg, pos)
        if cs_len < 0 or pos + cs_len > len(msg):
            return None
        for i in range(pos, pos + cs_len - 1, 2):
            out["cipher_suites"].append(int.from_bytes(msg[i:i + 2], "big"))
        pos += cs_len
        comp_len = msg[pos]
        pos += 1 + comp_len
        if pos + 2 > len(msg):
            return out
        ext_len, pos = _read_u16(msg, pos)
        if ext_len < 0:
            return out
        ext_end = min(pos + ext_len, len(msg))
        while pos + 4 <= ext_end:
            etype, pos = _read_u16(msg, pos)
            elen, pos = _read_u16(msg, pos)
            if elen < 0 or pos + elen > len(msg):
                return out
            edata = msg[pos:pos + elen]
            pos += elen
            if etype == 0x0000 and len(edata) >= 5:
                sni_type = edata[2]
                name_len = int.from_bytes(edata[3:5], "big")
                if sni_type == 0 and 5 + name_len <= len(edata):
                    out["sni"] = edata[5:5 + name_len].decode("ascii", errors="replace")
            elif etype == 0x000A and len(edata) >= 2:
                glen = int.from_bytes(edata[0:2], "big")
                for i in range(2, min(2 + glen, len(edata)) - 1, 2):
                    g = int.from_bytes(edata[i:i + 2], "big")
                    if not _is_grease(g):
                        out["groups"].append(g)
            elif etype == 0x000D and len(edata) >= 2:
                slen = int.from_bytes(edata[0:2], "big")
                for i in range(2, min(2 + slen, len(edata)) - 1, 2):
                    out["sigalgs"].append(int.from_bytes(edata[i:i + 2], "big"))
            elif etype == 0x0017:
                out["max_fragment"] = int.from_bytes(edata[0:2], "big") if len(edata) >= 2 else 0
            elif etype == 0x002B and len(edata) >= 1:
                vlen = edata[0]
                for i in range(1, min(1 + vlen, len(edata)) - 1, 2):
                    out["supported_versions"].append(int.from_bytes(edata[i:i + 2], "big"))
            elif etype == 0x0033 and len(edata) >= 2:
                klen = int.from_bytes(edata[0:2], "big")
                kp = 2
                while kp + 4 <= min(2 + klen, len(edata)):
                    g = int.from_bytes(edata[kp:kp + 2], "big")
                    kx_len = int.from_bytes(edata[kp + 2:kp + 4], "big")
                    if not _is_grease(g):
                        out["key_share_groups"].append(g)
                    kp += 4 + kx_len
        return out
    except (IndexError, struct.error):
        return None


def _parse_server_hello(msg: bytes) -> dict[str, Any] | None:
    try:
        if len(msg) < 38:
            return None
        out: dict[str, Any] = {
            "version": int.from_bytes(msg[0:2], "big"),
            "cipher_suite": -1,
            "selected_version": 0,
            "key_share_group": 0,
        }
        pos = 2 + 32
        sid_len = msg[pos]
        pos += 1 + sid_len
        if pos + 3 > len(msg):
            return None
        out["cipher_suite"] = int.from_bytes(msg[pos:pos + 2], "big")
        pos += 2 + 1
        if pos + 2 > len(msg):
            return out
        ext_len, pos = _read_u16(msg, pos)
        if ext_len < 0:
            return out
        ext_end = min(pos + ext_len, len(msg))
        while pos + 4 <= ext_end:
            etype, pos = _read_u16(msg, pos)
            elen, pos = _read_u16(msg, pos)
            if elen < 0 or pos + elen > len(msg):
                return out
            edata = msg[pos:pos + elen]
            pos += elen
            if etype == 0x002B and len(edata) >= 2:
                out["selected_version"] = int.from_bytes(edata[0:2], "big")
            elif etype == 0x0033 and len(edata) >= 4:
                out["key_share_group"] = int.from_bytes(edata[0:2], "big")
        return out
    except (IndexError, struct.error):
        return None


class _DirStream:
    __slots__ = ("next_seq", "pending", "data", "truncated")

    def __init__(self) -> None:
        self.next_seq: int | None = None
        self.pending: dict[int, bytes] = {}
        self.data = bytearray()
        self.truncated = False

    def add(self, seq: int, payload: bytes, syn: bool) -> None:
        if syn:
            if self.next_seq is None:
                self.next_seq = seq + 1
            seq += 1
            if not payload:
                return
        if not payload:
            return
        if self.next_seq is None:
            self.next_seq = seq
        if self.truncated:
            return
        if seq + len(payload) <= self.next_seq:
            return
        if seq < self.next_seq:
            payload = payload[self.next_seq - seq:]
            seq = self.next_seq
        if seq == self.next_seq:
            self._append(payload)
            while not self.truncated and self.next_seq in self.pending:
                nxt = self.pending.pop(self.next_seq)
                self._append(nxt)
        else:
            if len(self.pending) < MAX_PENDING_SEGMENTS:
                existing = self.pending.get(seq)
                if existing is None or len(existing) < len(payload):
                    self.pending[seq] = bytes(payload)

    def _append(self, payload: bytes) -> None:
        self.next_seq += len(payload)
        room = MAX_STREAM_BYTES - len(self.data)
        if room <= 0:
            self.truncated = True
            return
        if room < len(payload):
            self.data.extend(payload[:room])
            self.truncated = True
        else:
            self.data.extend(payload)


@dataclass
class _Conn:
    key_a: tuple
    key_b: tuple
    streams: dict[tuple, _DirStream] = field(default_factory=dict)
    client_key: tuple | None = None
    client_hello: dict[str, Any] | None = None
    server_hello: dict[str, Any] | None = None
    server_key: tuple | None = None
    tls_seen: bool = False
    ssh_banner: bool = False
    record_gate: bool = False
    record_version: int = 0

    def __post_init__(self) -> None:
        self.streams = {self.key_a: _DirStream(), self.key_b: _DirStream()}


class _CaptureParser:
    def __init__(self) -> None:
        self.conns: dict[tuple, _Conn] = {}

    def feed_packet(self, linktype: int, pkt: bytes) -> None:
        ip_payload = _decode_link_layer(linktype, pkt)
        if not ip_payload:
            return
        parsed = _decode_network_layer(ip_payload)
        if not parsed:
            return
        proto, src_ip, dst_ip, l4 = parsed
        if proto != 6 or len(l4) < 20:
            return
        sport = int.from_bytes(l4[0:2], "big")
        dport = int.from_bytes(l4[2:4], "big")
        seq = int.from_bytes(l4[4:8], "big")
        doff = ((l4[12] >> 4) & 0xF) * 4
        if doff < 20 or doff > len(l4):
            return
        flags = l4[13]
        payload = l4[doff:]

        key_a = (src_ip, sport, dst_ip, dport)
        key_b = (dst_ip, dport, src_ip, sport)
        conn = self.conns.get(key_a) or self.conns.get(key_b)
        if conn is None:
            if len(self.conns) >= MAX_CONNS:
                return
            conn = _Conn(key_a=key_a, key_b=key_b)
            self.conns[key_a] = conn
        conn.streams[key_a].add(seq, payload, bool(flags & 0x02))
        if payload[:4] == b"SSH-":
            conn.ssh_banner = True
            return
        if payload and payload[0] in (0x14, 0x15, 0x16, 0x17):
            conn.record_gate = True
        if conn.record_gate:
            self._inspect_tls(conn, key_a)

    def _inspect_tls(self, conn: _Conn, direction_key: tuple) -> None:
        data = bytes(conn.streams[direction_key].data)
        if not data:
            return
        candidates = [0]
        if not (data[0] == 0x16 and len(data) >= 5 and 0x0300 <= int.from_bytes(data[1:3], "big") <= 0x0304):
            candidates = [
                m.start() for m in re.finditer(rb"\x16\x03[\x00-\x04]", data[:MAX_STREAM_BYTES])
            ][:64] or [0]
        best_handshake = b""
        best_version = conn.record_version
        records_seen = False
        for start in candidates:
            records = list(_iter_tls_records(data[start:]))
            if not records:
                continue
            records_seen = True
            handshake = b"".join(body for ctype, _, body in records if ctype == 22)
            if len(handshake) > len(best_handshake):
                best_handshake = handshake
                best_version = records[0][1]
        if not records_seen:
            return
        conn.tls_seen = True
        if not best_handshake:
            if not conn.record_version:
                conn.record_version = best_version
            return
        if not conn.record_version:
            conn.record_version = best_version
        for htype, msg in _walk_handshake_messages(best_handshake):
            if htype == 0x01 and conn.client_hello is None:
                hello = _parse_client_hello(msg)
                if hello:
                    conn.client_hello = hello
                    conn.client_key = direction_key
            elif htype == 0x02 and conn.server_hello is None:
                shello = _parse_server_hello(msg)
                if shello:
                    conn.server_hello = shello
                    conn.server_key = direction_key

    def build_flows(self) -> list[TLSFlow]:
        flows: list[TLSFlow] = []
        for conn in self.conns.values():
            flow = self._flow_from_conn(conn)
            if flow is not None:
                flows.append(flow)
        return flows

    def _flow_from_conn(self, conn: _Conn) -> TLSFlow | None:
        ch = conn.client_hello
        sh = conn.server_hello

        if conn.ssh_banner and ch is None and sh is None:
            key = conn.key_a if conn.streams[conn.key_a].data else conn.key_b
            return TLSFlow(
                src_ip=key[0], dst_ip=key[2],
                src_port=key[1], dst_port=key[3],
                protocol=FlowProtocol.SSH,
                source="pcap",
            )

        if ch is not None:
            ck = conn.client_key or conn.key_a
            sk = (ck[2], ck[3], ck[0], ck[1])
        elif sh is not None:
            sk = conn.server_key or conn.key_a
            ck = (sk[2], sk[3], sk[0], sk[1])
        elif conn.tls_seen:
            dk = None
            for key, stream in conn.streams.items():
                if stream.data:
                    dk = key
                    break
            if dk is None:
                return None
            proto = _protocol_from_record_version(conn.record_version)
            return TLSFlow(
                src_ip=dk[0], dst_ip=dk[2],
                src_port=dk[1], dst_port=dk[3],
                protocol=proto,
                tls_version=proto.value if proto != FlowProtocol.UNKNOWN else "",
                cipher_extraction=False,
                source="pcap",
            )
        else:
            return None

        flow = TLSFlow(
            src_ip=ck[0], dst_ip=ck[2],
            src_port=ck[1], dst_port=ck[3],
            protocol=FlowProtocol.TLS_1_2,
            source="pcap",
        )
        if ch is not None:
            flow.sni = ch.get("sni", "")
            flow.offered_ciphers = [_cipher_name(c)[0] for c in ch.get("cipher_suites", [])]
            flow.supported_groups = [_group_name(g) for g in ch.get("groups", [])]
            flow.signature_algorithms = [_sigalg_name(s) for s in ch.get("sigalgs", [])]
            flow.cipher_extraction = True
            versions = ch.get("supported_versions", [])
            if 0x0304 in versions:
                flow.protocol = FlowProtocol.TLS_1_3
                flow.tls_version = "TLSv1.3"
            else:
                flow.protocol = _protocol_from_record_version(
                    ch.get("version") or conn.record_version)
                flow.tls_version = flow.protocol.value
        if sh is not None:
            chosen = sh.get("cipher_suite", -1)
            if chosen >= 0:
                name, meta = _cipher_name(chosen)
                flow.cipher_suite = name
                flow.key_exchange = meta.get("kex", "")
            group = sh.get("key_share_group", 0)
            if group:
                flow.negotiated_group = _group_name(group)
            if sh.get("selected_version"):
                flow.protocol = _protocol_from_version_code(sh["selected_version"])
                flow.tls_version = flow.protocol.value
            flow.cipher_extraction = True

        if not flow.cipher_suite and ch and len(ch.get("cipher_suites", [])) == 1:
            only = ch["cipher_suites"][0]
            name, meta = _cipher_name(only)
            flow.cipher_suite = name
            flow.key_exchange = meta.get("kex", "")

        if flow.negotiated_group:
            flow.pq_hybrid = _group_is_pqc(flow.negotiated_group)
        elif ch is not None:
            flow.pq_hybrid = any(
                _group_is_pqc(g) for g in flow.supported_groups
            ) or any(_group_is_pqc(_group_name(g)) for g in ch.get("key_share_groups", []))

        return flow


def _protocol_from_record_version(version: int) -> FlowProtocol:
    return {
        0x0301: FlowProtocol.TLS_1_0,
        0x0302: FlowProtocol.TLS_1_1,
        0x0303: FlowProtocol.TLS_1_2,
        0x0304: FlowProtocol.TLS_1_3,
    }.get(version, FlowProtocol.UNKNOWN)


def _protocol_from_version_code(code: int) -> FlowProtocol:
    if code >= 0x0304:
        return FlowProtocol.TLS_1_3
    return _protocol_from_record_version(code)


def _decode_link_layer(linktype: int, pkt: bytes) -> bytes | None:
    if linktype == DLT_EN10MB:
        if len(pkt) < 14:
            return None
        ethertype = int.from_bytes(pkt[12:14], "big")
        offset = 14
        hops = 0
        while ethertype in VLAN_ETHERTYPES and hops < 4:
            if len(pkt) < offset + 4:
                return None
            ethertype = int.from_bytes(pkt[offset + 2:offset + 4], "big")
            offset += 4
            hops += 1
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return None
        return pkt[offset:]
    if linktype == DLT_LINUX_SLL:
        if len(pkt) < 16:
            return None
        protocol = int.from_bytes(pkt[14:16], "big")
        offset = 16
        hops = 0
        while protocol in VLAN_ETHERTYPES and hops < 4:
            if len(pkt) < offset + 4:
                return None
            protocol = int.from_bytes(pkt[offset + 2:offset + 4], "big")
            offset += 4
            hops += 1
        if protocol not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return None
        return pkt[offset:]
    if linktype in RAW_LINK_TYPES:
        if not pkt:
            return None
        version = (pkt[0] >> 4) & 0xF
        if version == 4 and linktype != DLT_IPV6:
            return pkt
        if version == 6 and linktype != DLT_IPV4:
            return pkt
        return None
    return None


def _decode_network_layer(ip_data: bytes) -> tuple[int, str, str, bytes] | None:
    if not ip_data:
        return None
    version = (ip_data[0] >> 4) & 0xF
    if version == 4:
        return _decode_ipv4(ip_data)
    if version == 6:
        return _decode_ipv6(ip_data)
    return None


def _decode_ipv4(ip_data: bytes) -> tuple[int, str, str, bytes] | None:
    if len(ip_data) < 20:
        return None
    ihl = (ip_data[0] & 0xF) * 4
    if ihl < 20 or len(ip_data) < ihl:
        return None
    flags_frag = int.from_bytes(ip_data[6:8], "big")
    frag_offset = (flags_frag & 0x1FFF) * 8
    more_fragments = bool(flags_frag & 0x2000)
    if frag_offset or more_fragments:
        return None
    proto = ip_data[9]
    src_ip = socket.inet_ntoa(ip_data[12:16])
    dst_ip = socket.inet_ntoa(ip_data[16:20])
    total_len = int.from_bytes(ip_data[2:4], "big")
    end = min(total_len, len(ip_data)) if total_len >= ihl else len(ip_data)
    return proto, src_ip, dst_ip, ip_data[ihl:end]


def _decode_ipv6(ip_data: bytes) -> tuple[int, str, str, bytes] | None:
    if len(ip_data) < 40:
        return None
    next_header = ip_data[6]
    src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
    payload = ip_data[40:]
    hops = 0
    while next_header in (0, 43, 44, 51, 60, 135) and hops < 8:
        if len(payload) < 8:
            return None
        if next_header == 44:
            frag_off = int.from_bytes(payload[2:4], "big") >> 3
            if frag_off:
                return None
            next_header = payload[0]
            payload = payload[8:]
        else:
            if next_header == 51:
                ext_len = (payload[1] + 2) * 4
            else:
                ext_len = (payload[1] + 1) * 8
            if ext_len > len(payload):
                return None
            next_header = payload[0]
            payload = payload[ext_len:]
        hops += 1
    if next_header != 6:
        return None
    return 6, src_ip, dst_ip, payload


def iter_capture_packets(
    fh,
    max_packets: int = MAX_PACKETS_DEFAULT,
    max_bytes: int = MAX_BYTES_DEFAULT,
) -> Iterator[tuple[int, bytes]]:
    head = fh.read(4)
    fh.seek(0)
    if head in PCAP_MAGICS:
        yield from _iter_classic_pcap(fh, max_packets, max_bytes)
    elif head == PCAPNG_MAGIC:
        yield from _iter_pcapng(fh, max_packets, max_bytes)
    else:
        return


def _iter_classic_pcap(fh, max_packets: int, max_bytes: int) -> Iterator[tuple[int, bytes]]:
    header = fh.read(24)
    if len(header) < 24:
        return
    endian = PCAP_MAGICS[header[:4]]
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    consumed = 24
    count = 0
    while count < max_packets and consumed < max_bytes:
        ph = fh.read(16)
        if len(ph) < 16:
            return
        incl_len = struct.unpack(endian + "I", ph[8:12])[0]
        if incl_len == 0 or incl_len > 0x4000000:
            return
        pkt = fh.read(incl_len)
        if len(pkt) < incl_len:
            return
        consumed += 16 + incl_len
        count += 1
        yield linktype, pkt


def _iter_pcapng(fh, max_packets: int, max_bytes: int) -> Iterator[tuple[int, bytes]]:
    endian = "<"
    interfaces: list[int] = []
    consumed = 0
    count = 0
    while consumed < max_bytes:
        blk_hdr = fh.read(8)
        if len(blk_hdr) < 8:
            return
        btype_raw = blk_hdr[:4]
        if btype_raw == PCAPNG_MAGIC:
            bom = fh.read(4)
            fh.seek(-4, 1)
            if len(bom) == 4 and struct.unpack("<I", bom)[0] == 0x1A2B3C4D:
                endian = "<"
            else:
                endian = ">"
        btype = struct.unpack("<I", btype_raw)[0]
        blen_raw = blk_hdr[4:8]
        if len(blen_raw) < 4:
            return
        try:
            blen = struct.unpack(endian + "I", blen_raw)[0]
        except struct.error:
            return
        if blen < 12 or blen > 0x4000000:
            return
        body = fh.read(blen - 12)
        if len(body) < blen - 12:
            return
        fh.read(4)
        consumed += blen
        if btype == 0x00000001 and len(body) >= 4:
            lt = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append(lt)
            continue
        if btype == 0x00000006 and len(body) >= 20:
            iid = struct.unpack(endian + "I", body[0:4])[0]
            cap_len = struct.unpack(endian + "I", body[12:16])[0]
            if cap_len > len(body) - 20:
                continue
            pkt = body[20:20 + cap_len]
            lt = interfaces[iid] if iid < len(interfaces) else DLT_EN10MB
            count += 1
            if count > max_packets:
                return
            yield lt, pkt
        elif btype == 0x00000003 and len(body) >= 4:
            orig_len = struct.unpack(endian + "I", body[0:4])[0]
            avail = len(body) - 4
            pkt = body[4:4 + min(orig_len, avail)]
            lt = interfaces[0] if interfaces else DLT_EN10MB
            count += 1
            if count > max_packets:
                return
            yield lt, pkt


def _classify_flow(flow: TLSFlow) -> None:
    if flow.protocol == FlowProtocol.SSH:
        flow.vulnerability = QuantumVulnerability.BROKEN
        return

    negotiated_pq = _group_is_pqc(flow.negotiated_group) if flow.negotiated_group else False
    negotiated_hybrid = _group_is_hybrid(flow.negotiated_group) if flow.negotiated_group else False

    suite_meta = _suite_meta_by_name(flow.cipher_suite)
    kex = flow.key_exchange or suite_meta.get("kex", "")
    enc = suite_meta.get("enc", "")
    weak_enc = any(w in enc.upper() for w in ("AES-128", "3DES", "RC4"))

    if negotiated_hybrid:
        flow.vulnerability = QuantumVulnerability.HYBRID
        return
    if negotiated_pq:
        flow.vulnerability = (
            QuantumVulnerability.WEAKENED if weak_enc else QuantumVulnerability.PQC_READY
        )
        return

    if kex:
        flow.vulnerability = QuantumVulnerability.BROKEN
        return

    offered_names = [n for n in flow.offered_ciphers if n and not n.startswith("0x")]
    if offered_names and not any(n.startswith("TLS_") for n in offered_names):
        flow.vulnerability = QuantumVulnerability.BROKEN
        return

    legacy_weak = flow.protocol in (FlowProtocol.TLS_1_0, FlowProtocol.TLS_1_1)
    if legacy_weak:
        flow.vulnerability = QuantumVulnerability.WEAKENED
        return

    flow.vulnerability = QuantumVulnerability.BROKEN


_VULN_FACTORS: dict[QuantumVulnerability, float] = {
    QuantumVulnerability.BROKEN: 1.0,
    QuantumVulnerability.WEAKENED: 0.75,
    QuantumVulnerability.SAFE: 0.5,
    QuantumVulnerability.HYBRID: 0.25,
    QuantumVulnerability.PQC_READY: 0.05,
}


def _score_hndl(vulnerability: QuantumVulnerability, dst_port: int, src_port: int) -> float:
    v = _VULN_FACTORS.get(vulnerability, 1.0)
    port_value = PORT_SENSITIVITY.get(dst_port, PORT_SENSITIVITY.get(src_port, 0.5))
    s = 0.7 + 0.3 * port_value
    r = 0.9
    e = 1.0
    return min(100.0, max(0.0, 100.0 * v * s * r * e))


def _determine_risk_level(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    elif score >= 10:
        return "LOW"
    return "NONE"


def _generate_recommendations(flow: TLSFlow) -> list[str]:
    recs: list[str] = []
    if flow.vulnerability in (QuantumVulnerability.BROKEN,):
        recs.append("Replace with ML-KEM-768 (FIPS 203) for key exchange")
        recs.append("Replace with ML-DSA-65 (FIPS 204) for signatures")
    elif flow.vulnerability == QuantumVulnerability.WEAKENED:
        if not flow.pq_hybrid:
            recs.append("Enable hybrid PQC key exchange (X25519MLKEM768, IANA 0x11EC)")
        recs.append("Upgrade to AES-256-GCM or ChaCha20-Poly1305")
    elif flow.vulnerability == QuantumVulnerability.HYBRID:
        recs.append("Consider pure PQC (ML-KEM-768) when peers support it")
    elif flow.vulnerability == QuantumVulnerability.PQC_READY:
        recs.append("Maintain PQC configuration; monitor peer compatibility")

    if not flow.cipher_extraction:
        recs.append(
            "Cipher details unavailable from capture; verify endpoints manually "
            "(conservative worst-case scoring applied)"
        )
    if flow.protocol in (FlowProtocol.TLS_1_0, FlowProtocol.TLS_1_1):
        recs.append("Upgrade to TLS 1.3")
    suite_meta = _suite_meta_by_name(flow.cipher_suite)
    if "AES-128" in suite_meta.get("enc", ""):
        recs.append("Negotiated AES-128 is Grover-weakened; prefer AES-256-GCM")
    return recs


def flow_to_dict(flow: TLSFlow, deep_scan: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "src": f"{flow.src_ip}:{flow.src_port}",
        "dst": f"{flow.dst_ip}:{flow.dst_port}",
        "src_ip": flow.src_ip,
        "dst_port": flow.dst_port,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "protocol": flow.protocol.value,
        "tls_version": flow.tls_version,
        "sni": flow.sni,
        "cipher_suite": flow.cipher_suite,
        "negotiated_group": flow.negotiated_group,
        "pq_hybrid": flow.pq_hybrid,
        "supported_groups": flow.supported_groups,
        "cipher_extraction": flow.cipher_extraction,
        "source": flow.source,
        "validation_status": flow.validation_status,
        "ja3_hash": flow.ja3_hash,
        "vulnerability": flow.vulnerability.value,
        "hndl_score": round(flow.hndl_score, 2),
        "risk_level": flow.risk_level,
        "recommendations": flow.recommendations,
    }
    if deep_scan:
        out["offered_ciphers"] = flow.offered_ciphers
        out["signature_algorithms"] = flow.signature_algorithms
        out["key_exchange"] = flow.key_exchange
    return out


def _finalize_result(
    flows: list[TLSFlow],
    path_label: str,
    fmt: str,
    deep_scan: bool,
    top_n: int,
) -> dict[str, Any]:
    for flow in flows:
        _classify_flow(flow)
        flow.hndl_score = _score_hndl(flow.vulnerability, flow.dst_port, flow.src_port)
        flow.risk_level = _determine_risk_level(flow.hndl_score)
        flow.recommendations = _generate_recommendations(flow)

    ordered = sorted(flows, key=lambda f: f.hndl_score, reverse=True)

    by_vuln: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for f in flows:
        by_vuln[f.vulnerability.value] = by_vuln.get(f.vulnerability.value, 0) + 1
        by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1

    avg = sum(f.hndl_score for f in flows) / len(flows) if flows else 0.0
    extraction_failures = sum(1 for f in flows if not f.cipher_extraction)

    return {
        "file": path_label,
        "format": fmt,
        "total_flows": len(flows),
        "average_hndl_score": round(avg, 2),
        "by_vulnerability": by_vuln,
        "by_risk_level": by_risk,
        "flows": [flow_to_dict(f, deep_scan=deep_scan) for f in ordered[:top_n]],
        "summary": {
            "total_flows": len(flows),
            "critical_flows": by_risk.get("CRITICAL", 0),
            "high_risk_flows": by_risk.get("HIGH", 0) + by_risk.get("CRITICAL", 0),
            "high_flows": by_risk.get("HIGH", 0),
            "medium_flows": by_risk.get("MEDIUM", 0),
            "low_flows": by_risk.get("LOW", 0),
            "safe_flows": by_risk.get("NONE", 0),
            "average_hndl_score": round(avg, 2),
            "cipher_extraction_failures": extraction_failures,
        },
    }


def detect_capture_format(path: str | Path) -> str:
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return "unknown"
    if head[:4] in PCAP_MAGICS or head[:4] == PCAPNG_MAGIC:
        return "pcap"
    stripped = head.lstrip()
    if stripped.startswith(b"#separator") or stripped.startswith(b"#fields"):
        return "zeek"
    if stripped.startswith(b"{"):
        try:
            first_line = stripped.splitlines()[0].decode("utf-8", errors="replace")
            obj = json.loads(first_line)
            if isinstance(obj, dict) and ("event_type" in obj or "tls" in obj):
                return "suricata"
        except (json.JSONDecodeError, IndexError):
            pass
        return "suricata"
    return "unknown"


def analyze_pcap(
    pcap_path: str | Path,
    deep_scan: bool = False,
    top_n: int = 10,
    fmt: str = "auto",
) -> dict[str, Any]:
    """Analyze a capture/log file for HNDL exposure.

    Args:
        pcap_path: Path to a PCAP/PCAPNG capture, Zeek ssl.log or Suricata EVE JSON.
        deep_scan: Include extended per-flow metadata (offered ciphers, sigalgs, JA3).
        top_n: Maximum number of highest-risk flows returned.
        fmt: Input format hint: auto|pcap|zeek|suricata.

    Returns:
        Dictionary with flow analysis results and HNDL scores.
    """
    path = Path(pcap_path)
    if not path.exists():
        return {"error": f"File not found: {pcap_path}", "flows": [], "summary": {}}

    resolved_fmt = fmt
    if resolved_fmt in ("auto", ""):
        detected = detect_capture_format(path)
        resolved_fmt = detected if detected != "unknown" else "pcap"

    if resolved_fmt == "zeek":
        return analyze_zeek_ssl_log(path, deep_scan=deep_scan, top_n=top_n)
    if resolved_fmt == "suricata":
        return analyze_suricata_eve(path, deep_scan=deep_scan, top_n=top_n)

    try:
        parser = _CaptureParser()
        with open(path, "rb") as fh:
            for linktype, pkt in iter_capture_packets(fh):
                parser.feed_packet(linktype, pkt)
        flows = parser.build_flows()
    except OSError as exc:
        return {"error": f"Unable to read capture: {exc}", "flows": [], "summary": {}}

    return _finalize_result(flows, str(path), resolved_fmt, deep_scan, top_n)


def _flow_from_log_record(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    *,
    cipher_raw: str = "",
    group_raw: str = "",
    sni: str = "",
    version_raw: str = "",
    source: str,
    validation_status: str = "",
    ja3_hash: str = "",
) -> TLSFlow:
    flow = TLSFlow(
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=_protocol_from_label(version_raw),
        sni=sni,
        tls_version=_normalize_version(version_raw),
        cipher_suite=_normalize_cipher_name(cipher_raw),
        negotiated_group=_normalize_group_name(group_raw),
        validation_status=validation_status,
        ja3_hash=ja3_hash,
        source=source,
        cipher_extraction=bool(cipher_raw),
    )
    if flow.cipher_suite and not flow.cipher_suite.startswith("0x"):
        meta = _suite_meta_by_name(flow.cipher_suite)
        flow.key_exchange = meta.get("kex", "")
        flow.offered_ciphers = [flow.cipher_suite]
    if flow.negotiated_group:
        flow.pq_hybrid = _group_is_pqc(flow.negotiated_group)
    return flow


def _protocol_from_label(label: str) -> FlowProtocol:
    normalized = _normalize_version(label)
    for proto in FlowProtocol:
        if proto.value == normalized:
            return proto
    if label:
        return FlowProtocol.TLS_1_2
    return FlowProtocol.UNKNOWN


def _normalize_version(label: str) -> str:
    return VERSION_LABELS.get(label.strip(), label.strip())


def _normalize_group_name(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or raw == "-":
        return ""
    upper = raw.upper()
    for name in GROUP_NAMES.values():
        if name.upper() == upper:
            return name
    compact = upper.replace("_", "").replace("-", "")
    for name in GROUP_NAMES.values():
        if name.upper().replace("_", "") == compact:
            return name
    return raw


def analyze_zeek_ssl_log(
    log_path: str | Path,
    deep_scan: bool = False,
    top_n: int = 10,
) -> dict[str, Any]:
    """Normalize a Zeek ssl.log (TSV or JSON variant) into flow records."""
    path = Path(log_path)
    if not path.exists():
        return {"error": f"File not found: {log_path}", "flows": [], "summary": {}}

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return _finalize_result([], str(path), "zeek", deep_scan, top_n)

    flows: list[TLSFlow] = []
    if lines[0].startswith("{"):
        for ln in lines:
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            ident = obj.get("id", {})
            flows.append(_flow_from_log_record(
                str(ident.get("orig_h", obj.get("id.orig_h", ""))),
                int(ident.get("orig_p", obj.get("id.orig_p", 0)) or 0),
                str(ident.get("resp_h", obj.get("id.resp_h", ""))),
                int(ident.get("resp_p", obj.get("id.resp_p", 0)) or 0),
                cipher_raw=obj.get("cipher", ""),
                group_raw=obj.get("curve", ""),
                sni=obj.get("server_name", ""),
                version_raw=obj.get("version", ""),
                source="zeek",
                validation_status=obj.get("validation_status", ""),
            ))
    else:
        separator = "\t"
        columns: list[str] | None = None
        for ln in lines:
            if ln.startswith("#separator"):
                token = ln.split(None, 1)[1].strip() if len(ln.split(None, 1)) > 1 else "\\x09"
                if token.lower().startswith("\\x") and len(token) >= 4:
                    try:
                        separator = chr(int(token[2:4], 16))
                    except ValueError:
                        separator = "\t"
                elif token:
                    separator = token[0]
                continue
            if ln.startswith("#fields"):
                columns = ln.split(separator)[1:]
                continue
            if ln.startswith("#"):
                continue
            if columns is None:
                continue
            parts = ln.split(separator)
            row = dict(zip(columns, parts))
            try:
                src_port = int(row.get("id.orig_p", "0"))
                dst_port = int(row.get("id.resp_p", "0"))
            except ValueError:
                continue
            flows.append(_flow_from_log_record(
                row.get("id.orig_h", ""), src_port,
                row.get("id.resp_h", ""), dst_port,
                cipher_raw=row.get("cipher", ""),
                group_raw=row.get("curve", ""),
                sni=row.get("server_name", ""),
                version_raw=row.get("version", ""),
                source="zeek",
                validation_status=row.get("validation_status", ""),
            ))

    return _finalize_result([f for f in flows if f.src_ip], str(path), "zeek", deep_scan, top_n)


def analyze_suricata_eve(
    eve_path: str | Path,
    deep_scan: bool = False,
    top_n: int = 10,
) -> dict[str, Any]:
    """Normalize Suricata EVE JSON (event_type=tls records) into flow records."""
    path = Path(eve_path)
    if not path.exists():
        return {"error": f"File not found: {eve_path}", "flows": [], "summary": {}}

    flows: list[TLSFlow] = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if obj.get("event_type") != "tls":
            continue
        tls = obj.get("tls", {}) or {}
        ja3 = tls.get("ja3") if isinstance(tls.get("ja3"), dict) else {}
        flows.append(_flow_from_log_record(
            str(obj.get("src_ip", "")),
            int(obj.get("src_port", 0) or 0),
            str(obj.get("dest_ip", "")),
            int(obj.get("dest_port", 0) or 0),
            cipher_raw=tls.get("ciphersuite", tls.get("cipher", "")),
            group_raw="",
            sni=tls.get("sni", ""),
            version_raw=tls.get("version", ""),
            source="suricata",
            ja3_hash=ja3.get("hash", "") or tls.get("ja3_hash", ""),
        ))

    return _finalize_result([f for f in flows if f.src_ip], str(path), "suricata", deep_scan, top_n)
