"""PCAP flow analyzer for Harvest-Now-Decrypt-Later (HNDL) exposure scoring.

Parses PCAP captures to extract TLS/SSH handshakes, classifies cipher suites,
and scores each flow's HNDL exposure using V x S x R x E formula.

V = Value of data (port-based sensitivity)
S = Sensitivity (classification level)
R = Retention (how long data is kept)
E = Exposure (time window of capture)
"""
from __future__ import annotations

import math
import struct
import socket
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


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


@dataclass
class TLSFlow:
    """A parsed TLS flow from PCAP data."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: FlowProtocol
    cipher_suite: str = ""
    key_exchange: str = ""
    signature_algorithm: str = ""
    certificate_alg: str = ""
    certificate_key_size: int = 0
    sni: str = ""
    hndl_score: float = 0.0
    vulnerability: QuantumVulnerability = QuantumVulnerability.BROKEN
    risk_level: str = "CRITICAL"
    recommendations: list[str] = field(default_factory=list)


# Known TLS cipher suite mappings (IANA -> algorithm breakdown)
CIPHER_SUITE_DB: dict[str, dict[str, Any]] = {
    # Quantum-vulnerable (RSA key exchange)
    "TLS_RSA_WITH_AES_128_CBC_SHA": {"kex": "RSA", "enc": "AES-128-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_RSA_WITH_AES_256_CBC_SHA": {"kex": "RSA", "enc": "AES-256-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_RSA_WITH_AES_128_CBC_SHA256": {"kex": "RSA", "enc": "AES-128-CBC", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_RSA_WITH_AES_256_CBC_SHA256": {"kex": "RSA", "enc": "AES-256-CBC", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_RSA_WITH_AES_128_GCM_SHA256": {"kex": "RSA", "enc": "AES-128-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_RSA_WITH_AES_256_GCM_SHA384": {"kex": "RSA", "enc": "AES-256-GCM", "mac": "SHA-384", "vuln": QuantumVulnerability.BROKEN},
    # Quantum-vulnerable (ECDHE with ECDSA)
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": {"kex": "ECDHE-RSA", "enc": "AES-128-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": {"kex": "ECDHE-RSA", "enc": "AES-256-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {"kex": "ECDHE-RSA", "enc": "AES-128-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {"kex": "ECDHE-RSA", "enc": "AES-256-GCM", "mac": "SHA-384", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": {"kex": "ECDHE-ECDSA", "enc": "AES-128-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": {"kex": "ECDHE-ECDSA", "enc": "AES-256-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {"kex": "ECDHE-ECDSA", "enc": "AES-128-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {"kex": "ECDHE-ECDSA", "enc": "AES-256-GCM", "mac": "SHA-384", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {"kex": "ECDHE-RSA", "enc": "ChaCha20-Poly1305", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": {"kex": "ECDHE-ECDSA", "enc": "ChaCha20-Poly1305", "mac": "SHA-256", "vuln": QuantumVulnerability.BROKEN},
    # Post-quantum ready (hybrid)
    "TLS_X25519_MLKEM768": {"kex": "X25519+ML-KEM-768", "enc": "AES-256-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.HYBRID},
    "TLS_MLKEM768": {"kex": "ML-KEM-768", "enc": "AES-256-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.PQC_READY},
    "TLS_MLKEM1024": {"kex": "ML-KEM-1024", "enc": "AES-256-GCM", "mac": "SHA-256", "vuln": QuantumVulnerability.PQC_READY},
    # Weak
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": {"kex": "RSA", "enc": "3DES-CBC", "mac": "SHA-1", "vuln": QuantumVulnerability.WEAKENED},
    "TLS_RSA_WITH_RC4_128_SHA": {"kex": "RSA", "enc": "RC4", "mac": "SHA-1", "vuln": QuantumVulnerability.WEAKENED},
    "TLS_RSA_WITH_RC4_128_MD5": {"kex": "RSA", "enc": "RC4", "mac": "MD5", "vuln": QuantumVulnerability.WEAKENED},
}

# Port-based sensitivity scoring (V)
PORT_SENSITIVITY: dict[int, float] = {
    443: 0.8,   # HTTPS - web traffic
    8443: 0.8,  # HTTPS alt
    993: 0.9,   # IMAPS - email
    995: 0.9,   # POP3S - email
    465: 0.9,   # SMTPS - email
    587: 0.85,  # SMTP submission
    22: 0.95,   # SSH - remote access
    2222: 0.95, # SSH alt
    3389: 0.9,  # RDP
    5432: 0.95, # PostgreSQL
    3306: 0.95, # MySQL
    6379: 0.9,  # Redis
    27017: 0.9, # MongoDB
    8080: 0.7,  # HTTP alt
    80: 0.6,    # HTTP
    21: 0.8,    # FTP
    25: 0.7,    # SMTP
    110: 0.7,   # POP3
    143: 0.7,   # IMAP
    53: 0.5,    # DNS
}


def _extract_flows_from_pcap(data: bytes) -> list[TLSFlow]:
    """Parse raw PCAP data to extract TLS/SSH flows.

    This is a simplified parser that looks for TLS ClientHello and
    ServerHello records in the packet data.
    """
    flows: list[TLSFlow] = []

    # PCAP global header (24 bytes)
    if len(data) < 24:
        return flows

    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
        return flows

    swapped = magic == 0xd4c3b2a1
    link_type = struct.unpack(">I" if swapped else "<I", data[20:24])[0]

    # Ethernet header (14 bytes) if link_type == 1
    offset = 24
    while offset < len(data) - 16:
        # Packet header (16 bytes)
        if offset + 16 > len(data):
            break
        incl_len = struct.unpack(">I" if swapped else "<I", data[offset + 8:offset + 12])[0]
        if incl_len == 0 or offset + 16 + incl_len > len(data):
            break

        pkt_data = data[offset + 16:offset + 16 + incl_len]
        offset += 16 + incl_len

        # Skip Ethernet header
        eth_offset = 14 if link_type == 1 else 0
        if eth_offset + 20 > len(pkt_data):
            continue

        # IP header
        ip_data = pkt_data[eth_offset:]
        version_ihl = ip_data[0]
        ip_version = (version_ihl >> 4) & 0xF
        if ip_version != 4:
            continue

        ihl = (version_ihl & 0xF) * 4
        protocol = ip_data[9]

        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        # TCP header
        if protocol != 6:
            continue

        tcp_offset = ihl
        if tcp_offset + 20 > len(ip_data):
            continue

        src_port = struct.unpack(">H", ip_data[tcp_offset:tcp_offset + 2])[0]
        dst_port = struct.unpack(">H", ip_data[tcp_offset + 2:tcp_offset + 4])[0]
        data_offset = ((ip_data[tcp_offset + 12] >> 4) & 0xF) * 4
        tcp_payload = ip_data[tcp_offset + data_offset:]

        if len(tcp_payload) < 5:
            continue

        # TLS record
        if tcp_payload[0] == 0x16 and tcp_payload[1] == 0x03:
            tls_version = struct.unpack(">H", tcp_payload[3:5])[0]
            protocol_map = {
                0x0301: FlowProtocol.TLS_1_0,
                0x0302: FlowProtocol.TLS_1_1,
                0x0303: FlowProtocol.TLS_1_2,
            }
            # TLS 1.3 also uses 0x0303 in record layer
            protocol = protocol_map.get(tls_version, FlowProtocol.TLS_1_2)

            # Try to find SNI in ClientHello
            sni = ""
            if len(tcp_payload) > 5 and tcp_payload[5] == 0x01:  # ClientHello
                sni_match = _extract_sni(tcp_payload[5:])
                if sni_match:
                    sni = sni_match

            flows.append(TLSFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                sni=sni,
            ))

        # SSH banner
        elif tcp_payload[:3] == b"SSH":
            flows.append(TLSFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=FlowProtocol.SSH,
            ))

    return flows


def _extract_sni(data: bytes) -> str:
    """Extract Server Name Indication from TLS ClientHello."""
    try:
        if len(data) < 43:
            return ""
        # Skip header (5 bytes), client version (2), random (32)
        session_id_len = data[38]
        offset = 39 + session_id_len
        if offset + 2 > len(data):
            return ""
        cipher_suites_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len
        if offset + 1 > len(data):
            return ""
        compression_len = data[offset]
        offset += 1 + compression_len
        if offset + 2 > len(data):
            return ""
        extensions_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + extensions_len
        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack(">H", data[offset:offset + 2])[0]
            ext_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            if ext_type == 0:  # SNI
                if offset + 9 <= len(data):
                    name_len = struct.unpack(">H", data[offset + 7:offset + 9])[0]
                    if offset + 9 + name_len <= len(data):
                        return data[offset + 9:offset + 9 + name_len].decode("ascii", errors="ignore")
            offset += 4 + ext_len
    except Exception:
        pass
    return ""


def _score_hndl(flow: TLSFlow) -> float:
    """Calculate HNDL exposure score using V x S x R x E formula.

    V = Value (port-based sensitivity)
    S = Sensitivity (default 0.7 for encrypted data)
    R = Retention (default 5 years for web, 10 for email)
    E = Exposure (recency, 0-1)
    """
    v = PORT_SENSITIVITY.get(flow.dst_port, PORT_SENSITIVITY.get(flow.src_port, 0.5))
    s = 0.7  # Default sensitivity for encrypted data
    r = min(1.0, 5.0 / 10.0)  # Default 5-year retention
    e = 0.8  # Default exposure (recent capture)

    score = 100.0 * v * s * r * e
    return min(100.0, max(0.0, score))


def _classify_vulnerability(flow: TLSFlow) -> QuantumVulnerability:
    """Classify the quantum vulnerability of a flow."""
    if flow.protocol == FlowProtocol.SSH:
        return QuantumVulnerability.BROKEN  # SSH typically uses ECDH/RSA

    if flow.cipher_suite:
        info = CIPHER_SUITE_DB.get(flow.cipher_suite, {})
        return info.get("vuln", QuantumVulnerability.BROKEN)

    # Default: TLS < 1.3 with classical crypto is vulnerable
    if flow.protocol in (FlowProtocol.TLS_1_0, FlowProtocol.TLS_1_1):
        return QuantumVulnerability.WEAKENED

    return QuantumVulnerability.BROKEN  # Assume worst case


def _determine_risk_level(score: float) -> str:
    """Map HNDL score to risk level."""
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
    """Generate migration recommendations for a flow."""
    recs = []
    if flow.vulnerability == QuantumVulnerability.BROKEN:
        recs.append("Replace with ML-KEM-768 (FIPS 203) for key exchange")
        recs.append("Replace with ML-DSA-65 (FIPS 204) for signatures")
    elif flow.vulnerability == QuantumVulnerability.WEAKENED:
        recs.append("Upgrade to AES-256-GCM or ChaCha20-Poly1305")
        recs.append("Replace SHA-1/MD5 with SHA-256 or SHA-384")
    elif flow.vulnerability == QuantumVulnerability.HYBRID:
        recs.append("Consider pure PQC when available")

    if flow.protocol in (FlowProtocol.TLS_1_0, FlowProtocol.TLS_1_1):
        recs.append("Upgrade to TLS 1.3")

    return recs


def analyze_pcap(pcap_path: str | Path) -> dict[str, Any]:
    """Analyze a PCAP file for HNDL exposure.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        Dictionary with flow analysis results and HNDL scores.
    """
    path = Path(pcap_path)
    if not path.exists():
        return {"error": f"File not found: {pcap_path}", "flows": []}

    data = path.read_bytes()
    flows = _extract_flows_from_pcap(data)

    for flow in flows:
        flow.vulnerability = _classify_vulnerability(flow)
        flow.hndl_score = _score_hndl(flow)
        flow.risk_level = _determine_risk_level(flow.hndl_score)
        flow.recommendations = _generate_recommendations(flow)

    # Aggregate statistics
    total = len(flows)
    by_vuln: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for f in flows:
        by_vuln[f.vulnerability.value] = by_vuln.get(f.vulnerability.value, 0) + 1
        by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1

    avg_score = sum(f.hndl_score for f in flows) / total if total > 0 else 0.0

    return {
        "file": str(path),
        "total_flows": total,
        "average_hndl_score": round(avg_score, 2),
        "by_vulnerability": by_vuln,
        "by_risk_level": by_risk,
        "flows": [
            {
                "src": f"{f.src_ip}:{f.src_port}",
                "dst": f"{f.dst_ip}:{f.dst_port}",
                "protocol": f.protocol.value,
                "sni": f.sni,
                "cipher_suite": f.cipher_suite,
                "vulnerability": f.vulnerability.value,
                "hndl_score": round(f.hndl_score, 2),
                "risk_level": f.risk_level,
                "recommendations": f.recommendations,
            }
            for f in flows
        ],
        "summary": {
            "critical_flows": by_risk.get("CRITICAL", 0),
            "high_flows": by_risk.get("HIGH", 0),
            "medium_flows": by_risk.get("MEDIUM", 0),
            "low_flows": by_risk.get("LOW", 0),
            "safe_flows": by_risk.get("NONE", 0),
        },
    }
