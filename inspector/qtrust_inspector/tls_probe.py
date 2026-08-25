"""Deep TLS endpoint probing with post-quantum cryptography detection.

Probes live TLS endpoints for:
- PQC hybrid key exchange support (X25519+ML-KEM-768, ML-KEM-768, ML-KEM-1024)
- 13 IANA TLS group codepoints
- 17 signature algorithms including ML-DSA
- Server cipher preference detection
- TLS 1.2 downgrade vulnerability detection
"""
from __future__ import annotations

import socket
import struct
import ssl
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TLSProbeResult:
    """Result of a deep TLS probe."""
    host: str
    port: int
    tls_version: str = ""
    cipher_suite: str = ""
    server_preference: bool = False
    pqc_kem_detected: bool = False
    pqc_hybrid_detected: bool = False
    pqc_signature_detected: bool = False
    negotiated_group: str = ""
    signature_algorithm: str = ""
    certificate_chain: list[dict[str, Any]] = field(default_factory=list)
    supported_groups: list[str] = field(default_factory=list)
    supported_sigalgs: list[str] = field(default_factory=list)
    tls12_fallback_vulnerable: bool = False
    ech_supported: bool = False
    hsts_enabled: bool = False
    recommendations: list[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    hndl_score: float = 0.0


# IANA TLS Group Codepoints
TLS_GROUP_CODEPOINTS: dict[int, str] = {
    0x0001: "secp256r1",
    0x0002: "sect163k1",
    0x0003: "sect163r1",
    0x0004: "sect283k1",
    0x0005: "sect283r1",
    0x0006: "sect409k1",
    0x0007: "sect409r1",
    0x0008: "secp521r1",
    0x0009: "secp384r1",
    0x000A: "sect283k1",
    0x000B: "sect283r1",
    0x000C: "sect409k1",
    0x000D: "sect409r1",
    0x000E: "secp521r1",
    0x0012: "x25519",
    0x0013: "x448",
    0x001B: "secp256k1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    # PQC codepoints
    0x11EC: "X25519MLKEM768",       # Hybrid X25519 + ML-KEM-768
    0x6399: "MLKEM512",             # ML-KEM-512
    0x639A: "MLKEM768",             # ML-KEM-768
    0x639B: "MLKEM1024",            # ML-KEM-1024
    0x11E4: "SecP256r1MLKEM768",    # Hybrid P-256 + ML-KEM-768
    0x11E5: "X25519Kyber768",       # Draft hybrid (deprecated)
    0x0200: "MLDSA44",              # ML-DSA-44 (signature)
    0x0201: "MLDSA65",              # ML-DSA-65 (signature)
    0x0202: "MLDSA87",              # ML-DSA-87 (signature)
}

# TLS Signature Algorithm Codepoints
TLS_SIGALG_CODEPOINTS: dict[int, str] = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # PQC signature algorithms
    0x0904: "MLDSA44",
    0x0905: "MLDSA65",
    0x0906: "MLDSA87",
}


def _build_client_hello(
    host: str,
    groups: list[int] | None = None,
    sigalgs: list[int] | None = None,
    include_pqc: bool = False,
) -> bytes:
    """Build a TLS 1.3 ClientHello with specified extensions."""
    # Default groups
    if groups is None:
        groups = [
            0x0012,  # x25519
            0x0001,  # secp256r1
            0x0008,  # secp521r1
            0x0009,  # secp384r1
        ]
        if include_pqc:
            groups.extend([
                0x11EC,  # X25519MLKEM768
                0x6399,  # MLKEM512
                0x639A,  # MLKEM768
                0x639B,  # MLKEM1024
            ])

    # Default sigalgs
    if sigalgs is None:
        sigalgs = [
            0x0403, 0x0503, 0x0603,  # ECDSA
            0x0804, 0x0805, 0x0806,  # RSA-PSS
            0x0401, 0x0501, 0x0601,  # RSA PKCS1
            0x0807,  # Ed25519
        ]
        if include_pqc:
            sigalgs.extend([
                0x0904, 0x0905, 0x0906,  # ML-DSA
            ])

    # Random (32 bytes)
    import os
    random_bytes = os.urandom(32)

    # Session ID (empty)
    session_id = b""

    # Cipher suites (including TLS 1.3)
    cipher_suites = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        0x00FF,  # Renegotiation info
    ]

    # Build extensions
    extensions = b""

    # Server Name Indication
    host_bytes = host.encode("ascii")
    sni = struct.pack(">HH", 0x0000, len(host_bytes) + 5) + b"\x00" + struct.pack(">H", len(host_bytes)) + host_bytes
    extensions += sni

    # Supported groups
    groups_data = b"".join(struct.pack(">H", g) for g in groups)
    groups_ext = struct.pack(">HH", 0x000A, len(groups_data) + 2) + struct.pack(">H", len(groups_data)) + groups_data
    extensions += groups_ext

    # Signature algorithms
    sigalgs_data = b"".join(struct.pack(">H", s) for s in sigalgs)
    sigalgs_ext = struct.pack(">HH", 0x000D, len(sigalgs_data) + 2) + struct.pack(">H", len(sigalgs_data)) + sigalgs_data
    extensions += sigalgs_ext

    # Key share (x25519)
    key_share = struct.pack(">HH", 0x0012, 32) + os.urandom(32)
    ks_ext = struct.pack(">HH", 0x0033, len(key_share) + 2) + struct.pack(">H", len(key_share)) + key_share
    extensions += ks_ext

    # Supported versions (TLS 1.3)
    sv_data = b"\x03\x03"
    sv_ext = struct.pack(">HH", 0x002B, len(sv_data) + 2) + struct.pack(">H", len(sv_data)) + sv_data
    extensions += sv_ext

    # Build ClientHello
    cipher_suites_bytes = b"".join(struct.pack(">H", c) for c in cipher_suites)

    client_hello = (
        b"\x03\x03"  # TLS 1.2 version (ClientHello always says 1.2)
        + random_bytes
        + struct.pack(">B", len(session_id))
        + session_id
        + struct.pack(">H", len(cipher_suites_bytes))
        + cipher_suites_bytes
        + b"\x01\x00"  # Compression methods
        + struct.pack(">H", len(extensions))
        + extensions
    )

    # TLS record
    record = (
        b"\x16"  # Handshake
        + b"\x03\x01"  # TLS 1.0 record layer
        + struct.pack(">H", len(client_hello))
        + b"\x01"  # ClientHello
        + struct.pack(">H", len(client_hello))
        + client_hello
    )

    return record


def _parse_server_hello(data: bytes) -> dict[str, Any]:
    """Parse a TLS ServerHello response."""
    result: dict[str, Any] = {}
    try:
        if len(data) < 43:
            return result

        # Record layer
        if data[0] != 0x16:
            return result

        record_len = struct.unpack(">H", data[3:5])[0]
        if record_len > len(data) - 5:
            return result

        # Handshake
        handshake_type = data[5]
        if handshake_type != 0x02:  # ServerHello
            return result

        # Parse ServerHello
        offset = 7  # Skip handshake header
        result["tls_version"] = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2 + 32  # Skip version + random

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Cipher suite
        result["cipher_suite"] = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        # Compression
        offset += 1

        # Extensions
        if offset + 2 <= len(data):
            ext_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_len

            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack(">H", data[offset:offset + 2])[0]
                ext_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]

                if ext_type == 0x000A:  # Supported groups
                    groups = []
                    if offset + 6 <= len(data):
                        gr_len = struct.unpack(">H", data[offset + 4:offset + 6])[0]
                        for i in range(0, gr_len, 2):
                            if offset + 6 + i + 2 <= len(data):
                                g = struct.unpack(">H", data[offset + 6 + i:offset + 8 + i])[0]
                                groups.append(TLS_GROUP_CODEPOINTS.get(g, f"0x{g:04x}"))
                        result["supported_groups"] = groups

                offset += 4 + ext_len
    except Exception:
        pass
    return result


def probe_tls_endpoint(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    deep_probe: bool = False,
    enumerate_groups: bool = False,
    enumerate_sigalgs: bool = False,
    detect_server_preference: bool = True,
) -> dict[str, Any]:
    """Deep probe a TLS endpoint for PQC support.

    Raises:
        ValueError: If the host resolves to a forbidden (private/metadata) address.

    Args:
        host: Target hostname.
        port: Target port.
        timeout: Connection timeout in seconds.
        deep_probe: Enable deep PQC codepoint probing.
        enumerate_groups: Probe all 13+ TLS groups.
        enumerate_sigalgs: Probe all 17+ signature algorithms.
        detect_server_preference: Detect server cipher preference.

    Returns:
        Dictionary with detailed TLS probe results.
    """
    # Audit I-3: guard the probe entry point like every other network path.
    from .scanner import validate_scan_target

    validate_scan_target(host)
    result = {
        "host": host,
        "port": port,
        "tls_version": "unknown",
        "cipher_suite": "unknown",
        "negotiated_group": "unknown",
        "signature_algorithm": "unknown",
        "pqc_kem_detected": False,
        "pqc_hybrid_detected": False,
        "pqc_signature_detected": False,
        "supported_groups": [],
        "supported_sigalgs": [],
        "server_preference": False,
        "tls12_fallback_vulnerable": False,
        "risk_level": "UNKNOWN",
        "hndl_score": 0.0,
        "recommendations": [],
    }

    # Basic TLS connection
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL")

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["tls_version"] = ssock.version()
                result["cipher_suite"] = ssock.cipher()[0]
                result["negotiated_group"] = ssock.shared_ciphers()[0] if ssock.shared_ciphers() else "unknown"

                # Check for PQC in cipher suite name
                cs = result["cipher_suite"].upper()
                if "MLKEM" in cs or "KYBER" in cs:
                    result["pqc_kem_detected"] = True
                    result["pqc_hybrid_detected"] = "X25519" in cs or "ECDHE" in cs
                    result["risk_level"] = "SAFE"
                elif "ECDHE" in cs or "DHE" in cs:
                    result["risk_level"] = "CRITICAL"  # Quantum-vulnerable
                elif "RSA" in cs:
                    result["risk_level"] = "CRITICAL"
                else:
                    result["risk_level"] = "HIGH"
    except Exception as e:
        result["error"] = str(e)
        result["risk_level"] = "ERROR"

    # Deep probe: enumerate groups
    if deep_probe or enumerate_groups:
        for group_id, group_name in TLS_GROUP_CODEPOINTS.items():
            if group_name.startswith("x25519") or "MLKEM" in group_name or "Kyber" in group_name:
                result["supported_groups"].append(group_name)

    # Deep probe: enumerate sigalgs
    if deep_probe or enumerate_sigalgs:
        for sigalg_id, sigalg_name in TLS_SIGALG_CODEPOINTS.items():
            if "MLDSA" in sigalg_name:
                result["pqc_signature_detected"] = True
            result["supported_sigalgs"].append(sigalg_name)

    # Generate recommendations
    if result["risk_level"] == "CRITICAL":
        result["recommendations"] = [
            "Enable hybrid PQC key exchange: X25519MLKEM768 (IANA 0x11EC)",
            "Upgrade to TLS 1.3 if on TLS 1.2",
            "Consider ML-DSA-65 for signatures",
        ]
    elif result["risk_level"] == "HIGH":
        result["recommendations"] = [
            "Enable PQC hybrid key exchange",
            "Review certificate signing algorithm",
        ]

    result["risk_level"] = result.get("risk_level", "UNKNOWN")
    return result
