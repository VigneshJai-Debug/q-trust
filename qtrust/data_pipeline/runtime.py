"""
Runtime observation — §43 (§44 evidence fusion).

Service → TLS handshake → cipher suite → certificate → key algorithm.
Combine static + runtime; flag evidence conflicts.

Secret weapon vs pure static competitors.
"""
from __future__ import annotations

import ssl
import socket
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class RuntimeObservation:
    host: str
    tls_version: str
    cipher_suite: str
    certificate_alg: str
    key_exchange: str
    pqc_hybrid: bool


def observe_tls(host: str, port: int = 443, timeout: float = 5.0) -> RuntimeObservation | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                # Simplified
                return RuntimeObservation(
                    host=host,
                    tls_version=ssock.version() or "unknown",
                    cipher_suite=cipher[0] if cipher else "unknown",
                    certificate_alg=str(cert.get("subject", ""))[:40] if cert else "unknown",
                    key_exchange=cipher[1] if cipher and len(cipher) > 1 else "unknown",
                    pqc_hybrid="MLKEM" in (cipher[0] if cipher else ""),
                )
    except Exception:
        return None


def fuse_evidence(static: Dict[str, Any], runtime: RuntimeObservation | None) -> Dict[str, Any]:
    fused: Dict[str, Any] = {"static": static, "runtime": runtime.__dict__ if runtime else None}
    if runtime and static.get("algorithm") and runtime.certificate_alg not in static["algorithm"]:
        fused["conflict"] = f"static {static['algorithm']} vs runtime {runtime.certificate_alg}"
        fused["confidence"] = 0.96  # runtime is ground truth (§44)
    else:
        fused["confidence"] = 0.92
    return fused
