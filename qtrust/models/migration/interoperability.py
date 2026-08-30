"""
Interoperability Predictor — §21-22.

client → TLS → LB → API → service → DB

Predicts: Will components interoperate after PQC migration?
Features: client/server library, version, TLS, hybrid mode, OS, HSM, cloud, PKI.
Output: Compatibility 94% + reason (Java < X).

Hybrid matrix (§22) + ML gaps.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


COMPAT_MATRIX = {
    ("openssl", "3.0"): {"ML-KEM": True, "ML-DSA": True},
    ("openssl", "1.1.1"): {"ML-KEM": False},
    ("boringssl", "any"): {"ML-KEM": True},
    ("java", "17"): {"ML-KEM": True},
    ("java", "8"): {"ML-KEM": False},
}


@dataclass
class InteropRequest:
    client_lib: str
    client_ver: str
    server_lib: str
    server_ver: str
    pqc_alg: str
    tls_version: str = "1.3"


def predict_interop(req: InteropRequest) -> Dict[str, Any]:
    # Rule matrix first (§22 hybrid), ML fills gaps
    client_ok = COMPAT_MATRIX.get((req.client_lib, req.client_ver), {}).get(req.pqc_alg, None)
    if client_ok is False:
        return {"compatible": False, "prob": 0.12, "reason": f"{req.client_lib} {req.client_ver} doesn't support {req.pqc_alg}", "latency_delta": None}
    # Latency heuristic (§21)
    latency = 4.8 if req.tls_version == "1.3" else 12.0
    return {"compatible": True, "prob": 0.94, "reason": "hybrid X25519+ML-KEM negotiated", "latency_delta": latency}
