"""Shared algorithm classification tables."""
from .heuristics import is_pqc_algorithm

ALGORITHM_FAMILIES = {
    "RSA": "classical",
    "ECDSA": "classical",
    "ECDH": "classical",
    "DSA": "classical",
    "DH": "classical",
    "EDDSA": "classical",
    "ML-KEM": "pqc",
    "ML-DSA": "pqc",
    "SLH-DSA": "pqc",
}

def classify_algorithm(algorithm: str) -> str:
    fam = algorithm.split("-")[0].upper() if "-" in algorithm else algorithm.upper()
    if is_pqc_algorithm(algorithm):
        return "pqc"
    return ALGORITHM_FAMILIES.get(fam, "unknown")
