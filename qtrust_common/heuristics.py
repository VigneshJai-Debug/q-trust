"""
Single canonical heuristic for PQC migration priority / risk.

Import this instead of reimplementing per-subsystem:

- inspector parallel_scanner (GPU-batch fallback)
- planner data_generator (synthetic label seeding)
- planner server / predict (no-model fallback)

Unit-tested once; drift between the three is now a test failure, not silent divergence.
"""
from __future__ import annotations


CRITICALITY_W = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

PQC_FAMILIES = {"ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "HQC", "FALCON"}

def _family(algorithm: str) -> str:
    if not algorithm:
        return "UNKNOWN"
    return algorithm.split("-")[0].split("_")[0].upper()

def is_pqc_algorithm(algorithm: str) -> bool:
    fam = _family(algorithm)
    return any(p in fam or fam in p for p in PQC_FAMILIES) or "PQC" in algorithm.upper()

def pqc_priority(asset: dict) -> float:
    """Single canonical priority score. Higher = migrate first.

    Inputs are tolerant: asset may be a dict with keys algorithm, key_size, criticality, pqc_ready.
    """
    crit = CRITICALITY_W.get(str(asset.get("criticality", "Medium")), 3)
    key_size = int(asset.get("key_size", 0) or 0)
    pqc_ready = bool(asset.get("pqc_ready", False))
    algorithm = str(asset.get("algorithm", "unknown"))
    family = _family(algorithm)

    # Base from criticality
    score = float(crit)

    # Quantum vulnerability boost if not yet PQC
    if not pqc_ready and not is_pqc_algorithm(algorithm):
        if family in ("RSA", "ECC", "DSA", "DH", "ECDH", "ECDSA"):
            score += 3.0
        elif family == "EDDSA":
            score += 2.0
        else:
            score += 1.0

    # Key size blow-up: larger keys are more painful to rotate but more critical
    if key_size >= 4096:
        score += 2.0
    elif key_size >= 2048:
        score += 1.0

    # Already PQC -> de-prioritize
    if pqc_ready or is_pqc_algorithm(algorithm):
        score -= 2.0

    return score

def pqc_risk(asset: dict) -> float:
    """Single canonical risk score in [0,1]. Higher = riskier if not migrated."""
    if bool(asset.get("pqc_ready", False)) or is_pqc_algorithm(str(asset.get("algorithm", ""))):
        return 0.1
    crit = CRITICALITY_W.get(str(asset.get("criticality", "Medium")), 3)
    # Normalize criticality to 0-1, then bump for classical RSA/ECC
    base = crit / 5.0
    alg = str(asset.get("algorithm", "")).upper()
    if "RSA" in alg and int(asset.get("key_size", 2048) or 2048) < 2048:
        base = max(base, 0.9)
    return min(base, 1.0)

# Backward-compatible aliases
heuristic_priority = pqc_priority
heuristic_risk = pqc_risk
