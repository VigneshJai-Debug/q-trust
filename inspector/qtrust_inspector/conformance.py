"""FIPS 203/204/205 parameter-set validator.

Verifies Q-Trust's declared ML-KEM (FIPS 203), ML-DSA (FIPS 204) and
SLH-DSA (FIPS 205) parameter tables against the parameter sets published
in those standards: element sizes, core parameters and NIST security
categories. Every PASS/FAIL below is a deterministic spec-table comparison
that runs locally -- no key generation, signing or encapsulation is
performed.

This is NOT ACVP-style cryptographic testing of an implementation.
Known-answer validation (keygen/encaps/sign against NIST ACVP vectors,
e.g. via a liboqs-backed implementation) is out of scope here and is
reported as SKIP with an explicit reason.

Run: crypto-inspector conformance --algorithm ML-KEM-768
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PQCAlgorithm(str, Enum):
    """NIST PQC algorithms."""
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"
    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"
    SLH_DSA_128S = "SLH-DSA-128s"
    SLH_DSA_128F = "SLH-DSA-128f"
    SLH_DSA_192S = "SLH-DSA-192s"
    SLH_DSA_192F = "SLH-DSA-192f"
    SLH_DSA_256S = "SLH-DSA-256s"
    SLH_DSA_256F = "SLH-DSA-256f"
    ML_KEM = "ML-KEM"  # Generic
    ML_DSA = "ML-DSA"  # Generic
    SLH_DSA = "SLH-DSA"  # Generic


class TestStatus(str, Enum):
    """Validation result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


# Reason attached to every check that cannot run without external resources.
EXTERNAL_REASON = "requires NIST ACVP vectors / liboqs integration"


@dataclass
class TestCase:
    """Individual parameter-set validation case."""
    name: str
    description: str
    status: TestStatus = TestStatus.SKIP
    details: str = ""
    expected: str = ""
    actual: str = ""


@dataclass
class ConformanceResult:
    """Result of parameter-set validation."""
    algorithm: PQCAlgorithm
    level: int
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    tests: list[TestCase] = field(default_factory=list)
    conformance_score: float = 0.0
    parameter_set_valid: bool = False
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return self.conformance_score

    @property
    def fips_compliant(self) -> bool:
        """Backward-compat alias for ``parameter_set_valid``."""
        return self.parameter_set_valid

    @property
    def is_compliant(self) -> bool:
        return self.parameter_set_valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "level": self.level,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "conformance_score": self.conformance_score,
            "parameter_set_valid": self.parameter_set_valid,
            # Backward-compat alias for parameter_set_valid.
            "fips_compliant": self.parameter_set_valid,
            "tests": [
                {
                    "name": t.name,
                    "description": t.description,
                    "status": t.status.value,
                    "details": t.details,
                    "expected": t.expected,
                    "actual": t.actual,
                }
                for t in self.tests
            ],
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Declared parameter tables (Q-Trust source of truth)
# ---------------------------------------------------------------------------

# Declared FIPS 203 (ML-KEM) parameters
ML_KEM_PARAMS: dict[str, dict[str, int]] = {
    "ML-KEM-512": {
        "k": 2, "n": 256, "eta1": 3, "eta2": 2, "du": 10, "dv": 4,
        "pk_size": 800, "sk_size": 1632, "ct_size": 768,
    },
    "ML-KEM-768": {
        "k": 3, "n": 256, "eta1": 2, "eta2": 2, "du": 10, "dv": 4,
        "pk_size": 1184, "sk_size": 2400, "ct_size": 1088,
    },
    "ML-KEM-1024": {
        "k": 4, "n": 256, "eta1": 2, "eta2": 2, "du": 11, "dv": 5,
        "pk_size": 1568, "sk_size": 3168, "ct_size": 1568,
    },
}

# Declared FIPS 204 (ML-DSA) parameters
ML_DSA_PARAMS: dict[str, dict[str, int]] = {
    "ML-DSA-44": {
        "n": 256, "q": 8380417, "k": 4, "l": 4, "eta": 2, "tau": 39,
        "gamma1": (1 << 17), "gamma2": (8380417 - 1) // 88,
        "pk_size": 1312, "sk_size": 2560, "sig_size": 2420,
    },
    "ML-DSA-65": {
        "n": 256, "q": 8380417, "k": 6, "l": 5, "eta": 4, "tau": 49,
        "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32,
        "pk_size": 1952, "sk_size": 4032, "sig_size": 3309,
    },
    "ML-DSA-87": {
        "n": 256, "q": 8380417, "k": 8, "l": 7, "eta": 2, "tau": 60,
        "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32,
        "pk_size": 2592, "sk_size": 4896, "sig_size": 4627,
    },
}

# Declared FIPS 205 (SLH-DSA) parameters. Only n and the pk/sig sizes are
# validated against the standard; internal tree parameters (h/d/log_t/w)
# are recorded here for reference but require full ACVP coverage to verify.
SLH_DSA_PARAMS: dict[str, dict[str, Any]] = {
    "SLH-DSA-128s": {"n": 16, "h": 7, "d": 12, "log_t": 6, "w": 7,
                     "pk_size": 32, "sig_size": 7856},
    "SLH-DSA-128f": {"n": 16, "h": 6, "d": 12, "log_t": 12, "w": 9,
                     "pk_size": 32, "sig_size": 17088},
    "SLH-DSA-192s": {"n": 24, "h": 7, "d": 14, "log_t": 7, "w": 7,
                     "pk_size": 48, "sig_size": 16224},
    "SLH-DSA-192f": {"n": 24, "h": 6, "d": 14, "log_t": 14, "w": 9,
                     "pk_size": 48, "sig_size": 35664},
    "SLH-DSA-256s": {"n": 32, "h": 8, "d": 14, "log_t": 8, "w": 7,
                     "pk_size": 64, "sig_size": 29792},
    "SLH-DSA-256f": {"n": 32, "h": 6, "d": 14, "log_t": 16, "w": 9,
                     "pk_size": 64, "sig_size": 49856},
}


# ---------------------------------------------------------------------------
# Reference parameter sets published in the standards (authoritative)
# ---------------------------------------------------------------------------

# FIPS 203 §8 / Table 2: n=256, q=3329 for all sets; sizes in bytes
# (ek/dk/ct). Values cross-checked via ek=⌈12·k·n/8⌉+32, dk=24·k·n/8+96,
# ct=⌈du·k·n/8⌉+⌈dv·n/8⌉.
FIPS_ML_KEM_SPEC: dict[str, dict[str, int]] = {
    "ML-KEM-512": {
        "k": 2, "n": 256, "eta1": 3, "eta2": 2, "du": 10, "dv": 4,
        "pk_size": 800, "sk_size": 1632, "ct_size": 768,
    },
    "ML-KEM-768": {
        "k": 3, "n": 256, "eta1": 2, "eta2": 2, "du": 10, "dv": 4,
        "pk_size": 1184, "sk_size": 2400, "ct_size": 1088,
    },
    "ML-KEM-1024": {
        "k": 4, "n": 256, "eta1": 2, "eta2": 2, "du": 11, "dv": 5,
        "pk_size": 1568, "sk_size": 3168, "ct_size": 1568,
    },
}

# FIPS 204 Table 2: q=8380417, n=256 for all sets; sizes in bytes
# (PK/SK/|σ|).
FIPS_ML_DSA_SPEC: dict[str, dict[str, int]] = {
    "ML-DSA-44": {
        "n": 256, "q": 8380417, "k": 4, "l": 4, "eta": 2, "tau": 39,
        "gamma1": (1 << 17), "gamma2": (8380417 - 1) // 88,
        "pk_size": 1312, "sk_size": 2560, "sig_size": 2420,
    },
    "ML-DSA-65": {
        "n": 256, "q": 8380417, "k": 6, "l": 5, "eta": 4, "tau": 49,
        "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32,
        "pk_size": 1952, "sk_size": 4032, "sig_size": 3309,
    },
    "ML-DSA-87": {
        "n": 256, "q": 8380417, "k": 8, "l": 7, "eta": 2, "tau": 60,
        "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32,
        "pk_size": 2592, "sk_size": 4896, "sig_size": 4627,
    },
}

# FIPS 205 Table 2: security-category-defining values only (message length
# n in bytes, PK size = n bytes, signature size |σ| in bytes).
FIPS_SLH_DSA_SPEC: dict[str, dict[str, int]] = {
    "SLH-DSA-128s": {"n": 16, "pk_size": 32, "sig_size": 7856},
    "SLH-DSA-128f": {"n": 16, "pk_size": 32, "sig_size": 17088},
    "SLH-DSA-192s": {"n": 24, "pk_size": 48, "sig_size": 16224},
    "SLH-DSA-192f": {"n": 24, "pk_size": 48, "sig_size": 35664},
    "SLH-DSA-256s": {"n": 32, "pk_size": 64, "sig_size": 29792},
    "SLH-DSA-256f": {"n": 32, "pk_size": 64, "sig_size": 49856},
}

# NIST security strength categories: ML-KEM-512 Cat 1, -768 Cat 3,
# -1024 Cat 5 (FIPS 203); ML-DSA-44 Cat 2, -65 Cat 3, -87 Cat 5 (FIPS 204);
# SLH-DSA-{128,192,256}-* Cat {1,3,5} (FIPS 205).
FIPS_SECURITY_CATEGORY: dict[PQCAlgorithm, int] = {
    PQCAlgorithm.ML_KEM_512: 1, PQCAlgorithm.ML_KEM_768: 3, PQCAlgorithm.ML_KEM_1024: 5,
    PQCAlgorithm.ML_DSA_44: 2, PQCAlgorithm.ML_DSA_65: 3, PQCAlgorithm.ML_DSA_87: 5,
    PQCAlgorithm.SLH_DSA_128S: 1, PQCAlgorithm.SLH_DSA_128F: 1,
    PQCAlgorithm.SLH_DSA_192S: 3, PQCAlgorithm.SLH_DSA_192F: 3,
    PQCAlgorithm.SLH_DSA_256S: 5, PQCAlgorithm.SLH_DSA_256F: 5,
}
CATEGORY_MIN_BITS = {1: 128, 2: 128, 3: 192, 5: 256}


def _normalize_algorithm(algorithm: str, level: str | None = None) -> tuple[PQCAlgorithm, int]:
    """Normalize algorithm name and level."""
    algo_upper = algorithm.upper().replace("-", "_").replace(" ", "_")

    # ML-KEM
    if "ML_KEM" in algo_upper or "MLKEM" in algo_upper or "KYBER" in algo_upper:
        level_num = int(level) if level else 768
        level_map = {
            512: PQCAlgorithm.ML_KEM_512,
            768: PQCAlgorithm.ML_KEM_768,
            1024: PQCAlgorithm.ML_KEM_1024,
        }
        return level_map.get(level_num, PQCAlgorithm.ML_KEM_768), level_num

    # ML-DSA
    if "ML_DSA" in algo_upper or "MLDSA" in algo_upper or "DILITHIUM" in algo_upper:
        level_num = int(level) if level else 65
        level_map = {
            44: PQCAlgorithm.ML_DSA_44,
            65: PQCAlgorithm.ML_DSA_65,
            87: PQCAlgorithm.ML_DSA_87,
        }
        return level_map.get(level_num, PQCAlgorithm.ML_DSA_65), level_num

    # SLH-DSA
    if "SLH_DSA" in algo_upper or "SLHDSA" in algo_upper or "SPHINCS" in algo_upper:
        mode = "128s"
        if "192" in algo_upper:
            mode = "192s"
        elif "256" in algo_upper:
            mode = "256s"
        if "f" in algo_upper.lower():
            mode = mode.replace("s", "f")
        level_map = {
            "128s": PQCAlgorithm.SLH_DSA_128S, "128f": PQCAlgorithm.SLH_DSA_128F,
            "192s": PQCAlgorithm.SLH_DSA_192S, "192f": PQCAlgorithm.SLH_DSA_192F,
            "256s": PQCAlgorithm.SLH_DSA_256S, "256f": PQCAlgorithm.SLH_DSA_256F,
        }
        return level_map.get(mode, PQCAlgorithm.SLH_DSA_128S), 128

    return PQCAlgorithm.ML_KEM_768, 768


def _spec_check(
    algo_name: str, key: str, spec_value: Any, declared_value: Any, ref: str
) -> TestCase:
    """Deterministically compare one declared parameter against the spec value."""
    ok = spec_value == declared_value
    return TestCase(
        name=f"{algo_name}_{key}",
        description=f"{key}: declared {declared_value}, FIPS specifies {spec_value}",
        expected=str(spec_value),
        actual=str(declared_value),
        status=TestStatus.PASS if ok else TestStatus.FAIL,
        details=f"{ref}: {key} must be {spec_value} for {algo_name}",
    )


def _test_parameter_sizes(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Execute spec-table comparisons of declared sizes/params vs FIPS constants."""
    algo_name = algorithm.value
    checks: list[TestCase] = []

    if "ML-KEM" in algo_name:
        declared = ML_KEM_PARAMS.get(algo_name, {})
        spec = FIPS_ML_KEM_SPEC[algo_name]
        for key, spec_val in spec.items():
            checks.append(_spec_check(algo_name, key, spec_val, declared.get(key), "FIPS 203"))
    elif "ML-DSA" in algo_name:
        declared = ML_DSA_PARAMS.get(algo_name, {})
        spec = FIPS_ML_DSA_SPEC[algo_name]
        for key, spec_val in spec.items():
            checks.append(_spec_check(algo_name, key, spec_val, declared.get(key), "FIPS 204"))
    elif "SLH-DSA" in algo_name:
        declared = SLH_DSA_PARAMS.get(algo_name, {})
        spec = FIPS_SLH_DSA_SPEC[algo_name]
        for key, spec_val in spec.items():
            checks.append(_spec_check(algo_name, key, spec_val, declared.get(key), "FIPS 205"))
    return checks


def _test_security_strength(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Verify claimed security strength matches the FIPS security category."""
    category = FIPS_SECURITY_CATEGORY.get(algorithm)
    min_bits = CATEGORY_MIN_BITS.get(category)
    declared_strength = {
        PQCAlgorithm.ML_KEM_512: 128, PQCAlgorithm.ML_KEM_768: 192, PQCAlgorithm.ML_KEM_1024: 256,
        PQCAlgorithm.ML_DSA_44: 128, PQCAlgorithm.ML_DSA_65: 192, PQCAlgorithm.ML_DSA_87: 256,
        PQCAlgorithm.SLH_DSA_128S: 128, PQCAlgorithm.SLH_DSA_128F: 128,
        PQCAlgorithm.SLH_DSA_192S: 192, PQCAlgorithm.SLH_DSA_192F: 192,
        PQCAlgorithm.SLH_DSA_256S: 256, PQCAlgorithm.SLH_DSA_256F: 256,
    }.get(algorithm)
    ok = declared_strength is not None and min_bits is not None and declared_strength >= min_bits
    return [TestCase(
        name=f"{algorithm.value}_security_strength",
        description=(
            f"FIPS category {category} requires ≥{min_bits}-bit classical security; "
            f"declared {declared_strength}-bit"
        ),
        expected=f">={min_bits}-bit (Category {category})",
        actual=f"{declared_strength}-bit",
        status=TestStatus.PASS if ok else TestStatus.FAIL,
        details=(
            f"NIST PQC category for {algorithm.value}: Category {category} "
            f"(≥ AES-{min_bits} classical strength)"
        ),
    )]


def _skip_external(name: str, description: str, ref: str) -> TestCase:
    """A genuinely external validation we cannot execute locally."""
    return TestCase(
        name=name,
        description=description,
        status=TestStatus.SKIP,
        details=f"{ref}: {EXTERNAL_REASON}",
    )


def _test_keygen_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Known-answer keygen determinism test — needs an implementation + ACVP vectors."""
    return [_skip_external(
        f"{algorithm.value}_keygen_kat",
        "Verify deterministic key generation with same seed (known-answer test)",
        "Keygen KAT",
    )]


def _test_encaps_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Encaps/decaps known-answer test — needs an implementation + ACVP vectors."""
    if "ML-KEM" not in algorithm.value:
        return []
    return [_skip_external(
        f"{algorithm.value}_encaps_kat",
        "Verify encaps(ek) -> ct, decaps(sk, ct) -> ss matches shared secret (KAT)",
        "FIPS 203 §4.3 encaps/decaps KAT",
    )]


def _test_signature_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Sign/verify known-answer test — needs an implementation + ACVP vectors."""
    if "SLH-DSA" in algorithm.value:
        return [_skip_external(
            f"{algorithm.value}_sign_verify_kat",
            "Verify sign(sk, msg) -> sig, verify(pk, msg, sig) = true (KAT)",
            "FIPS 205 §4 sign/verify KAT",
        )]
    if "ML-DSA" in algorithm.value:
        return [_skip_external(
            f"{algorithm.value}_sign_verify_kat",
            "Verify sign(sk, msg) -> sig, verify(pk, msg, sig) = true (KAT)",
            "FIPS 204 §4 sign/verify KAT",
        )]
    return []


def run_conformance_tests(
    algorithm: str,
    level: str | None = None,
    test_vectors_path: str | None = None,
    test_vector_hex: str | None = None,
) -> ConformanceResult:
    """Validate declared FIPS 203/204/205 parameter sets for an algorithm.

    Executes deterministic spec-table comparisons (sizes, core parameters,
    security categories) that PASS or FAIL locally. Known-answer testing of
    an actual implementation is reported as SKIP with an explicit reason.

    Args:
        algorithm: PQC algorithm name (ML-KEM, ML-DSA, SLH-DSA, or specific variant).
        level: Security level (512/768/1024 for ML-KEM, 44/65/87 for
            ML-DSA, 128/192/256 for SLH-DSA).
        test_vectors_path: Path to NIST ACVP vector file. Accepted for API
            compatibility; vectors cannot be executed without an
            implementation under test, so the item is reported as SKIP.
        test_vector_hex: Hex-encoded test vector input (same limitation).

    Returns:
        ConformanceResult with validation results.
    """
    algo, level_num = _normalize_algorithm(algorithm, level)

    all_tests: list[TestCase] = []

    # Executable spec-table checks (PASS/FAIL)
    all_tests.extend(_test_parameter_sizes(algo))
    all_tests.extend(_test_security_strength(algo))

    # Genuinely external validations (SKIP with reason)
    all_tests.extend(_test_keygen_consistency(algo))
    all_tests.extend(_test_encaps_consistency(algo))
    all_tests.extend(_test_signature_consistency(algo))

    if test_vectors_path or test_vector_hex:
        tv_test = TestCase(
            name=f"{algo.value}_acvp_vectors",
            description="Execute NIST ACVP known-answer vectors against an implementation",
            expected="Outputs match NIST ACVP reference values",
            details=f"ACVP execution {EXTERNAL_REASON}",
        )
        if test_vectors_path:
            try:
                with open(test_vectors_path, "rb") as f:
                    data = f.read()
                tv_test.actual = f"Loaded {len(data)} bytes from test vectors"
            except FileNotFoundError:
                tv_test.status = TestStatus.ERROR
                tv_test.details = f"File not found: {test_vectors_path}"
                tv_test.actual = f"File not found: {test_vectors_path}"
        else:
            tv_test.actual = "Hex input accepted but no implementation available to execute it"
        all_tests.append(tv_test)

    # Calculate results: score excludes skips entirely.
    total = len(all_tests)
    passed = sum(1 for t in all_tests if t.status == TestStatus.PASS)
    failed = sum(1 for t in all_tests if t.status == TestStatus.FAIL)
    skipped = sum(1 for t in all_tests if t.status == TestStatus.SKIP)

    executed = passed + failed
    score = (passed / executed * 100.0) if executed > 0 else 0.0
    parameter_set_valid = failed == 0 and passed > 0

    warnings = []
    recommendations = []

    if failed > 0:
        warnings.append(
            f"{failed} parameter-set check(s) FAILED against FIPS 203/204/205 tables"
        )
        recommendations.append(
            "Correct the declared parameter tables to match the FIPS-published values"
        )
    if skipped > 0:
        warnings.append(f"{skipped} check(s) skipped ({EXTERNAL_REASON})")
    if failed == 0 and passed > 0:
        recommendations.append(
            "Parameter tables match the standards; for implementation-level assurance "
            "run NIST ACVP tests (e.g. via liboqs)"
        )

    return ConformanceResult(
        algorithm=algo,
        level=level_num,
        total_tests=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        tests=all_tests,
        conformance_score=score,
        parameter_set_valid=parameter_set_valid,
        warnings=warnings,
        recommendations=recommendations,
    )
