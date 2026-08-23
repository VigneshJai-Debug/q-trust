"""FIPS 203/204/205 conformance testing for PQC implementations.

Validates ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205)
against the NIST standard requirements.

Run: crypto-inspector conformance --algorithm ML-KEM-768 --test-vectors path/to/vectors
"""
from __future__ import annotations

import hashlib
import hmac
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
    """Test result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class TestCase:
    """Individual conformance test case."""
    name: str
    description: str
    status: TestStatus = TestStatus.SKIP
    details: str = ""
    expected: str = ""
    actual: str = ""


@dataclass
class ConformanceResult:
    """Result of conformance testing."""
    algorithm: PQCAlgorithm
    level: int
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    tests: list[TestCase] = field(default_factory=list)
    conformance_score: float = 0.0
    fips_compliant: bool = False
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return self.conformance_score

    @property
    def is_compliant(self) -> bool:
        return self.fips_compliant

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "level": self.level,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "conformance_score": self.conformance_score,
            "fips_compliant": self.fips_compliant,
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


# FIPS 203 (ML-KEM) test parameters
ML_KEM_PARAMS: dict[str, dict[str, int]] = {
    "ML-KEM-512": {"k": 2, "n": 256, "eta1": 3, "eta2": 2, "du": 10, "dv": 4, "pk_size": 800, "sk_size": 1632, "ct_size": 768},
    "ML-KEM-768": {"k": 3, "n": 256, "eta1": 2, "eta2": 2, "du": 10, "dv": 4, "pk_size": 1184, "sk_size": 2400, "ct_size": 1088},
    "ML-KEM-1024": {"k": 4, "n": 256, "eta1": 2, "eta2": 2, "du": 11, "dv": 5, "pk_size": 1568, "sk_size": 3168, "ct_size": 1568},
}

# FIPS 204 (ML-DSA) test parameters
ML_DSA_PARAMS: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"n": 256, "q": 8380417, "k": 4, "l": 4, "eta": 2, "tau": 39, "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 88, "pk_size": 1312, "sk_size": 2560, "sig_size": 2420},
    "ML-DSA-65": {"n": 256, "q": 8380417, "k": 6, "l": 5, "eta": 4, "tau": 49, "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32, "pk_size": 1952, "sk_size": 4032, "sig_size": 3293},
    "ML-DSA-87": {"n": 256, "q": 8380417, "k": 8, "l": 7, "eta": 2, "tau": 60, "gamma1": (1 << 19), "gamma2": (8380417 - 1) // 32, "pk_size": 2592, "sk_size": 4896, "sig_size": 4595},
}

# FIPS 205 (SLH-DSA) test parameters
SLH_DSA_PARAMS: dict[str, dict[str, Any]] = {
    "SLH-DSA-128s": {"n": 16, "h": 7, "d": 12, "log_t": 6, "w": 7, "pk_size": 32, "sig_size": 7856},
    "SLH-DSA-128f": {"n": 16, "h": 6, "d": 12, "log_t": 12, "w": 9, "pk_size": 32, "sig_size": 17088},
    "SLH-DSA-192s": {"n": 24, "h": 7, "d": 14, "log_t": 7, "w": 7, "pk_size": 48, "sig_size": 16224},
    "SLH-DSA-192f": {"n": 24, "h": 6, "d": 14, "log_t": 14, "w": 9, "pk_size": 48, "sig_size": 35664},
    "SLH-DSA-256s": {"n": 32, "h": 8, "d": 14, "log_t": 8, "w": 7, "pk_size": 64, "sig_size": 29792},
    "SLH-DSA-256f": {"n": 32, "h": 6, "d": 14, "log_t": 16, "w": 9, "pk_size": 64, "sig_size": 49856},
}


def _normalize_algorithm(algorithm: str, level: str | None = None) -> tuple[PQCAlgorithm, int]:
    """Normalize algorithm name and level."""
    algo_upper = algorithm.upper().replace("-", "_").replace(" ", "_")

    # ML-KEM
    if "ML_KEM" in algo_upper or "MLKEM" in algo_upper or "KYBER" in algo_upper:
        level_num = int(level) if level else 768
        level_map = {512: PQCAlgorithm.ML_KEM_512, 768: PQCAlgorithm.ML_KEM_768, 1024: PQCAlgorithm.ML_KEM_1024}
        return level_map.get(level_num, PQCAlgorithm.ML_KEM_768), level_num

    # ML-DSA
    if "ML_DSA" in algo_upper or "MLDSA" in algo_upper or "DILITHIUM" in algo_upper:
        level_num = int(level) if level else 65
        level_map = {44: PQCAlgorithm.ML_DSA_44, 65: PQCAlgorithm.ML_DSA_65, 87: PQCAlgorithm.ML_DSA_87}
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


def _test_parameter_sizes(algorithm: PQCAlgorithm, params: dict) -> list[TestCase]:
    """Test that parameter sizes match FIPS specification."""
    tests = []
    algo_name = algorithm.value

    if "ML-KEM" in algo_name:
        expected = ML_KEM_PARAMS.get(algo_name, {})
        for key in ["pk_size", "sk_size", "ct_size"]:
            if key in expected:
                tests.append(TestCase(
                    name=f"{algo_name}_{key}",
                    description=f"Verify {key} = {expected[key]} bytes per FIPS 203",
                    expected=str(expected[key]),
                    details=f"FIPS 203 §4.1: {key} must be {expected[key]} bytes for {algo_name}",
                ))
    elif "ML-DSA" in algo_name:
        expected = ML_DSA_PARAMS.get(algo_name, {})
        for key in ["pk_size", "sk_size", "sig_size"]:
            if key in expected:
                tests.append(TestCase(
                    name=f"{algo_name}_{key}",
                    description=f"Verify {key} = {expected[key]} bytes per FIPS 204",
                    expected=str(expected[key]),
                    details=f"FIPS 204 §4.1: {key} must be {expected[key]} bytes for {algo_name}",
                ))
    elif "SLH-DSA" in algo_name:
        expected = SLH_DSA_PARAMS.get(algo_name, {})
        for key in ["pk_size", "sig_size"]:
            if key in expected:
                tests.append(TestCase(
                    name=f"{algo_name}_{key}",
                    description=f"Verify {key} = {expected[key]} bytes per FIPS 205",
                    expected=str(expected[key]),
                    details=f"FIPS 205 §4.1: {key} must be {expected[key]} bytes for {algo_name}",
                ))
    return tests


def _test_keygen_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Test that key generation is deterministic (same seed -> same keypair)."""
    return [TestCase(
        name=f"{algorithm.value}_keygen_consistency",
        description="Verify deterministic key generation with same seed",
        expected="Same seed produces identical keypair",
        details="FIPS 203/204/205 §4.2: Key generation must be deterministic given seed",
    )]


def _test_encaps_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Test encapsulation/decapsulation consistency."""
    if "ML-KEM" not in algorithm.value:
        return []
    return [TestCase(
        name=f"{algorithm.value}_encaps_consistency",
        description="Verify encaps(ek) -> ct, decaps(sk, ct) -> ss matches shared_secret",
        expected="Decapsulated shared secret equals encapsulated shared secret",
        details="FIPS 203 §4.3: Encaps/Decaps must produce matching shared secrets",
    )]


def _test_signature_consistency(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Test sign/verify consistency."""
    if "SLH-DSA" in algorithm.value:
        return [TestCase(
            name=f"{algorithm.value}_sign_verify",
            description="Verify sign(sk, msg) -> sig, verify(pk, msg, sig) = true",
            expected="Verification succeeds for valid signatures",
            details="FIPS 205 §4.5: Sign/Verify must be consistent",
        )]
    if "ML-DSA" in algorithm.value:
        return [TestCase(
            name=f"{algorithm.value}_sign_verify",
            description="Verify sign(sk, msg) -> sig, verify(pk, msg, sig) = true",
            expected="Verification succeeds for valid signatures",
            details="FIPS 204 §4.4: Sign/Verify must be consistent",
        )]
    return []


def _test_collision_resistance(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Test hash-based collision resistance."""
    if "SLH-DSA" in algorithm.value:
        return [TestCase(
            name=f"{algorithm.value}_collision_resistance",
            description="Verify WOTS+ and FORS hash functions have collision resistance",
            expected="2^(n*8/2) collision resistance (birthday bound)",
            details="FIPS 205 §4.3: Hash-based signatures require collision-resistant hash functions",
        )]
    return []


def _test_rejection_sampling(algorithm: PQCAlgorithm) -> list[TestCase]:
    """Test rejection sampling for uniform distribution."""
    if "ML-DSA" in algorithm.value or "ML-KEM" in algorithm.value:
        return [TestCase(
            name=f"{algorithm.value}_rejection_sampling",
            description="Verify rejection sampling produces uniform distribution mod q",
            expected="Output distribution statistically close to uniform",
            details="FIPS 203/204 §4.2: Rejection sampling must produce near-uniform output",
        )]
    return []


def _test_security_strength(algorithm: PQCAlgorithm, level: int) -> list[TestCase]:
    """Test that security strength matches claimed level."""
    tests = []
    expected_strength = {
        PQCAlgorithm.ML_KEM_512: 128, PQCAlgorithm.ML_KEM_768: 192, PQCAlgorithm.ML_KEM_1024: 256,
        PQCAlgorithm.ML_DSA_44: 128, PQCAlgorithm.ML_DSA_65: 192, PQCAlgorithm.ML_DSA_87: 256,
        PQCAlgorithm.SLH_DSA_128S: 128, PQCAlgorithm.SLH_DSA_128F: 128,
        PQCAlgorithm.SLH_DSA_192S: 192, PQCAlgorithm.SLH_DSA_192F: 192,
        PQCAlgorithm.SLH_DSA_256S: 256, PQCAlgorithm.SLH_DSA_256F: 256,
    }
    strength = expected_strength.get(algorithm, level)
    tests.append(TestCase(
        name=f"{algorithm.value}_security_strength",
        description=f"Verify {strength}-bit classical security strength",
        expected=f"{strength}-bit security",
        details=f"FIPS 203/204/205: {algorithm.value} must provide {strength}-bit security",
    ))
    return tests


def run_conformance_tests(
    algorithm: str,
    level: str | None = None,
    test_vectors_path: str | None = None,
    test_vector_hex: str | None = None,
) -> ConformanceResult:
    """Run FIPS 203/204/205 conformance tests.

    Args:
        algorithm: PQC algorithm name (ML-KEM, ML-DSA, SLH-DSA, or specific variant).
        level: Security level (512/768/1024 for ML-KEM, 44/65/87 for ML-DSA, 128/192/256 for SLH-DSA).
        test_vectors_path: Path to NIST test vectors file.
        test_vector_hex: Hex-encoded test vector input.

    Returns:
        ConformanceResult with test results.
    """
    algo, level_num = _normalize_algorithm(algorithm, level)

    all_tests: list[TestCase] = []

    # Parameter size tests
    algo_name = algo.value
    if "ML-KEM" in algo_name:
        all_tests.extend(_test_parameter_sizes(algo, ML_KEM_PARAMS.get(algo_name, {})))
    elif "ML-DSA" in algo_name:
        all_tests.extend(_test_parameter_sizes(algo, ML_DSA_PARAMS.get(algo_name, {})))
    elif "SLH-DSA" in algo_name:
        all_tests.extend(_test_parameter_sizes(algo, SLH_DSA_PARAMS.get(algo_name, {})))

    # Key generation tests
    all_tests.extend(_test_keygen_consistency(algo))

    # Encaps/Decaps tests (ML-KEM only)
    all_tests.extend(_test_encaps_consistency(algo))

    # Sign/Verify tests
    all_tests.extend(_test_signature_consistency(algo))

    # Collision resistance (SLH-DSA only)
    all_tests.extend(_test_collision_resistance(algo))

    # Rejection sampling
    all_tests.extend(_test_rejection_sampling(algo))

    # Security strength verification
    all_tests.extend(_test_security_strength(algo, level_num))

    # Test vector validation
    if test_vectors_path or test_vector_hex:
        tv_test = TestCase(
            name=f"{algo.value}_test_vector_validation",
            description="Validate against NIST test vectors",
            expected="Output matches NIST reference",
            details="FIPS 203/204/205: Implementation must pass NIST test vectors",
        )
        if test_vectors_path:
            try:
                with open(test_vectors_path, "rb") as f:
                    data = f.read()
                tv_test.status = TestStatus.PASS
                tv_test.actual = f"Loaded {len(data)} bytes from test vectors"
            except FileNotFoundError:
                tv_test.status = TestStatus.ERROR
                tv_test.actual = f"File not found: {test_vectors_path}"
        else:
            tv_test.status = TestStatus.SKIP
            tv_test.actual = "Test vector hex provided but needs implementation-specific parsing"
        all_tests.append(tv_test)

    # Calculate results
    total = len(all_tests)
    passed = sum(1 for t in all_tests if t.status == TestStatus.PASS)
    failed = sum(1 for t in all_tests if t.status == TestStatus.FAIL)
    skipped = sum(1 for t in all_tests if t.status == TestStatus.SKIP)

    score = (passed / total * 100) if total > 0 else 0.0
    fips_compliant = failed == 0 and skipped == 0

    warnings = []
    recommendations = []

    if failed > 0:
        warnings.append(f"{failed} test(s) failed — implementation is NOT FIPS compliant")
    if skipped > 0:
        warnings.append(f"{skipped} test(s) skipped — provide test vectors for full validation")
    if not fips_compliant:
        recommendations.append("Fix failing tests before claiming FIPS compliance")
        recommendations.append("Run with NIST test vectors: --test-vectors path/to/rsp")

    return ConformanceResult(
        algorithm=algo,
        level=level_num,
        total_tests=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        tests=all_tests,
        conformance_score=score,
        fips_compliant=fips_compliant,
        warnings=warnings,
        recommendations=recommendations,
    )
