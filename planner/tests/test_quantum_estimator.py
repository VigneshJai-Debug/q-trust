"""Tests for the quantum threat estimator.

Verifies Shor factoring (quantum when Aer available, classical fallback
otherwise — both must report honest method labels) and the RSA resource
estimates.
"""
import pytest

from qtrust_planner.quantum_estimator import QuantumThreatEstimator


@pytest.fixture(scope="module")
def estimator() -> QuantumThreatEstimator:
    return QuantumThreatEstimator()


def test_factor_semiprimes_honest_labels(estimator):
    """Factoring succeeds for small semiprimes with a truthful method label."""
    for N, expected in [(15, {3, 5}), (21, {3, 7})]:
        result = estimator.factor(N, use_gpu=True)
        assert result.number == N
        assert result.success, f"factoring {N} failed: {result.method}"
        assert set(result.factors) == expected
        assert set(result.factors) != {1, N}
        # Honest labeling: either real quantum simulation or a labeled fallback.
        assert (
            "shor" in result.method.lower()
            or "classical" in result.method.lower()
            or "gcd" in result.method.lower()
        ), f"opaque method label: {result.method}"
        assert result.elapsed_seconds >= 0


def test_estimate_qubits_for_rsa(estimator):
    est = estimator.estimate_qubits_for_rsa(2048)
    assert est.rsa_key_size == 2048
    assert est.logical_qubits_needed == 2 * 2048 + 3
    assert est.physical_qubits_needed == est.logical_qubits_needed * 1000
    assert est.based_on


def test_breakable_year_monotonic(estimator):
    """Larger keys break later (or never within the roadmap horizon)."""
    years = [estimator.estimate_breakable_year(bits) for bits in (1024, 2048, 4096)]
    known = [y for y in years if y is not None]
    assert known == sorted(known)


def test_threat_report(estimator):
    report = estimator.generate_threat_report([1024, 2048])
    assert "generated_at" in report
    assert set(report["key_sizes"]) == {"RSA-1024", "RSA-2048"}
    assert report["key_sizes"]["RSA-2048"]["logical_qubits_needed"] == 4099
