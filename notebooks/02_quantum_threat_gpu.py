"""Quantum threat demonstration — GPU-aware Shor simulation + RSA threat estimates.

Run as a script or in Jupyter:
    python notebooks/02_quantum_threat_gpu.py

Uses qiskit-algorithms + qiskit-aer(-gpu) when available; otherwise falls back
to an honestly-labeled classical Pollard's rho for small N. All quantum
resource estimates come from published roadmaps via
qtrust_planner.quantum_estimator.QuantumThreatEstimator.
"""
import time

# Check for GPU simulator
gpu_available = False
sim_error = None
try:
    from qiskit_aer import AerSimulator  # noqa: F401

    test_sim = AerSimulator(method="statevector", device="GPU")
    gpu_available = True
    print("✓ GPU-accelerated simulator available")
except ImportError:
    sim_error = "qiskit-aer not installed (pip install qiskit-aer)"
except Exception as exc:  # GPU driver/CUDA issues
    sim_error = str(exc)

if sim_error:
    print(f"⚠ quantum simulator unavailable: {sim_error}")
    print("  factor() will use the classical fallback with honest method labels.")

from qtrust_planner.quantum_estimator import QuantumThreatEstimator

estimator = QuantumThreatEstimator()

# ── Factoring demo ────────────────────────────────────────────────────────────
numbers = [15, 21, 35, 77]
results = {}
for N in numbers:
    print(f"\nFactoring N={N}...")
    start = time.time()
    result = estimator.factor(N, use_gpu=gpu_available)
    elapsed = time.time() - start
    results[N] = result
    status = "✓" if result.success else "✗"
    print(
        f"  {status} factors={result.factors} "
        f"method={result.method!r} circuit_qubits={result.quantum_circuit_qubits} "
        f"time={elapsed:.2f}s"
    )

# ── RSA threat estimates ──────────────────────────────────────────────────────
print("\n=== Quantum Threat Estimates (Gidney & Ekerå 2019 + hardware roadmaps) ===")
report = estimator.generate_threat_report([1024, 2048, 3072, 4096])
for key, est in report["key_sizes"].items():
    year = est["estimated_breakable_year"] or "after 2033"
    print(
        f"{key:>8}: {est['logical_qubits_needed']:>6,} logical qubits | "
        f"{est['physical_qubits_needed']:>12,} physical | breakable ~{year}"
    )

out_path = "quantum_threat_report.json"
estimator.save_report(out_path)
print(f"\nFull report saved to {out_path}")
