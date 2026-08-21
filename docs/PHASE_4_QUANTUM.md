# Phase 4: Quantum Shor Simulation

## Status: DONE

## Deliverables
- `notebooks/01_quantum_threat_demo.ipynb` (12 cells; copied from `shor_demo.ipynb`)
- Uses qiskit 2.5 + qiskit-aer 0.17 (qiskit311-compatible)
- Simulates Shor's algorithm against RSA keys
- Shows "qubits needed to break" + IBM/Google roadmap timeline

## Verification
- `jupyter nbconvert --to notebook --execute` — 0 errors, all 12 cells run
- Outputs verified:
  - RSA-1024 → 2,051,000 physical qubits; RSA-2048 → 4,096,000; RSA-3072 → 6,147,000; RSA-4096 → 8,195,000
  - Qubit-vs-RSA chart and roadmap chart saved (`shor_qubits_vs_rsa.png`, `shor_roadmap.png`)
  - Risk assessment cell: all current RSA key sizes are breakable on the IBM roadmap horizon

## Notes
- This is the sales tool — converts the abstract Shor threat into a concrete timeline
- The same resource table is reproduced programmatically in `pilot/run_pilot.py` (step 3)