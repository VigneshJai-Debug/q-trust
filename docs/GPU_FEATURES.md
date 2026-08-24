# GPU-Accelerated Features Documentation

## Overview

Q-Trust includes 6 GPU-accelerated features that transform the protocol from
"an idle A100" into a genuinely differentiated product. These features use
the NVIDIA A100 GPU available in the BrevLab environment.

## Features

### 1. Large-Scale GNN Training (P0)

**File:** `planner/qtrust_planner/train_gpu.py` + `model_v3.py`

Trains the migration planner GNN on 100,000 synthetic graphs (vs 1,200)
with BF16 mixed precision on the A100. Uses a larger model (256-dim hidden
vs 64-dim) with 4 GCN layers + GAT attention.

**Why it matters:** Addresses the biggest technical risk identified in the
master audit — the GNN has not been validated at scale. 100K graphs +
larger model should improve τ from 0.387 to 0.55+.

**Usage:**
```bash
cd planner
python -m qtrust_planner.train_gpu --epochs 200 --n-graphs 100000
# Quick test:
python -m qtrust_planner.train_gpu --quick
```

**Expected time:** ~4 hours on A100 for 200 epochs / 100K graphs.

---

### 2. Side-Channel Analysis (P1 — KILLER DIFFERENTIATOR)

**File:** `inspector/qtrust_inspector/side_channel.py`

Analyzes PQC implementations for timing side-channel vulnerabilities by
collecting 10,000+ timing traces and running a CNN+LSTM deep learning
classifier on the A100.

**Why it matters:** No competitor has this. CARAF is an Excel calculator.
QSTriage is rule-based. Keyfactor is vendor-specific. Q-Trust is the first
to verify PQC implementations for side-channel resistance.

**Usage:**
```python
from qtrust_inspector.side_channel import SideChannelAnalyzer

analyzer = SideChannelAnalyzer()

# Train the detector (first time only, ~2 minutes on GPU)
analyzer.train_detector(n_clean=2000, n_leaking=2000, epochs=30)

# Analyze a real implementation
result = analyzer.analyze_implementation(["./ml_dsa_sign", "input.hex"])

# Or analyze simulated traces (for demo)
result = analyzer.analyze_simulated(leakage_prob=0.0)  # clean
result = analyzer.analyze_simulated(leakage_prob=0.8)  # leaking
```

**Verdicts:**
- `SIDE_CHANNEL_VERIFIED` — calibrated leakage probability < 10%
- `SIDE_CHANNEL_LOW_RISK` — 10–50%
- `SIDE_CHANNEL_HIGH_RISK` — > 50%

**How it works:** the detector consumes distribution-shape features of the
timing trace (sorted order statistics + skewness/kurtosis channels) rather
than the raw trace, so its decision depends only on the timing distribution
— the thing secret-dependent execution actually perturbs. Training uses
leakage strengths drawn from U[0.15, 1.0] (below ~0.08σ is genuinely
indistinguishable from constant-time jitter at these trace lengths), and a
held-out calibration split anchors raw scores to probabilities
(clean-median → 0.05, leak-median → 0.95). The analyzer refuses to score
before training (raises / HTTP 409).

---

### 3. GPU-Accelerated Quantum Simulation (P0)

**File:** `notebooks/02_quantum_threat_gpu.py` + `planner/qtrust_planner/quantum_estimator.py`

Uses `qiskit-aer(-gpu)` to simulate Shor's algorithm when available,
factoring larger numbers than possible on CPU. When the quantum stack is
not installed, `factor()` falls back to classical Pollard's rho and labels
the result honestly via `method="classical_fallback (quantum sim unavailable)"`.

**Why it matters:** Makes the sales demo 10x more compelling. Instead of
"we factored N=15 in 30 seconds," you say "we factored N=77 in 5 minutes
using GPU-accelerated quantum simulation."

**Usage:**
```python
from qtrust_planner.quantum_estimator import QuantumThreatEstimator

estimator = QuantumThreatEstimator()

# Factor small numbers (demonstrates Shor's algorithm)
result = estimator.factor(15)  # ~3 seconds on GPU
result = estimator.factor(77)  # ~5 minutes on GPU

# Estimate quantum resources for RSA keys
estimate = estimator.estimate_qubits_for_rsa(2048)
# → logical_qubits: 4099, physical_qubits: 4,099,000, breakable: ~2032
```

**Installation:**
```bash
pip install qiskit-aer-gpu
```

---

### 4. Parallel Enterprise Scanning (P2)

**File:** `inspector/qtrust_inspector/parallel_scanner.py`

Scans 1,000+ hosts in parallel using async I/O, then runs GPU-batch risk
scoring on all discovered assets at once.

**Why it matters:** Enterprises have 50,000+ assets across 1,000+ hosts.
Serial scanning takes hours; parallel scanning takes minutes.

**Usage:**
```python
from qtrust_inspector.parallel_scanner import ParallelScanner
import asyncio

scanner = ParallelScanner(max_concurrent=100, use_gpu=True)

# Scan from a hosts file
result = asyncio.run(scanner.scan_enterprise(["host1.com", "host2.com", ...]))

# Or scan from a file
result = scanner.scan_from_file("hosts.txt")
```

---

### 5. RL Migration Agent (P1 — PATENTABLE MOAT)

**File:** `planner/qtrust_planner/rl_agent.py`

Trains a reinforcement learning agent via simulation to learn optimal PQC
migration strategies. The agent learns which assets to migrate first,
considering dependencies, deadlines, and risk.

**Why it matters:** No competitor has a learned agent. This is patentable
and creates a durable moat.

**Usage:**
```bash
cd planner

# Train the agent (takes ~2 hours on A100)
python -m qtrust_planner.rl_agent

# Quick test (100 episodes)
python -m qtrust_planner.rl_agent --episodes 100
```

---

### 6. CBOM Anomaly Detection (P2)

**File:** `inspector/qtrust_inspector/anomaly_detector.py`

Uses a variational autoencoder (VAE) trained on normal CBOMs to detect
anomalous changes that may indicate security incidents.

**Why it matters:** Detects configuration drift, unauthorized certificate
additions, and sudden appearance of weak algorithms — automatically.

**Usage:**
```python
from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector

detector = CBOMAnomalyDetector()

# Train on normal CBOMs (first time only)
training_cboms = detector.generate_synthetic_training_data(n_cboms=500)
detector.train(training_cboms, epochs=50, save_path="anomaly_model.pt")

# Score a new CBOM
result = detector.score_cbom(new_cbom)
if result.is_anomalous:
    print(f"ANOMALY DETECTED: score={result.anomaly_score:.4f}")
    for asset in result.top_anomalous_assets:
        print(f"  {asset['location']}: {asset['algorithm']} (error={asset['reconstruction_error']:.4f})")
```

---

## Backend Integration

The backend exposes GPU features via REST API:

```
GET  /v1/gpu/status                     — check GPU availability
POST /v1/gpu/side-channel/analyze       — analyze PQC implementation
POST /v1/gpu/anomaly/score              — score CBOM for anomalies
GET  /v1/gpu/quantum/estimate/:bits     — estimate quantum threat
POST /v1/gpu/rl/plan                    — RL-based migration plan
```

Enable in backend:
```bash
# In backend/.env
QTRUST_GPU_ENABLED=true
```

---

## Hardware Requirements

| Feature | Minimum GPU | Recommended | Memory |
|---|---|---|---|
| GNN training (100K graphs) | RTX 3090 | A100 40GB | 8GB |
| Side-channel analysis | RTX 3090 | A100 40GB | 4GB |
| Quantum simulation | A100 40GB | A100 80GB | 5GB (N=77) |
| Parallel scanning | None (CPU OK) | A100 for batch scoring | 2GB |
| RL agent training | RTX 3090 | A100 40GB | 4GB |
| Anomaly detection | None (CPU OK) | A100 for fast training | 2GB |

---

## Build Priority

1. **P0:** GNN training (#1) — addresses biggest audit risk, 3 days
2. **P0:** Quantum simulation (#3) — 10x better demo, 2 days
3. **P1:** Side-channel analysis (#2) — killer differentiator, 2 weeks
4. **P1:** RL agent (#5) — patentable moat, 2 weeks
5. **P2:** Parallel scanning (#4) — enterprise-scale, 1 week
6. **P2:** Anomaly detection (#6) — nice-to-have, 1 week

---

## Backend Integration Notes

- All `/v1/gpu/*` routes are gated by `QTRUST_GPU_ENABLED=true` (checked per
  request). `GET /v1/gpu/status` and the RL proxy are always available.
- Request payloads reach Python **only via stdin JSON** through
  `backend/scripts/gpu_bridge.py` — no shell interpolation of user data.
- Untrained detectors return HTTP 409 (`*_untrained`) rather than garbage
  scores; set `QTRUST_SIDE_CHANNEL_MODEL` / `QTRUST_ANOMALY_MODEL` to
  pre-trained checkpoint paths in the backend environment.
- The RL plan endpoint reports `"method": "rl_policy"` when a trained
  checkpoint exists, otherwise `"method": "heuristic_fallback"`.

## Frontend

`frontend/src/components/side-channel-panel.tsx` exposes the side-channel
analyzer in the scanner dashboard ("Side Channel" tab): run a simulated
analysis with an adjustable leakage slider or analyze a real binary, and
see the calibrated verdict, leakage probability, trace count, accelerator,
and evidence hash. Untrained-detector (409) responses surface a hint
pointing at `make -f Makefile.gpu side-channel-train`.

## Model checkpoints

| Checkpoint | Produced by | Consumed by |
|---|---|---|
| `planner/model_gpu_v3.pt` | `make -f Makefile.gpu train-gnn[-quick]` | parallel scanner risk scoring, planner server |
| `planner/rl_agent.pt` | `make -f Makefile.gpu train-rl[-quick]` | planner `/rl/plan` (`rl_policy`) |
| `inspector/side_channel_model.pt` | `make -f Makefile.gpu side-channel-train` | bridge `side-channel` via `QTRUST_SIDE_CHANNEL_MODEL` |
| `inspector/anomaly_model.pt` | `make -f Makefile.gpu anomaly-train` | bridge `anomaly` via `QTRUST_ANOMALY_MODEL` |

Checkpoints are `.gitignore`d artifacts — train them on the target GPU host.
The anomaly VAE checkpoint stores its calibrated decision threshold alongside
the weights; legacy raw state-dict files still load with the default threshold.
