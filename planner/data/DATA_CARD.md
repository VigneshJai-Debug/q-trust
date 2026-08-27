# Data Card — Q-Trust Corpora (pdf §17)

Every corpus has schema, provenance, and license recorded; DVC hashes lock data,
runs log data_hash.

## Trace Corpus (Track A)

- **Today (verified, pdf Table 7):** 5 files × 10K scalar ints; 3.5/10+ NIST parameter sets; provenance unverifiable (harness missing, collector measures fork overhead).
- **Program target:** multi-point power/EM/timing, ≥10 parameter sets + classical baselines, full metadata (device, clock, compiler, implementation version) per capture.
  - ML-KEM-512,768,1024; ML-DSA-44,65,87; SLH-DSA (128s/f,192s/f,256s/f); Falcon-512/1024; HQC-128/192/256; classical RSA/ECC baselines.
- **Harness:** `qtrust_inspector.side_channel.collect_timing_traces` (subprocess wall-clock) is being replaced by `inspector/scripts/trace_harness.c` (multi-point, cycle-accurate, registered in `inspector/pyproject.toml`).
- **Leak library:** ≥20 documented leaking implementations (known-leaky reference, for fine-tuning).
- **Versioning:** `dvc.yaml` tracks `data/traces_v1` with `dvc locked-hash`.

## Estate Corpus (Tracks B, D)

- **Today:** 454 TLS-only scans; enterprise generator defaulted off (backward compat).
- **Target:** enterprise-topology synthetic at scale + ≥1K real estates, org-level splits (no leakage across train/eval).
  - Generator: `planner/qtrust_planner/data_generator.py:enterprise_topology=True` switched on; layers L0 infra 15% → L1 services 40% → L2 edge 45%, cross-layer p=0.12/0.09.
  - Real CBOMs: `cbom_to_dependency_graph()` with host-affinity fallback; grown via scheduled scans of maintainer infra + volunteer orgs.
- **Versioning:** `dvc.yaml` tracks `planner/data/estates_v1`.

## Code Corpus (Track C)

- **Today:** 4 benchmark fixtures.
- **Target:** annotated crypto-usage corpus (OpenSSL/forks, language crypto libs, vulnerable-example corpus, synthetically seeded variants). Fixtures become training data with provenance.
  - Builder: `inspector/qtrust_inspector/qscan_code.py:build_corpus()`.

## Anomaly Corpus (Track D + anomaly detector)

- **Today:** 404 TLS-only scans, all medium criticality, zero expired, zero PQC (expired/PQC/weak-key features constant zero). Threshold at 95th percentile of training-set reconstruction error (leak).
- **Fixed:** `inspector/qtrust_inspector/anomaly_detector.py` now thresholds on per-CBOM maxima (not per-asset percentile) and logs threshold in checkpoint; training data includes synthetic diversity (criticality expired/PQC varied); `qrisk.py` feature store feeds rebuilt VAE.

## Versioning

- DVC: `dvc.yaml` (see root) locks `planner/data` and `inspector/data` with hashes; CI asserts `dvc status` clean.
- Every `train_gpu.py` / `train_ddp.py` run logs `data_hash = sha256(n_graphs-seed-batch)` in checkpoint and registry.
- Split scripts are committed (`generate_dataset`, `generate_migration_graph`, `cbom_to_dependency_graph`) so any dataset is regeneratable from raw captures.

## Preprocessing Standards (Phase 0, frozen)

- Per-device trace normalization with recorded statistics; augmentations (jitter, resampling, clock desync) only on training split.
- Graph feature schema frozen (6-dim: alg_type/14, key_size/4096, vendor_pqc_ready, criticality/5, days_to_deadline/730, required_rate) with migration notes.
