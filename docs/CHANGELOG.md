# Changelog

All notable changes to Q-Trust are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Real-data training campaign + X.509 encoder fix + tie-aware metrics + strategic analysis (2026-08-29)

**Real-data corpus expanded (web-collected, all public):**

- **Code corpus 4,431 → 13,058 real files.** Added production crypto libraries
  (`openssl/openssl`, `google/boringssl`, `aws/aws-lc`, `mbedtls/mbedtls`,
  `wolfSSL/wolfssl`, `gpg/libgcrypt`, `randombit/botan`, `PyCryptoDome/pycryptodome`,
  `paramiko/paramiko`, `nodejs/node`, `golang/go`) and pure non-crypto control
  repos (`numpy`, `pandas`, `react`, `svelte`, `commons-lang`).
- **Live TLS inventory 60 → 131 real hosts** (banks, cloud, gov/edu, security
  vendors) with real cert algorithms/key sizes/expiry — converted to **39 real
  enterprise CBOMs** in `planner/data/real_cboms/`.
- **NVD CVE data 138 → 401 real CVEs** across all 16 crypto libraries (incl.
  previously rate-limited botan, libgcrypt, gnupg, gnutls, nss, nettle...).

**X.509 encoder bug — fixed (silent real-data poison).**
`encode_algorithm_type` prefix-matched `sha256WithRSAEncryption` to `SHA` (7)
instead of `RSA` (0), so real TLS certs were featurized as hash algorithms and
real-CBOM rankings were anti-correlated (τ ≈ −0.6). Now maps X.509 signature
OID names to the underlying key type in both `model.py` and `model_v3.py`.

**Real-CBOM eval suite — actually real now.** `eval_harness.py` scanned a file
path (`planner/data/algorithms.json`) as a directory and silently fell back to
synthetic; it now loads `planner/data/real_cboms/` (39 real enterprise CBOMs
from live TLS scans).

**Tie-aware ranking metric.** `score_order` now reports Kendall **τ-b against
priority scores** — identical assets (e.g. eight RSA-2048 certs) are genuinely
indistinguishable, so arbitrary dense-rank labels no longer punish every model
(τ was meaningless/negative before). τ-b ≡ τ-a on synthetic graphs, so
historical numbers remain comparable.

**GNN trained on real CBOM graphs — best model on every suite.**
`train_gpu.py` gained `--init` (checkpoint continuation) and `--real-cboms`
mixing. The fine-tuned `model_real_v3.pt` is now the canonical default
(`predict.py` resolution order):

| Suite | model_gpu_v3 (synth) | **model_real_v3 (real-data)** |
| --- | --- | --- |
| in-dist τ | 0.9683 | **0.9710** |
| OOD-size τ | 0.8844 | **0.8850** |
| enterprise τ | 0.9680 | **0.9690** |
| **real-CBOM τ-b** | 0.7077 | **0.8074** (heuristic ceiling 0.855) |

**All 15 qtrust_ai models trained on real data** (`train_qtrust_all.py --real`):
CryptoCodeDetector fine-tuned CodeBERTa on **10,294 real examples on GPU**
(train accuracy 0.953, eval precision 0.978), plus purpose classifier, risk,
recommender, anomaly, vendor, and regression models; RL agent re-benchmarked
(106.82 vs random 106.06, 100% completion).

**Strategic analysis + design assets.** `docs/STRATEGIC_ANALYSIS.md` (how the
developer would take the project further — audit-first, trust decentralization,
real-data moat, technology adoption). New rendered design images in
`docs/design/`: `architecture_target.svg`, `dashboard_mockup.svg` (Quantum
Security Control Center), `verify_page_mockup.svg`, `roadmap.svg`.

### Specialist sub-audit + PQC Passport + competitive positioning (2026-08-29)

- **`docs/SPECIALIST_AUDIT.md`** — nine specialized sub-agent reviews
  (contracts, backend/indexer, frontend/UX, ML/planner, SDK, DevOps,
  compliance, data/moat, competitive), each with code-verified findings and
  prioritized actions. Verified in this pass: the indexer already has reorg
  rewinding, `verify.ts` has SSRF guards, the copilot is honestly
  deterministic-evidence-first, and 207 Foundry tests are present.
- **New design images** in `docs/design/`: `passport_mockup.svg` (PQC
  Passport — readiness score, attestation history, vendor evidence) and
  `competitive_positioning.svg` (2×2 market map + feature matrix vs
  Keyfactor / DigiCert Quantum Central / IBM Quantum Safe).
- Research refresh: NIST IR 8547 (deprecate 2030 / disallow 2035), CNSA 2.0
  (2027 vendor requirement), FIPS 140-2 sunset (Sep 2026), W3C VC 2.1 +
  BBS+ selective disclosure, and market stats (87% pursue PQC, 7% deploy at
  scale — DigiCert 2026) inform the roadmap.

### HPO real objectives + QTrace-FM real loss (2026-08-29)

- **HPO no longer scores dummy/random objectives.** `planner/qtrust_planner/hpo.py`
  previously returned a random-ish score from `_objective_dummy` (its own
  docstring said "Placeholder objective — replace with real training +
  eval_harness()"). Every track now runs a **real, reduced-scale training + held-out
  evaluation**: `plan` trains a small MigrationGNNv3 and reports Kendall τ on a
  held-out suite (canonical `score_order` protocol); `code` trains
  `CryptoCodeDetector` and reports macro-F1; `risk` fits the QRisk ensemble and
  reports held-out accuracy; `trace` runs the real masked-patch reconstruction
  loss. Trial budgets are recorded in the result JSON and the winner is
  retrained at full scale (relative ranking only — no reduced-scale number is
  presented as a final benchmark).
- **QTrace-FM pretraining loss was a stub.** `pretrain_step` returned
  `recon.mean() * 0.01` (never compared against input). It is now a real
  MAE-style masked-patch reconstruction: a learnable mask token replaces masked
  patch embeddings and the loss is MSE over the masked patches vs original
  patch pixels (`planner/qtrust_planner/qtrace_fm.py`).

### Model-training rigor campaign — every checkpoint retrained and benchmarked (2026-08-28)

Rigorous retraining of every shipped model with honest, verified metrics:

**Planner GNN v3 — HPO sweep at 4× A100 scale.** A 4-config hyperparameter
sweep (graph counts 150-250K, LR 5e-4-1e-3, weight decay, 200-300 epochs,
LayerNorm, warmup-cosine, best-checkpoint selection) replaced the single
config. Two real training bugs were found and fixed along the way:

- **ListMLE NaN at scale (fixed).** The vectorized per-graph ListMLE loss
  (P0-1 fix) computed segmented suffix-logsumexp in float32; when logits
  spanned a wide range, the segment decomposition `seg_total - within + e`
  suffered catastrophic cancellation, going slightly negative and producing
  `log(NaN)` after ~10-20 epochs — silently corrupting the loss while the
  weights looked clean. Now computed in float64 with a mathematically exact
  `clamp(min=e)` floor (the suffix sum always contains the current element's
  exp). Verified: 0 NaN, 0 negative losses, matches the reference within
  3.6e-7, plus a regression test. This also unblocked a 3-6× training
  speedup (vectorized loss + subsampled validation + no torch.compile
  recompilation churn on dynamic PyG shapes).
- Sweep winner (config A: 200K graphs, LayerNorm, warmup-cosine,
  best-checkpointing) reached **v3 τ 0.9746** on the held-out set — up from
  the previous canonical 0.9718 — see `planner/results/benchmark_v3.json` and
  the README results table.

**RL migration agent — PPO is now real PPO.** The previous implementation
was a stub: the importance ratio `exp(log π_θ - log π_θ_old)` reused the
rollout log-probs, so the ratio was identically 1 and the clipped surrogate
never engaged (plain advantage-weighted SGD in PPO clothing). The rollout is
now fully vectorized (one batched GNN forward per step across all 64 envs,
~160× faster than the serial loop) and each inner epoch recomputes
log-probs under the *updated* policy with the true importance ratio, plus a
fresh critic pass. Regression tests assert `evaluate()` matches
`select_action()` log-probs and the vectorized feature builder matches
`state_to_tensors()`. Retrained at 4K rollouts × 64 envs on A100 — see the
README results table for the measured mean reward.

**qtrust_ai intelligence layer — real-data retrain with baseline
comparison.** `train_qtrust_all.py --real` retrained all 15 models on the
real cached datasets (4,431 code samples, 60 TLS hosts, 16 vendor records):
15/15 trained, 0 errors, 15/15 calibration anchors. The existing
`BaselineComparison` module (qtrust_ai/benchmark/compare.py) was never wired
into training — it now runs after every real-data training and writes
`qtrust_ai/artifacts/benchmark_comparison.json`: 7 comparisons, 6/7 models
beat their best naive baseline, mean relative gain 8.98×.

**Inspector models retrained.** Canonical side-channel detector (80 epochs,
perfect clean-vs-leaky separation on real liboqs traces: 0.05 VERIFIED vs
0.95 HIGH_RISK) and anomaly VAE (80 epochs, threshold 0.2754) regenerated
and verified through the production GPU bridge.

**Honesty fixes a reviewer would flag:**

- `export.py` no longer writes fake `exports/*.onnx` files — the committed
  "exports" were JSON error markers (e.g. `{"error": "No module named
  'onnxscript'"}`) and JSON stubs for the inspector models. Removed from
  git, `exports/` gitignored, and the exporter now performs real ONNX
  exports (side-channel CNN, anomaly VAE) with a clear `pip install onnx
  onnxscript` error when deps are missing — never a placeholder.
- `Makefile.gpu` created — it was referenced by 6+ doc pages (GPU_FEATURES,
  api, index, CHANGELOG) but did not exist. Now provides `train-gnn[-quick]`,
  `train-rl[-quick]`, `side-channel-train`, `anomaly-train`, `help` wired to
  the real training entry points.
- `sweep_gnn.py` now launches via the argument wrapper instead of an inline
  `python -c` blob (which broke on shell quoting and caused duplicate
  generations to race on the same logs/checkpoints).
- Minor: `code_detector.py` detached a grad-carrying tensor before
  `float()` (removes the UserWarning in the fine-tune loop).

### Security — external codebase audit remediation (2026-08-26)

Remediates the 2026-08-26 Z.ai engineering audit (`docs/Q-Trust_Codebase_Audit.pdf`).
All Critical and High findings are fixed with regression tests; all Medium,
Low, and Informational code findings are fixed unless explicitly noted below.

**Critical**

- **C-1 — deployer retained unilateral governance control.** `Deploy.s.sol` now
  transfers `QTrustGovernance.DEFAULT_ADMIN_ROLE` to the timelock, then the
  deployer renounces timelock admin/proposer/executor/canceller roles and
  governance admin. Regression test
  (`contracts/test/AuditRemediations.t.sol::test_C1_*`) runs the actual deploy
  script and asserts zero residual deployer roles.
- **C-2 — `schedule()` allowed UUPS upgrade bypass.** `_isRoleMutationCall`
  now also rejects `upgradeTo` (0x3659cfe6) and `upgradeToAndCall` (0x4f1ef286)
  selectors, closing implementation-swap-after-delay.

**High**

- **H-1 — `attestProductSigned` skipped the VENDOR_ROLE check** (the only
  signed path in the codebase without a post-recovery role check). Added;
  regression test revokes the role from a still-active vendor and expects
  `NotVendor`.
- **H-2 — missing `whenNotPaused`** on `TrustAnchorRegistry.revokeAccreditation`,
  `reaccreditIssuer`, `SchemaRegistry.addEquivalence`, `deactivateSchema`.
- **H-3 — `/v1/relay/*` gas-griefing.** All four relay POST routes now require
  an API key, and the relayer pre-checks the signer's on-chain role before
  broadcasting (failed txs no longer cost relayer gas). Operators must issue
  API keys to relaying clients (see `.env.example`); dev mode without keys is
  unchanged.
- **H-4 — Sentry could capture secrets.** `beforeSend` scrubs `x-api-key`/
  `authorization`/cookie headers, redacts request bodies, masks any
  64-hex private-key-shaped string anywhere in the event; `sendDefaultPii: false`.
- **H-5 — webhook secrets stored plaintext when `QTRUST_WEBHOOK_ENC_KEY`
  unset.** Production now refuses to store unencrypted subscriber secrets
  (fail-closed); dev fallback retained.
- **H-6 — RPC-pool Proxy broke `watchEvent` unsubscription.** The indexer now
  awaits the pooled `watchEvent` Promise so real unwatch functions are stored;
  new test asserts `stopIndexer` unsubscribes all seven streams.
- **H-7 — `/v/[id]` interpolated server-controlled `asset_id` into copy-paste
  shell commands.** `parseAssetId` enforces strict `^0x[0-9a-fA-F]{64}$`; the
  CLI block renders only for valid IDs, otherwise a warning explains how to
  verify manually.
- **Planner HIGH-1 — inference endpoints unauthenticated.** New
  `ApiKeyMiddleware` enforces `X-Auth… X-Api-Key` (`QTRUST_PLANNER_API_KEY`);
  fail-closed 503 in production when unset. Backend proxies forward the key.
  First-ever planner HTTP tests added (`planner/tests/test_server.py`).

**Medium**

- M-1: count-only + paginated views across Asset/Vendor/Migration/Audit/
  Compliance/Revocation/TrustAnchor registries; `AuditRegistry._postAudit`
  reads a count instead of copying the full per-org array.
- M-2: `MigrationRegistry._recordMigration` uses the `orgDid` already returned
  by `verifyAsset` (one cross-contract call instead of two).
- M-3: operational role grants restricted to the timelock only (proposer-to-
  proposer lateral grants removed).
- M-4: `ComplianceAttestation.getOrgComplianceStatus` is O(1) via a latest-
  attestation pointer; revocation clears it.
- M-5: `PolicyCommitment.commitPolicy` enforces version == 1 for new policies
  and latest+1 afterwards (a v=type(uint256).max brick is impossible).
- M-6/M-7: `/v1/evidence/create` API-key gated with a 5/min route limit and a
  bounded in-memory chain; `/v1/stats` gated and scan targets stored as keyed
  hashes (no absolute paths).
- M-8 (reorg): after a reorg purge the indexer re-runs backfill so re-executed
  events are indexed immediately, not on next restart.
- M-8 (docker): runtime image installs production-only node_modules (dev deps
  no longer shipped); inspector installed into a venv (PEP 668 respected).
- M-9: webhook payloads carry `timestamp` + `expires_at` (5-minute TTL) so
  recipients can reject replays.
- M-10: single shared `requireApiKey` (per-call env read, cached 30s, uniform
  401 semantics); the divergent server.ts copy was deleted.

**Low / Informational**

- L-1: `MigrationVerified` and `IssuerDeactivated` events emitted; deactivateIssuer
  also validates registration and pauses.
- L-2: `EvidenceRegistry` batch IDs use OZ `Strings.toHexString` (batch ID
  format gains `0x` prefixes — off-chain parsers of `batchId` must adjust).
- L-3: address-addressed `scheduleGrantRoleOn/schedulePauseOn/scheduleUnpauseOn`
  wrappers reach all ten registries, not just the core four.
- L-4: redundant contract-level `_initialized` guards removed from all ten
  registries (OZ Initializable suffices). **Storage layout shifted — redeploy
  via Deploy.s.sol rather than upgrading existing staging proxies.**
- L-6: schema equivalences require both endpoints to exist.
- L-7: reaccreditation clears stale `revocationReason`.
- L-8: default RPC endpoint is `https://sepolia.base.org`; production refuses
  plaintext `http://` RPC at boot.
- L-9: Dockerfile creates/chowns `/var/lib/qtrust` so the evidence chain
  persists for the non-root user.
- I-1/I-2/I-4: misleading `NotRegistrar` error split out as
  `NotOwnerOrAdmin`; dead `verifySignature` and unused auth helpers deleted.
- SDK M-3/M-4: loopback-RPC guard parses hostnames properly (userinfo-substring
  bypass blocked); malformed VC `proofValue` returns `invalid_signature`
  instead of raising.
- Inspector pcap DoS bounds documented; MAX_CONNS tightening tracked upstream.

### Added

- `contracts/test/AuditRemediations.t.sol` — C-1/C-2/H-1/H-2/L-6/M-4/M-5
  regressions (contract suite now 211 tests).
- `backend/tests/indexer.test.ts` — H-6 unsubscription regression.
- `backend/tests/secret-box.test.ts` additions — H-5 production fail-closed.
- `frontend/src/components/__tests__/attestation-form.test.tsx` — first tests
  for the signing component: domain pinning, nonce fetch → sign → relay
  round-trip, chain-switch behavior, error surfacing.
- `planner/tests/test_server.py` — first tests for the FastAPI surface:
  health shape, plan happy path/validation, API-key auth matrix, prod fail-closed.
- `models.sha256` + `scripts/verify_models.sh` + CI `model-integrity` job —
  committed `.pt` checkpoints are now tamper-evident.
- CI `abi-drift` job — regenerates `abis.ts`/`contracts.py` from Forge
  artifacts and fails on drift (previously claimed but not implemented).
- CI `golive-preflight` job (release tags only) — fails releases that still
  carry `_PLACEHOLDER_` escalation contacts or the placeholder security email.
- Pre-commit hooks pinned to commit SHAs (supply-chain parity with CI).

### Changed

- Docs: WHITEPAPER §6.5 benchmark numbers refreshed to the corrected Kendall
  protocol (τ=0.89 → τ=0.961 canonical); PHASE_6/PHASE_7 marked SUPERSEDED;
  QTrust_Implementation_Guide.md marked HISTORICAL and excluded from mkdocs.
- ABIs regenerated from Forge artifacts (new views/events above).

### Known remaining blockers (external — cannot be closed from code)

- Base Sepolia faucet funding, frontend/backend hosting accounts
  (Implementation Gaps #2–#4).
- Real incident-response contacts and security mailbox (CI gate enforces
  replacement before any release).
- `docs/PATENT/` remains tracked pending a legal decision.


### Fixed

- **Benchmark Kendall-tau protocol bug (`benchmark.score_order`)** — tau was
  computed by index-correlating the two *order sequences* (node IDs at each
  list position) instead of comparing per-node ranks. Any imperfect model
  was silently understated; the repo's historical GNN τ ≈ 0.27–0.39 grew to
  **τ ≈ 0.78–0.96** under the corrected per-node-rank protocol while the
  heuristic upper bound stays 1.00. `train_gpu.compute_metrics` already used
  the correct formulation and is now cross-validated by a regression test
  suite (`planner/tests/test_benchmark_protocol.py`). `results/benchmark.json`
  regenerated at canonical scale.
- **RL agent critic/advantage broadcasting bug** — stacked per-step values had
  shape `(T, 1)` against `(T,)` returns, silently broadcasting the advantage
  and critic loss to `(T, T)` and corrupting policy gradients; values are now
  flattened before the loss computation (`planner/qtrust_planner/rl_agent.py`).
- **Anomaly VAE threshold persistence** — training calibrates a data-derived
  decision threshold but checkpoints only stored weights, so reloaded
  detectors silently fell back to the 0.8 default; checkpoints now persist
  `{state_dict, threshold}` with legacy raw state-dict loading still
  supported (`inspector/qtrust_inspector/anomaly_detector.py`).
- **Invariant-handler bugs surfaced by `fail_on_revert = true`** — pause
  toggles in `RegistryHandler` lacked admin roles (silently reverting since
  inception) and bounded salts replayed duplicate content-addressed IDs;
  fixed via role grants and ghost-set dedup.

### Changed

- **Shor factoring no longer depends on `qiskit_algorithms`** — order finding
  is implemented directly via quantum phase estimation on the modular
  multiplication permutation unitary, compatible with qiskit 1.x/2.x and any
  Aer backend (GPU when available, CPU otherwise, classical Pollard's rho as
  labeled last resort). Controlled-U powers are executed natively by Aer as
  block unitaries (no transpilation synthesis), making the demo ~20x faster:
  N=35 factors via the full quantum path in <1s and order finding for
  N=77 completes in ~3s.
- **requirements-gpu.txt** — drop unused gymnasium pin and document that the
  legacy `qiskit-aer-gpu` PyPI package stops at Python 3.12 (use a GPU-built
  Aer on newer Pythons).
- **Invariant testing strengthened** — foundry `[invariant]` raised to
  runs=1000, depth=100 with `fail_on_revert = true`; all 189 contract tests
  pass under the strict config.
- **Rate limiter configurable** — `QTRUST_RATE_LIMIT_MAX` env override
  (`0` disables globally, e.g. behind an edge proxy or for load tests);
  default unchanged at 120/min per IP.
- **k6 stress thresholds scoped per tag** so intentional 404 probes don't
  fail the global budget; measured results published in PERFORMANCE.md
  (147.8 req/s @ 100 VUs, p95 = 11.3 ms).

### Added

- **Frontend GPU panels complete** — `QuantumThreatPanel`, `AnomalyPanel`,
  `RLPlanViewer` join `SideChannelPanel` on the org dashboard's GPU analysis
  grid, with component tests (frontend suite now 44 tests).
- **v2-vs-v3 GNN benchmark** (`planner/qtrust_planner/benchmark_v3.py`) —
  same held-out split and scipy-Kendall protocol as `benchmark.py`;
  writes `results/benchmark_v3.json`.
- **Executable quantum notebook** (`notebooks/02_quantum_threat_gpu.ipynb`)
  generated from the authoritative script and executed with outputs; the
  script is now runnable from any working directory.
- **Publishing pipelines** — PyPI Trusted Publishing workflow
  (`publish-pypi.yml`) and GHCR Docker workflow (`publish-docker.yml`) on
  tags/releases.
- **Documentation site** — `mkdocs.yml` (Material) + GitHub Pages workflow;
  new pages: PERFORMANCE.md, MULTI_CHAIN.md, GO_LIVE_CHECKLIST.md,
  case-studies/CASE_STUDY_EXAMPLE_COM.md (scan → CBOM → on-chain → verify,
  validated end-to-end on a local chain-id-84532 chain).
- **Generated API types** — `frontend/src/lib/generated/api-schema.ts` from
  `backend/openapi.yaml` via openapi-typescript.
- **Halmos formal-verification workflow** (report-only mode pending a
  halmos-clean test setup) plus property-based Hypothesis job in CI with a
  `ci` profile (1000 examples where per-test settings allow).
- **GitHub Release v2.0.0** published with release notes, audit PDF, and
  GPU feature bundle.
- **Trained checkpoints at full scale** — RL agent 4K rollouts × 64 envs
  (vectorized PPO; reproducible eval in
  `planner/results/rl_benchmark.json`, `scripts/eval_rl_agent.py`);
  side-channel detector trained at
  5K+5K traces / 50 epochs; anomaly VAE on 1,000 CBOMs / 100 epochs; GNN v3
  best val τ 0.658 → 0.70+ during the 100K-graph run (checkpoint saved
  continuously; `make -f Makefile.gpu train-gnn` reproduces/resumes).

## [2.0.0] — 2026-08-24

Master-audit remediation release. Breaking changes are pre-deployment
(nothing has shipped to a public chain yet).

### Breaking

- **EIP-712 domain separators are now chainid-defensive** — cached per
  `block.chainid` and recomputed on mismatch (EIP-712 "defensive copies"
  pattern) across all six EIP-712 contracts, enabling safe multi-chain
  redeployment. One extra cold SLOAD on signed paths.
- **Deterministic content-addressed IDs verified contract-wide** —
  `computeAssetId()` / `computeAttestationId()` getters exposed;
  duplicates revert with explicit errors.
- **String-length bounds enforced on all contracts** (URI ≤512,
  DID ≤128, IDs ≤64, reason ≤256) via shared `StringBounds` lib.

### Security

Security-hardening fixes shipped in the current hardening pass:

- **VendorRegistry duplicate-attestation DoS fix** — reject and bound duplicate
  attestations so a single vendor cannot exhaust registry gas/loop capacity.
- **Backend scanner wired to real inspector** — backend no longer serves stubbed
  scan results; it invokes the actual `qtrust-inspector` engine end-to-end.
- **SHA-256 evidence chain** — evidence ledger entries are chained with SHA-256
  hashes, making tampering with historical evidence detectable.
- **Fail-closed VC verification (backend + SDK)** — verifiable-credential
  verification now fails closed on signature, schema, or status-check errors
  instead of degrading to an accept.
- **Risk-engine quantum classification correction** — asymmetric keys (RSA,
  ECC) are classified correctly as quantum-vulnerable rather than being
  mis-scored via symmetric heuristics.
- **Operational-role transfer to timelock** — administrative operations moved
  from deployer EOA control to a timelock-governed operational role.
- **Webhook secret redaction** — webhook signing secrets are redacted from all
  logs, error payloads, and API responses.
- **SSRF DNS pinning** — outbound fetches resolve once and pin the resolved IP
  for the connection lifetime, defeating DNS-rebinding SSRF bypasses.
- **Relayer-key fallback removal** — removed hardcoded/fallback relayer keys;
  relayer credentials must be provided explicitly or operations abort.
- **Indexer reorg handling** — chain reorganizations are detected and replayed
  instead of persisting orphaned events into indexed state.

### Added (2.0.0)

- **AuditRegistry `postAuditSigned`** — EIP-712 gasless path for auditors,
  closing the last trust-model gap; backend relay route `/v1/relay/audit`
  (+ nonce endpoint) with TypeBox schema and tests.
- **Solidity invariant + upgrade tests** — handler-based invariants (nonce
  monotonicity, ID uniqueness, paused-rejects-writes at 256×128 depth) and
  UUPS upgrade state-preservation tests; 189 contract tests total.
- **Configurable `MAX_ATTESTATIONS_PER_PRODUCT`** — governor-settable within
  [16, 4096], default 256, with change event.
- **Frontend wallet gating** — /dashboard and /vendors require a connected
  wallet with a recognized role; real admin detection via on-chain
  `hasRole(DEFAULT_ADMIN_ROLE)` read (UI hint only).
- **Mobile + accessibility E2E** — Playwright desktop/mobile projects,
  axe-core wcag2a/2aa assertions on public pages.
- **Code splitting** — provenance graph client-isolated via `next/dynamic`
  (ssr:false), planning panel lazy-loaded on dashboard.
- **Multi-provider IPFS pinning** — Pinata + Kubo + web3.storage behind
  `QTRUST_IPFS_PROVIDERS`, best-effort replication, CID-mismatch warnings.
- **Property-based tests** — 19 hypothesis tests: CBOM-hash determinism,
  VC round-trip/tamper, DID grammar, risk monotonicity, evidence-chain
  tamper detection (found + fixed a head-truncation bug in `verify_chain`).
- **Alerting** — Prometheus alert rules (API errors/p99, indexer lag,
  RPC-pool health, relay 429 surge) + AlertManager service.
- **Observability gauges** — `indexer_lag_blocks`,
  `rpc_pool_unhealthy_endpoints`.
- **Operations docs** — incident-response runbook (incl. pause + relayer-
  compromise playbooks), backup/restore drill, step-by-step Base Sepolia
  deployment guide, k6 smoke/stress load-test scripts.
- **Engineering hygiene** — CODEOWNERS, PR/issue templates, ADRs 0000–0006,
  CBOM↔CycloneDX conformance mapping doc, inspector dependency graph.

### Added

- **Real AST-based detection** — Python analysis via the stdlib `ast` module
  (scope-aware, key-size/curve refinement, false-positive controls);
  optional tree-sitter upgrade path for JS/TS with honest per-finding
  `detector` labels (`ast-python` / `tree-sitter` / `regex-fallback`).
  Wired into CLI, API, and MCP server.
- **Real PCAP TLS extraction** — pure-stdlib pcap/pcapng reader with TCP
  reassembly-lite and full ClientHello/ServerHello parsing: cipher suites,
  negotiated groups (incl. X25519MLKEM768), SNI. HNDL scoring now derives
  from the actual negotiated suite instead of worst-case defaults.
- **Zeek/Suricata log ingestion** — `analyze_zeek_ssl_log` and
  `analyze_suricata_eve` normalize network TLS telemetry into flow records.
- **Binary artifact scanning** — ELF/PE/Mach-O crypto-library fingerprinting
  (OpenSSL/BoringSSL/liboqs/...), JAR/WAR/APK/wheel/gem inspection,
  embedded PEM detection; wired into CLI/API/MCP.
- **Benchmark corpus + CI gate** — labeled ground-truth fixtures with
  precision/recall thresholds enforced in pytest (first published evaluation
  harness in the PQC-scanning space).
- **EAS schema publication kit** — three PQC-compliance attestation schemas
  (compliance, vendor readiness, migration milestone) with field mappings
  from Q-Trust registries plus a Foundry registration script for EAS on Base.
- **FIPS parameter-set validator** — conformance module now executes real
  spec-table checks (PASS/FAIL) against FIPS 203/204/205 constants,
  reserving SKIP strictly for external KAT/ACVP items; corrected stale
  ML-DSA constants to final FIPS values.

### Fixed

- **Deployment integrity** — docker-compose fail-fast credentials (no more
  empty-password Postgres/Redis), loopback-only DB/Redis ports,
  service healthchecks; backend image bundles Python + inspector so
  `/v1/scan/*` works in containers; evidence chain persists across restarts
  (append-only JSONL store); planner serves explicit heuristic mode instead
  of placeholder model weights.
- **Package honesty** — inspector renamed `qtrust-inspector` v1.1.0 with an
  accurate description; SDK version drift resolved (0.2.0/1.0.0 → 1.1.0);
  python-nmap moved to optional extra.

### Changed — Stack Migration (2026-08)

- **Frontend wallet stack** — replaced custom `dynamic-provider.tsx` with
  wagmi 2 + RainbowKit 2 (30+ wallets, chain-switching, mobile support);
  EIP-712 verifyingContract still pinned to local env config, never API.
- **Backend API surface** — @fastify/helmet security headers (HSTS,
  nosniff, frameguard); @fastify/swagger + swagger-ui serving OpenAPI at
  `/docs` (44 paths); TypeBox JSON-Schema validation on scan/evidence/
  risk/compliance/credential routes replacing manual field checks.
- **SDK** — web3.py 7.x (audited: already v7-clean API usage);
  cryptography pinned `>=43,<45`.
- **Planner** — torch pinned `>=2.5,<3.0`; non-root Dockerfile USER;
  Redis sliding-window rate limiter (ZSET pipeline) with graceful
  in-memory fallback across uvicorn workers.
- **RPC reliability** — multi-endpoint failover pool (`QTRUST_RPC_URLS`)
  with round-robin rotation and 60s health cooldown for attestation +
  indexer viem clients.
- **Component primitives** — Radix UI tabs/dialog/select + cva-based
  Button/Card/Badge primitives; scanner dashboard refactored as proof.
- **Observability** — prom-client `/metrics` endpoint with HTTP request
  duration histogram; Prometheus + Grafana (provisioned datasource) added
  to compose on loopback ports; Sentry (backend, DSN-gated no-op).
- **CI completeness** — Dependabot (6 ecosystems, grouped); gitleaks
  secret scanning; `forge verify-contract` job (guarded, push-to-main);
  coverage reporting (pytest-cov + forge coverage → Codecov).

### Deferred (documented, not forgotten)

- Arweave/Walrus storage migration, full 11→EAS contract consolidation
  (schema kit + registration script shipped), ERC-4337 paymaster,
  WebAuthn/passkey auth, Drizzle migrations, Postgres HA — tracked as
  P2 strategic items in the stack-migration checklist.

### Added — GPU-Accelerated Features (2026-08)

Six CUDA features activated on A100-class hardware (`QTRUST_GPU_ENABLED=true`,
`/v1/gpu/*`; see docs/GPU_FEATURES.md, Makefile.gpu):

- **Large-scale GNN training** — MigrationGNNv3 (256-dim hidden, 8 GAT heads,
  4 layers) with BF16 mixed precision; quick run already reaches val
  Kendall τ 0.66 vs the audit-flagged 0.387 baseline. Fixed ListMLE
  (log-cumsum-exp), vectorized Kendall τ.
- **Timing side-channel analysis** — CNN distribution-shape detector
  (sorted-trace + skew/kurtosis channels) with held-out calibration;
  clean → VERIFIED, leaking ≥0.1σ → HIGH_RISK. Redesigned the provided
  simulator, whose original leakage model was mathematically undetectable
  (sub-σ shift vs within-group width); raw-trace input allowed seed
  memorization — both fixed and documented honestly.
- **Quantum threat estimation** — Shor simulation via qiskit-algorithms when
  available, honest classical fallback otherwise (the provided code used
  qiskit ≤0.x APIs removed in 1.0).
- **RL migration agent** — REINFORCE actor-critic over a DAG migration
  environment (cycle-free fix); `/rl/plan` planner endpoint decodes plans,
  reporting `rl_policy` or `heuristic_fallback` truthfully.
- **Parallel enterprise scanning** — async multi-host scanning with SSRF
  validation and optional GPU-batch risk scoring.
- **CBOM anomaly detection** — VAE with per-CBOM threshold calibration
  (per-asset percentile would flag ~98% of normal CBOMs by construction);
  untrained scoring now raises instead of returning garbage.

Backend: stdin-JSON bridge (`backend/scripts/gpu_bridge.py`) — no shell
interpolation of request data; per-request feature gate; 409 for untrained
detectors; OpenAPI-tagged routes + 15 vitest tests.

## [1.1.0] - 2026-06-30

### Added

- **AST-based analysis** — inspector now parses Python/JavaScript ASTs for
  cryptographic API usage detection beyond regex matching.
- **PCAP scoring** — offline network-capture (pcap) TLS/cipher inventory and
  post-quantum readiness scoring.
- **MCP server** — Model Context Protocol server exposing inspector
  capabilities to AI agents and toolchains.
- **Kubernetes admission policies** — ready-made policies blocking non-PQC
  workloads at cluster admission time.
- **Conformance testing suite** — cross-version conformance harness for SDK,
  backend, and contract interfaces.
- **TLS deep probe** — active handshake probing (protocol negotiation,
  key-share inspection, hybrid X25519MLKEM768 verification).
- **Auto-remediation engine** — generated migration steps with prioritized
  remediation plans per asset.
- **11 compliance frameworks** — CNSA 2.0, NIST FIPS 203/204/205 mapping,
  ETSI, BSI TR-02102, PCI DSS, HIPAA, SOC 2, GDPR, FedRAMP, ISO 27001, and
  CISA PQC guidance coverage in compliance reporting.
- **Official GitHub Action** (`qtrust-inspector-action`) for CI integration.

## [1.0.0] - 2026-03-15

### Added

Enterprise-grade release of the Q-Trust platform.

- **Scanner suite** — multi-language cryptographic asset discovery across
  Python, JavaScript/TypeScript, Go, Java, Rust, and C# codebases.
- **Risk engine** — quantitative post-quantum risk scoring with
  exploitability-weighted prioritization ("harvest-now-decrypt-later" aware).
- **Compliance frameworks** — pluggable framework reporting (CNSA 2.0 gate)
  with machine-readable results.
- **CycloneDX CBOM** — Cryptography Bill of Materials generation per scan.
- **SARIF output** — GitHub Security tab integration via SARIF 2.1.0 uploads.
- **Evidence ledger** — on-chain attested audit-evidence records supporting
  enterprise assurance workflows.
- **Roadmap** — published forward plan covering AST analysis, network probes,
  remediation automation, and expanded governance integrations.

[Unreleased]: https://github.com/humoge7502/q-trust/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/humoge7502/q-trust/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/humoge7502/q-trust/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/humoge7502/q-trust/releases/tag/v1.0.0
