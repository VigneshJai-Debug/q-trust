# Changelog

All notable changes to Q-Trust are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
