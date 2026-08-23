# Changelog

All notable changes to Q-Trust are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/q-trust/q-trust/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/q-trust/q-trust/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/q-trust/q-trust/releases/tag/v1.0.0
