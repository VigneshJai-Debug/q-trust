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
