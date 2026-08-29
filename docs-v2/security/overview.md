---
title: Security Model
outline: [2, 3]
---

# Security Model

Q-Trust's security model spans three layers: the contracts, the off-chain
services, and the engineering process around both. This page summarizes what
exists today — including its limits.

## On-chain: least privilege by construction

- **Role-based access.** Every registry uses OpenZeppelin `AccessControl`
  with named operational roles (`REGISTRAR_ROLE`, `VENDOR_ROLE`,
  `MIGRATOR_ROLE`, `AUDITOR_ROLE`); no single EOA can write everywhere.
- **UUPS upgrades behind a timelock.** All 11 registries are UUPS proxies;
  operational roles are held by a 7-day `TimelockController` and the deployer
  renounces `DEFAULT_ADMIN_ROLE` after handover (ADR-0003). Consequence:
  no silent upgrades — but also no instant emergency pause; pausing is a
  *scheduled* governance action. That trade-off is deliberate and documented.
- **Gasless writes are still authorized writes.** Every relayed write
  (CBOM registration, vendor attestation, migration recording) is an EIP-712
  typed-data signature with a **per-signer, per-registry nonce** that
  increments on-chain — a replayed submission reverts with
  `InvalidNonce(signer, provided, expected)`. Signature recovery binds the
  signer to the claimed org/vendor identity.
- **Deterministic, content-addressed IDs** (ADR-0006) mean identical payloads
  cannot be double-registered under different IDs.

## Off-chain hardening

The Fastify 5 backend applies CORS allowlisting, API-key auth on admin
writes, per-IP rate limiting, TypeBox schema validation on every body, and a
1 MB request cap. Webhook secrets are AES-256-GCM encrypted at rest and
redacted from logs; outbound webhook delivery includes SSRF protections
(including DNS pinning). Evidence chains are SHA-256 hash-chained so
tampering is detectable without a blockchain write per record.

## Verification & automation

- **211 contract tests** pass under Foundry's strict invariant config
  (`runs=1000, depth=100, fail_on_revert=true`), including invariant,
  fuzz, attack-scenario and upgrade state-preservation suites
  (see `CHANGELOG.md`).
- **Symbolic execution:** Halmos runs in CI — currently in
  *report-only* mode (the shared invariant `setUp` is not yet
  halmos-clean; see `.github/workflows/halmos.yml`).
- **Continuous scanning:** Slither (gated on HIGH findings), Semgrep SAST and
  CodeQL run on every push/PR plus a daily schedule
  (`.github/workflows/security.yml`), with SARIF uploaded to GitHub
  code-scanning. Hypothesis property tests cover the SDK with 1000-example
  CI profiles.

## Reporting vulnerabilities

Please use **GitHub private vulnerability reporting** on this repository
(Security tab → *Report a vulnerability*); see
[SECURITY.md](https://github.com/humoge7502/q-trust/blob/main/SECURITY.md)
for scope, what to include, and disclosure coordination. Do not open public
issues for suspected vulnerabilities.

::: danger Pre-release software
Q-Trust is a **research / pre-release** project. Contracts are deployed to
Base Sepolia (testnet); no mainnet deployment exists. Do not anchor
production trust decisions to it yet.
:::
