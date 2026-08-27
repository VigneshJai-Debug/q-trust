# Security Policy

Q-Trust is a post-quantum cryptography migration & attestation protocol:
Solidity contracts on Base L2, a Fastify backend, a Python SDK
(`qtrust-sdk`), a cryptography inspector (`crypto-inspector`), a GNN
migration planner, and a Next.js frontend. We take the security of this
stack — and of the systems that will depend on it — seriously.

> **Honesty first:** Q-Trust is **research / pre-release** software. It is a
> solo-maintained project with no external audit yet. Contracts are deployed
> to Base Sepolia (testnet) only. Please do not anchor production trust
> decisions to it in its current state.

## Supported versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| `main` branch | ✅ | The only supported line — fixes land here first |
| Tagged pre-releases (if any) | ⚠️ Best effort | Upgrade to `main` for security fixes |
| No stable/production release exists | — | No mainnet deployment; no LTS promises |

## Reporting a vulnerability

**Preferred — GitHub private vulnerability reporting:** go to the
repository's **Security tab → "Report a vulnerability"**
(<https://github.com/humoge7502/q-trust/security>). This keeps the report
confidential end-to-end and lets us coordinate disclosure and CVE assignment
in one place.

<!-- TODO(owner): confirm private vulnerability reporting is ENABLED in
     repo Settings → Code security and analysis, and optionally publish a
     security@ contact / PGP key at /.well-known/security.txt. Until then,
     GitHub private reporting is the only supported channel. -->

Please **do not open public GitHub issues, PRs, or discussions** for
suspected vulnerabilities.

### What to include

- Affected component and the exact commit (`contracts/`, `backend/`,
  `frontend/`, `sdk/`, `inspector/`, `planner/`, CI workflows)
- A minimal reproduction: PoC, transaction calldata, HTTP request, or test case
- Impact assessment and exploitation prerequisites
- Whether you wish to be credited publicly

## Scope

**In scope:** `contracts/` (incl. upgrade/timelock mechanics and deployment
scripts), `backend/` (API, relayer, indexer, webhook delivery), `sdk/`
(incl. DID resolution and VC verification — e.g. SSRF in `DIDResolver`,
signature-validation bypasses), `inspector/` (CLI and analysis engine),
`planner/`, `frontend/`, and the GitHub Actions workflows.

**Out of scope:** third-party dependency bugs without a demonstrable exploit
path in Q-Trust code (report upstream — we track advisories via Dependabot);
volumetric DoS; missing best-practice flags without concrete impact;
self-XSS; social engineering; test-only mocks and fixtures; issues in
unsupported versions.

## Response targets (SLM — service level commitment, not SLA)

- **Acknowledgment target: 72 hours** (a maintainer confirms receipt and
  begins triage).
- Fix timelines are severity-dependent and set after triage — this is a
  solo-maintained research project, so treat these as targets, not
  contractual commitments. We will tell you honestly if a fix will take
  weeks (e.g. contract changes needing timelock execution).

## Disclosure & safe harbor

- Reports are handled under **coordinated disclosure**; details stay private
  until a fix ships.
- After a patch, we publish a GitHub Security Advisory with affected
  versions, remediation guidance, and reporter credit (unless you prefer
  anonymity).
- Default embargo: **90 days**, extendable by mutual agreement — contract
  upgrades legitimately need the 7-day timelock plus scheduling.
- **Safe harbor:** good-faith research that respects user data, avoids
  service degradation, and stays out of scope boundaries will not be pursued
  legally.

## Security controls (for context)

Continuous scanning runs on every push/PR and daily: Slither (fail on HIGH),
Semgrep, and CodeQL (`.github/workflows/security.yml`) plus PQC-readiness
scans (`pqc-scan.yml`). Contracts route all admin mutations through the
7-day timelock governor (ADR-0003) with role separation; EIP-712 relayed
writes use per-signer nonces; evidence chains are SHA-256 hash-chained; VC
verification fails closed.
