# Security Policy

Q-Trust is a post-quantum trust infrastructure platform: Solidity contracts, a Node.js backend, a Python SDK, a cryptography inspector, a planner, and a web frontend. We take the security of this stack — and of the systems that depend on it — seriously.

## Supported Versions

| Version | Supported          | Notes                                          |
|---------|--------------------|------------------------------------------------|
| 1.1.x   | :white_check_mark: | Current release line; receives fixes           |
| 1.0.x   | :white_check_mark: | Security fixes only until 2027-01-31           |
| < 1.0   | :x:                | Pre-GA; upgrade to a supported release         |

## Reporting a Vulnerability

**Preferred:** Open a private report via [GitHub Security Advisories](https://github.com/security/advisories/new) on this repository. This keeps the report confidential end-to-end and lets us coordinate disclosure and CVE assignment in one place.

**Alternative:** Email `security@q-trust.example` (placeholder — replace with your operational mailbox before production). Encrypt sensitive reports with our PGP key published at `/.well-known/security.txt`.

Please include:

- Affected component and version/commit (`contracts/`, `backend/`, `sdk/`, `inspector/`, `planner/`, `frontend/`)
- A minimal reproduction (PoC, transaction calldata, HTTP request, or test case)
- Impact assessment and any exploitation prerequisites
- Whether you wish to be credited

Do **not** open public GitHub issues for suspected vulnerabilities.

## Response SLAs

| Severity | Triage acknowledgment | Fix target            |
|----------|----------------------|-----------------------|
| Critical | 48 hours             | 7 days                |
| High     | 72 hours             | 14 days               |
| Medium   | 5 business days      | Next minor release    |
| Low      | 10 business days     | Best effort / next release |

Triage means a maintainer has reproduced or credibly assessed the issue and replied with severity and a plan. Severity follows CVSS v3.1, adjusted for exploitability against deployed contract state.

## Disclosure Policy

- Reports are handled under coordinated disclosure. We will not publish or discuss details publicly before a fix ships.
- Once a patch is released, we publish a GitHub Security Advisory with affected versions, remediation guidance, and credit to the reporter (unless anonymity is requested).
- Embargo default is 90 days from initial report; we may request extensions for complex migrations (e.g., contract upgrades requiring timelock execution).
- Safe-harbor: good-faith research that respects user data and avoids service degradation will not be pursued legally.

## Scope

In scope:

- `contracts/` — Solidity contracts, deployment scripts, upgrade/timelock mechanics
- `backend/` — Node.js API server, webhook handling, indexer
- `sdk/` — Python SDK (`qtrust`), DID/VC verification logic
- `inspector/` — PQC scanner CLI and analysis engine
- `planner/` — migration planning services
- `frontend/` — web application served to users

Out of scope:

- Vulnerabilities in third-party dependencies without a demonstrable exploit path in Q-Trust code (report upstream; we track advisories continuously)
- Denial of service via volumetric network flooding of public infrastructure
- Missing security headers or best-practice hardening flags without concrete impact (e.g., CSP reports)
- Self-XSS and attacks requiring an attacker-controlled browser/device of the victim
- Social engineering, phishing, or physical attacks against team members or hosting providers
- Issues affecting only unsupported versions (< 1.0) or clearly marked experimental branches
- Test-only contracts, mocks, and fixtures never intended for mainnet deployment

## Security Controls (Reference)

- Continuous scanning: Slither, Semgrep, CodeQL, pip-audit (`.github/workflows/security.yml`) and PQC readiness scans (`pqc-scan.yml`)
- Contract changes route through timelock governance with an operational role separate from deployer privileges
- Evidence chains use SHA-256 integrity hashing; VC verification fails closed on verification errors
- Webhook secrets are redacted from logs; outbound requests apply SSRF protections including DNS pinning
