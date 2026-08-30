# Support

## Getting Help

Thank you for using Q-Trust — the post-quantum trust infrastructure platform
(Solidity contracts, Node.js backend, Python SDK, inspector, planner, and Next.js frontend).

### Documentation

* **Docs site:** https://humoge7502.github.io/q-trust (Material for MkDocs, `mkdocs.yml`)
* **Architecture:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
* **Whitepaper:** [docs/WHITEPAPER.md](docs/WHITEPAPER.md)
* **API reference:** `backend/openapi.yaml` — live Swagger at `GET /docs` (`/docs/json`)
* **On-chain deployment:** [docs/deployment/BASE_SEPOLIA.md](docs/deployment/BASE_SEPOLIA.md)
* **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

### Community Support

* **GitHub Discussions:** https://github.com/humoge7502/q-trust/discussions — questions, ideas, show-and-tell
* **GitHub Issues:** https://github.com/humoge7502/q-trust/issues — bug reports and feature requests
  * Use the provided issue templates (Bug report / Feature request). Security issues must **not** be filed publicly — see below.
* **Changelog:** [CHANGELOG.md](CHANGELOG.md)

### Operational Runbooks

* **Backup & Restore:** [docs/runbook/backup-restore.md](docs/runbook/backup-restore.md)
* **Incident Response:** [docs/runbook/incident-response.md](docs/runbook/incident-response.md)
* **Go-Live Checklist:** [docs/deployment/GO_LIVE_CHECKLIST.md](docs/deployment/GO_LIVE_CHECKLIST.md)

## Security Issues — Private Disclosure Only

**Do not open public GitHub issues for suspected vulnerabilities.**

Please report privately via one of:

* **Preferred:** [GitHub Security Advisories](https://github.com/humoge7502/q-trust/security/advisories/new) — confidential end-to-end, with coordinated disclosure and CVE assignment
* **Alternative:** Email `humoge7502.security@gmail.com` (mention "Q-Trust security" in the subject; GitHub Security Advisories remain preferred)

Include: affected component and version/commit (`contracts/`, `backend/`, `sdk/`, `inspector/`, `planner/`, `frontend`), minimal reproduction (PoC, calldata, HTTP request, or test case), impact assessment, and whether you wish to be credited.

See [SECURITY.md](SECURITY.md) for supported versions, response SLAs (Critical 48h triage / 7d fix, High 72h / 14d), scope, and disclosure policy. Safe-harbor applies to good-faith research that respects user data and avoids service degradation.

## Version Support

| Version | Supported | Notes |
|---------|-----------|-------|
| 2.0.x | ✅ | Current release line; receives fixes |
| 1.1.x | ✅ | Security fixes only until 2027-01-31 |
| < 1.1 | ❌ | Pre-GA; upgrade to a supported release |

Derived from [SECURITY.md](SECURITY.md) — that file is authoritative for security support.

## Commercial / Enterprise Support

For deployment assistance, Base mainnet migration, or SLA-backed support, contact the maintainers via GitHub Discussions or the emails listed in `pyproject.toml` / [.github/CODEOWNERS](.github/CODEOWNERS).
