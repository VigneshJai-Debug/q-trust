# Contributing to Q-Trust

Thank you for your interest in contributing to Q-Trust — the protocol that
helps organizations coordinate the migration from classical to post-quantum
cryptography. Every contribution counts: code, documentation, bug reports,
benchmark results, and feature ideas.

> **Status:** research / pre-release, solo-maintained. Reviews may take a few
> days — please be patient, and keep PRs small and focused.

## Getting started

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/<your-username>/q-trust.git
cd q-trust
git remote add upstream https://github.com/humoge7502/q-trust.git
cp .env.example .env   # fill in what your subsystem needs
```

### Prerequisites

- Node.js 20+ (backend, frontend, docs)
- Python 3.10+ (inspector, SDK, planner) — 3.11 in CI
- [Foundry](https://getfoundry.sh) (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- Docker (integration stack via `docker-compose.yml`)

## Monorepo map

| Directory | What it is | Build/test tooling |
| --- | --- | --- |
| `contracts/` | 11 UUPS registries + timelock governance on Base L2 | Foundry (`forge`) |
| `backend/` | Fastify 5 verification API, EIP-712 relayer, viem indexer | npm, TypeScript, vitest |
| `frontend/` | Next.js dashboard & public verify pages | npm, vitest, Playwright |
| `inspector/` | `crypto-inspector` PQC scanner CLI (CycloneDX 1.7, SARIF) | pip, pytest |
| `sdk/` | `qtrust-sdk` — on-chain client, trust/VC/DID engines | pip, pytest, ruff, mypy |
| `planner/` | FastAPI + PyTorch Geometric migration planner | pip, pytest |
| `docs/` + `mkdocs.yml` | current docs site | mkdocs-material |
| `docs-v2/` | staged VitePress next-gen docs | npm, VitePress |

## Development environment per subsystem

Use the same commands CI uses (`.github/workflows/ci.yml`):

```bash
# Contracts (Solidity 0.8.24)
cd contracts && forge build && forge test -vvv

# Backend (Fastify 5)
cd backend && npm ci && npm run typecheck && npm run build && npm run test

# Frontend (Next.js)
cd frontend && npm ci && npm run build && npm test          # vitest
cd frontend && npm run test:e2e                             # Playwright

# Inspector
pip install -e "./inspector[dev,ml]" && pytest inspector/tests/ -v

# SDK
pip install -e "./sdk[dev]" && pytest sdk/tests/ -v && ruff check sdk/

# Planner (CPU torch is fine for tests)
pip install -r planner/requirements.txt
QTRUST_PLANNER_DEVICE=cpu pytest planner/tests/ -v

# Whole-repo smoke check
./scripts/verify_all.sh
```

The Docker Compose profile starts the full backend stack (API, webhooks,
Postgres, Redis, planner, Prometheus, Alertmanager, Grafana):
`cp .env.example .env && docker compose up -d`.

## Workflow: branches, commits, PRs

- **Branch naming:** `feat/<short-slug>`, `fix/<short-slug>`,
  `docs/<short-slug>`, `chore/<short-slug>` — branched from `main`.
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `chore:`, `perf:` — e.g. `fix(inspector): dedupe AST+regex findings`.
- **PRs:** target `main`, fill in
  [`.github/PULL_REQUEST_TEMPLATE.md`](https://github.com/humoge7502/q-trust/blob/main/.github/PULL_REQUEST_TEMPLATE.md)
  (summary, changes, testing checklist, security considerations, breaking
  changes), and link issues with `Closes #N` / `Refs #N`.

## Testing expectations

Every PR is expected to keep the suite green for the subsystems it touches,
and to **add tests for new behavior**:

| Subsystem | Expectation |
| --- | --- |
| Contracts | `forge test -vvv` passes; invariant suite runs under `fail_on_revert=true` (runs=1000, depth=100); new registry functions need invariant + fuzz coverage |
| Backend | `vitest run` + `npm run typecheck` pass; new endpoints get TypeBox-validated schemas + tests |
| Frontend | `vitest run` passes; user-visible components get component tests; flows that touch wallet/API get Playwright coverage |
| Inspector / SDK / Planner | `pytest` passes; bug fixes should include a regression test; SDK ships Hypothesis property tests (CI runs a 1000-example profile) |

## Measured-claims policy

Numbers in docs, README, and marketing material must be **reproducible from
the repo**: cite the benchmark/artifact that produced them (e.g. "147.8
req/s @ 100 VUs, p95 = 11.3 ms" → `docs/PERFORMANCE.md` + k6 scripts in
`ops/loadtest/`; "189 contract tests" → `forge test` under the strict
invariant config; "Kendall τ 0.961" → `planner/results/benchmark_v3.json`).
If you can't cite it, don't claim it — and if a claim becomes stale, fix the
claim, not the reader's expectations.

## Code style

- **Solidity** — 0.8.24, OpenZeppelin conventions, NatSpec on all
  public/external functions, `Initializable`/`UUPSUpgradeable`/
  `AccessControlUpgradeable` where appropriate, no hardcoded addresses.
- **Python** — `ruff` (`ruff check .`), type hints everywhere, Pydantic
  models for data structures, Google-style docstrings.
- **TypeScript** — strict mode, ESLint with the project config, prefer
  `readonly` and `interface` for object shapes.

## Security

- **Never commit secrets, private keys, or API tokens** — use environment
  variables (`.env.example` documents them).
- **All admin operations go through timelock governance. No bypasses.**
- Report vulnerabilities via GitHub private vulnerability reporting
  (Security tab → *Report a vulnerability*) — see [SECURITY.md](SECURITY.md).
  Never open public issues for security bugs.
- Run `npm audit` and `pip audit` before submitting security-sensitive
  changes (CI already does `npm audit --audit-level=high`).

## Updating docs

If your change alters user-visible behavior — CLI flags, API endpoints, env
vars, contract events — update the docs in the same PR: `docs/` (current
site), plus `docs-v2/` pages and `sdk/README.md` / CLI `--help` text where
relevant. Mermaid diagrams in docs must stay ≤12 nodes and match the code.

## Architecture decisions

Significant design changes should land as an ADR in `docs/adr/` (see
ADR-0000 for the format). Existing decisions worth reading before proposing
changes: Base L2 selection (0001), EIP-712 gasless relay for all writes
(0002), UUPS + 7-day timelock (0003), Postgres read model with RPC fallback
(0004), in-house Python VC/DID (0005), deterministic content-addressed IDs
(0006).
