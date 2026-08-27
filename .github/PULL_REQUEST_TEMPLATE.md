<!-- Pull request template for humoge7502/q-trust.
     Filled-in PRs make review faster and feed the Release Drafter label
     taxonomy (see .github/release-drafter.yml) — please label this PR with
     one of: feat / fix / security / perf / docs / chore / deps (+ major /
     minor for version bumps, or skip-changelog to keep it out of the notes). -->

## Summary

<!-- One or two sentences: what does this PR do, and why? Link issues with
     "Closes #N" / "Fixes #N" so they close on merge. -->

## Type of change

<!-- Check exactly one primary type. This should mirror the PR label used
     for the release notes. -->

- [ ] Bug fix (`fix`) — non-breaking change that resolves a defect
- [ ] New feature (`feat`) — non-breaking change that adds capability
- [ ] Security hardening (`security`) — fixes or mitigates a security concern
      (If this PR fixes a reported vulnerability, reference the advisory —
      do not include exploit details here.)
- [ ] Performance improvement (`perf`) — measured speed/memory/latency win
- [ ] Documentation (`docs`) — docs/, mkdocs, or inline doc changes only
- [ ] Maintenance (`chore` / `deps`) — tooling, CI, refactors, dependency bumps
- [ ] **Breaking change** — API, ABI, env var, on-chain schema, or storage
      layout change that requires migration (also apply the `major` label)

## Affected subsystems

<!-- Check every subsystem this PR touches. Reviewers use this to route. -->

- [ ] `contracts/` — Solidity (Foundry)
- [ ] `backend/` — Fastify 5 API, relayer, indexer
- [ ] `frontend/` — Next.js dashboard
- [ ] `inspector/` — qtrust-inspector (Python)
- [ ] `sdk/` — qtrust-sdk (Python)
- [ ] `planner/` — GNN + RL planner (Python)
- [ ] `docs/` — mkdocs site
- [ ] `infra` — CI workflows, Docker, ops/, deployment config

## Testing

<!-- Run the suites for every subsystem you touched (commands verified
     against CONTRIBUTING.md and the CI workflow). Full-stack check:
     `./scripts/verify_all.sh` from the repo root. -->

- [ ] Contracts: `cd contracts && forge test` passes
      (CI also runs `forge build --sizes` and coverage)
- [ ] Backend: `cd backend && npm test` (vitest) — plus `npm run typecheck` and `npm run build`
- [ ] Frontend: `cd frontend && npm test` (vitest) — plus `npm run build`;
      E2E if UI changed: `npm run test:e2e` (Playwright)
- [ ] Inspector: `cd inspector && pytest`
- [ ] SDK: `cd sdk && pytest` (property tests: `pytest sdk/tests/test_properties.py -v`)
- [ ] Planner: `cd planner && pytest` (CPU: `QTRUST_PLANNER_DEVICE=cpu pytest`)
- [ ] New/changed behavior is covered by tests (no snapshot-only "coverage")

## Documentation & claims

- [ ] Docs updated for user-visible changes (`docs/`, README, docstrings) — or N/A with a one-line reason
- [ ] Any measured claims (latency, throughput, τ, gas) cite their source:
      benchmark script/JSON, CI run, or notebook — no unsourced numbers
      (Q-Trust's credibility rests on reproducible measurements)

## Security

- [ ] No secrets, private keys, or API tokens committed (CI runs gitleaks +
      dev-key-guard; dev keys belong in tests only)
- [ ] Auth, key handling, on-chain access control, rate limiting, input
      validation, and data exposure considered — impact described below or "None"

<!-- Security impact: -->

## Breaking changes & migration

<!-- If none, write "None". Otherwise describe the migration path: env vars,
     API consumers, SDK users, contract upgrade/timelock steps. -->
