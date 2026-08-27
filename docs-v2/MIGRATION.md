---
title: Migration Runbook (mkdocs → VitePress)
outline: [2, 3]
---

# Migration Runbook — mkdocs-material → VitePress (docs-v2)

This directory (`docs-v2/`) is a **staged next-generation docs site**. It
does not affect production until you follow §4. The current production site
remains the mkdocs-material build deployed by
`.github/workflows/docs.yml` at <https://humoge7502.github.io/q-trust>.

## 1. Current state

| Item | Value |
| --- | --- |
| Production site | mkdocs-material, built from `mkdocs.yml` + `docs/` |
| Workflow | `.github/workflows/docs.yml` → `pip install mkdocs mkdocs-material` → `mkdocs build --site-dir site` → upload `site/` → `actions/deploy-pages` |
| Triggers | push to `main` touching `docs/**`, `mkdocs.yml`, or the workflow itself |

docs-v2 adds: native Mermaid rendering, local search, per-section sidebars,
last-updated stamps, and the brand theme — none of which mkdocs-material
provides in the current setup.

## 2. Trial locally

```bash
cd docs-v2
npm install
npm run docs:dev       # http://localhost:5173/q-trust/
```

## 3. Build check (do this before any workflow edit)

```bash
npm run docs:build     # static site → docs-v2/.vitepress/dist
npm run docs:preview   # serve the production build locally
```

The build must finish with 0 errors (dead links are errors in VitePress) —
this is the acceptance gate for the switch.

## 4. Switching production

Edit `.github/workflows/docs.yml` — the deploy job stays identical, only the
build job changes:

```yaml
# BEFORE (mkdocs)
- uses: actions/setup-python@…  # keep only if other steps need it
- run: pip install mkdocs mkdocs-material
- run: mkdocs build --site-dir site
- uses: actions/upload-pages-artifact@…
  with:
    path: site

# AFTER (VitePress)
- uses: actions/setup-node@…          # pin like other workflows in this repo
  with:
    node-version: "20"
    cache: npm
    cache-dependency-path: docs-v2/package-lock.json
- run: npm ci
  working-directory: docs-v2
- run: npx vitepress build
  working-directory: docs-v2
- uses: actions/upload-pages-artifact@…
  with:
    path: docs-v2/.vitepress/dist
```

Also add `docs-v2/**` to the workflow's `paths:` trigger list. Keep
`actions/deploy-pages` exactly as-is (the `deploy` job and the `pages`
concurrency group need no changes).

::: warning
Do not delete `mkdocs.yml` or `docs/` during the switch — they are the
rollback path until §5 is complete.
:::

## 5. Content parity (what still needs porting)

docs-v2 currently covers the entry surface (guide, architecture overview,
security model, both PyPI packages). The following mkdocs pages are **not yet
ported** — keep mkdocs live (or keep the old URLs redirecting) until the ones
you care about are moved over:

| mkdocs page | Status in docs-v2 |
| --- | --- |
| `docs/ARCHITECTURE.md` | summarized in [Architecture](/architecture/overview) — full page not ported |
| `docs/WHITEPAPER.md` | not ported |
| `docs/GPU_FEATURES.md` | not ported |
| `docs/PERFORMANCE.md` (147.8 req/s @ 100 VUs, p95 = 11.3 ms) | not ported |
| `docs/deployment/BASE_SEPOLIA.md`, `MULTI_CHAIN.md`, `GO_LIVE_CHECKLIST.md` | not ported |
| `docs/case-studies/CASE_STUDY_EXAMPLE_COM.md` | not ported |
| `docs/adr/0000`–`0006` (7 ADRs) | referenced/summarized only |
| `docs/runbook/backup-restore.md`, `incident-response.md` | not ported |
| `docs/PATENT/*` (invention disclosure, draft claims, prior-art survey) | **recommend NOT porting** — these are currently exposed in the public mkdocs nav; internal invention disclosures usually should not be published (see prior repo audits) |

<!-- TODO(owner): decide the fate of docs/PATENT/* in the public nav before
     migrating; also decide whether the 8 PHASE_*.md build logs should ever
     be public (they are currently excluded from mkdocs via exclude_docs). -->

## 6. Rollback

Revert the workflow edit (`git revert <commit>`). The next push to `main`
rebuilds and redeploys mkdocs from `mkdocs.yml` + `docs/` — docs-v2 remains
harmless in the tree until you retry.
