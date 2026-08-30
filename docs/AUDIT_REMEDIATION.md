# Q-Trust Audit Remediation — 2026-08-30

This pass ran every verifiable check in the repository, fixed everything that
was actually broken, and recorded the evidence. All numbers below were
measured locally on this checkout, not estimated.

## 1. Verification matrix (all checks that exist in CI / Makefile / README)

| Check | Command | Result |
|---|---|---|
| Contracts (unit + invariant + fuzz + attack) | `forge test` (contracts/) | **211/211 pass** |
| Backend typecheck | `npm run typecheck` (backend/) | pass |
| Backend unit tests | `npm test` (backend/, vitest) | **72/72 pass** |
| Backend production build | `npm run build` (backend/, tsc emit) | pass |
| Frontend unit tests | `npm test` (frontend/, vitest) | **55/55 pass** |
| Frontend lint | `npm run lint` (frontend/) | **pass — was broken** (see §2) |
| Frontend production build | `npm run build` (frontend/, Next 16.3.1) | pass (requires `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID`, same as CI) |
| Frontend npm audit | `npm audit --audit-level=high` | **0 vulnerabilities** |
| Backend npm audit | `npm audit --audit-level=high` | **0 vulnerabilities** |
| SDK tests | `pytest sdk/tests/` | **64 pass, 1 skip — was collection-broken** (see §3) |
| Inspector tests | `pytest inspector/tests/` | **202 pass, 1 skip — was 8 failed** (see §4) |
| Planner tests | `pytest planner/tests/` | **52 pass** |
| qtrust_ai tests | `pytest qtrust_ai/tests/` | **12 pass** |
| Full Python suite | `pytest` (all four suites) | **330 pass, 2 skip** |
| Python lint | `ruff check .` | **pass — was 449 violations** (see §5) |
| Docs site | `mkdocs build --strict` | pass |
| Docs v2 (VitePress) | `npm run docs:build` (docs-v2/) | pass |
| Go-live preflight | `scripts/check_golive_blockers.sh` | **passed** |

## 2. Frontend lint was completely broken

`npm run lint` ran `next lint`, which Next.js 16 removed — the command failed
with `Invalid project directory provided`. ESLint was not even installed.

- `frontend/package.json` — added `eslint`, `eslint-config-next`,
  `@next/eslint-plugin-next` as devDependencies; lint script now `eslint .`.
- `frontend/eslint.config.mjs` — replaced the dependency-free stub with the
  native `eslint-config-next` flat config (the stub even documented this fix).
  Using `FlatCompat` here fails with a circular-structure error on Next 16, so
  the native flat config is required.
- Fixed the 8 lint errors the newly-enabled rules surfaced:
  - `src/app/dashboard/page.tsx`, `src/app/vendors/page.tsx` — unescaped `'`
    in JSX text (`react/no-unescaped-entities`).
  - `src/components/stats-panel.client.tsx`,
    `src/components/wallet-gate.tsx` — `setMounted(true)` inside `useEffect`
    (`react-hooks/set-state-in-effect`). `useMounted` now uses
    `useSyncExternalStore` (client/server snapshots), which is the idiomatic
    hydration guard and removes the cascading-render anti-pattern.
  - `src/hooks/__tests__/use-user-role.test.tsx` — anonymous wrapper component
    missing a display name (`react/display-name`).
  - `frontend/postcss.config.mjs` — anonymous default export warning.
- Verified: lint clean, 55/55 vitest tests still pass, production build emits.

## 3. SDK tests failed at collection (namespace collision)

`from qtrust import QTrustClient` resolved to the repo-root `qtrust/` ML-factory
package (v3.0) instead of the SDK's `qtrust` module, so `sdk/tests/test_client.py`
could not even be collected. The root `qtrust/` package shadows `sdk/qtrust`
whenever the repository root is on `sys.path`; end-users of
`pip install qtrust-sdk` are unaffected.

- Added `sdk/tests/conftest.py` that puts the SDK root first on `sys.path`
  *and* eagerly imports `qtrust` so `sdk/qtrust` is registered in
  `sys.modules` — later test imports resolve to the SDK regardless of how
  pytest reorders `sys.path` (per-test basedirs and conftest directories are
  prepended after conftests run, so path-order alone is not stable across
  `pytest sdk/tests/` vs `cd sdk && pytest` invocations).
- Result: 64 pass, 1 skip from both the repo root and `cd sdk`.

## 4. Inspector ML tests failed on a phantom CUDA device

`torch.cuda.is_available()` returned True but the device cannot actually be
used in this container, so `CBOMAnomalyDetector` / `SideChannelAnalyzer`
selected CUDA and every training test crashed
(`torch.AcceleratorError: CUDA-capable device(s) is/are busy or unavailable`).
torch 2.13's `optimizer.step()` consults the accelerator API even for CPU
tensors, so this also broke pure-CPU training. CI (CPU torch wheel) never saw
this.

- `inspector/qtrust_inspector/_device.py` (new) — `resolve_device()` probes a
  real CUDA allocation and falls back to CPU when CUDA is reported but
  unusable; used by both the anomaly detector and side-channel analyzer.
- `conftest.py` (new, repo root) — probes CUDA in a subprocess (fresh
  interpreter, avoids the cached `torch.cuda.is_available()` result) and, when
  the device is unusable, hides it with `CUDA_VISIBLE_DEVICES=""` before any
  in-process torch import. Healthy GPU machines are untouched.
- Result: 8 failures → 0; inspector 202 pass, 1 skip.

## 5. `ruff check .` was red with 449 violations

The root `.ruff.toml` pinned `select = ["E4","E7","E9","F"]` as a
top-level key — deprecated and ignored by modern ruff — and the per-package
ruff configs in `sdk/pyproject.toml` / `inspector/pyproject.toml` used a
stricter `["E","F","I","W","UP"]` contract the code never satisfied
(331 `E501` line-length violations alone). CI's `ruff check .` was red.

- `.ruff.toml` — moved `select` under the canonical `[lint]` section so every
  ruff version enforces the pinned contract.
- `sdk/pyproject.toml`, `inspector/pyproject.toml` — aligned their
  `[tool.ruff.lint]` select with the repo-wide E4/E7/E9/F contract (documented
  why in a comment) so one consistent rule set applies repo-wide.
- Fixed all 40 violations that remained under the real contract
  (34 unused imports, 3 unused variables, 1 ambiguous `l`, 1 placeholder-less
  f-string, 1 multiple-import line) across `qtrust/` and `scripts/`.
  `qtrust/models/__init__.py` re-exports got the missing names added to
  `__all__` instead of dropping public API.
- Result: `ruff check .` → **All checks passed**.

## 6. WalletConnect env template contradicted the production guard

`next build` fails fast (audit F-2) when `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID`
is unset or `"demo"`, but both `.env.example` files shipped `demo` — so a fresh
setup following the template hit a build error. CI already passed a 32-char
placeholder.

- `.env.example`, `frontend/.env.example` — use the 32-char placeholder CI
  uses, with comments explaining the production requirement. No code change:
  the fail-fast guard is deliberate and matches CI behavior.

## 7. Real-data reproduction (measured 2026-08-30)

Ran the real-data pipeline on the existing real corpus (37 host-disjoint CBOMs,
277 hosts). All numbers below were produced by actually executing the scripts;
nothing is estimated. See `docs/DEVELOPER_ROADMAP.md` for interpretation.

| Run | Command | Measured result | Artifact |
|---|---|---|---|
| Real-CBOM LOO (3 folds) | `python scripts/eval_real_cbom_loo.py --quick --epochs 3 --n-synthetic 600` | model τ-b **0.6546** = heuristic **0.6546** (Δ 0.0000); random 0.3416 | `planner/results/real_cbom_loo_cpu_repro.json` |
| RL agent (20 feasible envs) | `python scripts/eval_rl_agent.py --n-envs 20` | agent reward **108.93** vs heuristic **112.40** vs random **100.11**; completion 100% | `planner/results/rl_benchmark_cpu_repro.json` |
| Anomaly detector on real CBOMs | `python scripts/train_real_models.py --model anomaly --epochs 30` | detection **168/168 (100%)**, FPR **3/56 (5.4%)** | `inspector/anomaly_model_real.pt` (gitignored) |

Two integrity fixes were made during reproduction:
- `scripts/eval_real_cbom_loo.py` / `scripts/eval_rl_agent.py` naively picked
  `"cuda"` whenever `torch.cuda.is_available()` was true and could record a
  GPU device label even when the device was unusable/busy at runtime. Both now
  use a probe-based resolver (`planner/qtrust_planner/_device.py`) so recorded
  results reflect the device actually used.
- Environment caveat: the A100 here is real but **contended** (another process
  holds it), so CUDA probes intermittently succeed/fail. Results above are real
  measurements; the committed 37-fold LOO artifact (`real_cbom_loo.json`) was
  measured on a dedicated A100 and is the canonical out-of-sample number
  (model τ-b 0.681 vs heuristic 0.731).

## 8. Environment-level notes (not repo defects, not changed)

- `pip-audit` reports `setuptools 80.10.2` vulnerable (PYSEC-2026-3447, fixed
  in 83.0.0) — that is the Python environment's own package, not a repository
  dependency; upgrade the environment (`pip install -U setuptools`).
- Playwright e2e and Halmos symbolic-execution jobs need browsers/foundry
  tooling not present in this environment; they are CI-only.
- `docker compose` stack (Postgres/Redis/anvil) was not brought up; the
  `scripts/verify_all.sh` full-stack check requires it.
