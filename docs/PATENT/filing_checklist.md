# Filing Checklist — Q-Trust Patent

> Action plan to get from "demo project" to a filed patent application. Not legal advice;
> work with qualified patent counsel.

## Phase A — Before anything is made public (do this first)

- [ ] **Disclosure audit**: confirm whether the repo, README, demos, talks, thesis
  drafts, or GitHub releases have been publicly accessible. Every public disclosure
  starts the clock:
  - US: 12-month grace period from first public disclosure (AIA §102(b)(1)).
  - Most other jurisdictions (EPO, CN, IN, JP): **no grace** — any public disclosure
    before filing destroys novelty.
  - If anything was public, tell counsel immediately; the US grace may still apply.
- [ ] **Ownership check**: if inventor is a student/employee, confirm university or
  employer IP policy (many universities own student inventions made with university
  resources). Get a written invention assignment signed.
- [ ] **Freeze disclosure**: do not push the repo public, publish the paper, or demo
  externally until the provisional is filed (or counsel confirms grace).
- [ ] **Inventorship list**: document all contributors and their contributions
  (lab notebooks, git logs, design docs). Inventorship errors can invalidate a patent.
- [ ] **Prior art package** to counsel: `docs/PATENT/prior_art_survey.md` + the closest
  references cited therein (CARAF, QSTriage, WO2018004783A1, US20170317833A1,
  VulRG, arXiv:2403.04989, VIVID).

## Phase B — Prepare the filing

- [ ] **Provisional (recommended first step, US)**:
  - Cost-effective (~$1–3k total with an attorney, or self-filed via USPTO
    `patentscope`/EFS-Web for $65–260 micro-entity).
  - Locks the filing date; gives 12 months to refine claims.
  - Contents: specification (invention disclosure + this doc set), drawings
    (architecture/data-flow diagrams — to be produced), claims (draft_claims.md).
  - **Must enable**: a person skilled in the art must be able to reproduce the
    invention from the spec. The codebase itself can be referenced as an appendix
    (counsel will advise on depositing source code as a CD-ROM appendix).
- [ ] **Figures**: produce 2–4 figures — (1) system architecture, (2) GNN architecture
  with dual heads, (3) registry data-flow/sequence diagram, (4) claim-mapping table.
- [ ] **Non-provisional (within 12 months of provisional)**: attorney drafts formal
  claims after a full search; pay filing fees; respond to office actions.
- [ ] **International (PCT)**: if global protection desired, file PCT within 12 months
  of the provisional priority date (or 12 months of first filing).

## Phase C — Support evidence to gather for the filing (updated 2026-08-21, all verified)

- [x] Benchmark results: `planner/results/benchmark.json` — **honest 3-seed 40-epoch 1000-graph 150-held-out benchmark (2026-08-21)**: `gnn-listmle` τ 0.266±0.023 top-5 0.500±0.061 (`gnn-mse` τ 0.144, `random` −0.009, `heuristic` τ 0.997). **Production `planner/model.pt` (80 epochs, 1200 graphs, ListMLE): τ 0.388 top-5 0.656 top-10 0.528 node 0.437** (single-seed validation). Fixed benchmark bug (`ckpt` ordering) and retrained.
- [x] E2E verification transcript: `bash sdk/tests/run_e2e.sh` → **ALL E2E CHECKS PASSED** (7 steps incl. timelock governance handling, EIP-712 gasless, integrity guards) on fresh anvil chain-id 84532.
- [x] Pilot transcript: `bash /tmp/run_pilot_e2e.sh` → **PILOT COMPLETE** (6 steps, 1 TLS asset from example.com, CBOM hash 0xfa2e…, GNN τ 0.388, migration ML-DSA-441, audit Passed) — see `pilot/run_pilot.py`.
- [x] Contract tests: `forge test` → **49/49 (5 suites)** — AssetRegistry 10, VendorRegistry 14, MigrationRegistry 11, AuditRegistry 8, QTrustGovernance 6; `forge build` clean.
- [x] Backend build: `npm run build` tsc clean; 8 `/v1` routes + health, webhook BullMQ, indexer, EIP-712 relayer.
- [x] Frontend build: `next build` clean (5 routes), verification page `/v/[id]` renders VALID.
- [x] Full-stack: `./scripts/verify_all.sh` → **ALL CHECKS PASSED** (9/9).
- [ ] Verification page screenshot (frontend `/v/<asset-id>` → VALID) — to capture after `docker compose up`.

## Phase D — Parallel: paper vs patent strategy

- [ ] Decide order: **file provisional → then publish/submit paper**. Publishing first
  risks losing non-US rights.
- [ ] Paper (if pursued): the current synthetic-data-only evaluation is a
  **workshop/demo paper** candidate, not yet a strong venue paper (see README
  "Known limitations"). Do not overclaim the GNN results in the paper abstract.
- [ ] Add to any paper: comparison against CARAF/QSTriage-style baselines + honest
  limitations section.

## Timeline sketch

| Week | Action |
|---|---|
| 0 | Disclosure audit + ownership check + freeze public exposure |
| 0–2 | Provisional draft: spec + figures + claims (counsel) |
| 2 | File provisional (US) |
| 3 | Optionally submit workshop paper (after filing) |
| 2–14 | Full prior-art search; refine claims |
| 14 | File non-provisional (or PCT if global) |
| Ongoing | Keep lab notebook; document all improvements post-filing |

## Contact items for counsel

- Inventor names/affiliations; employment/funding details.
- Any pre-existing public disclosures (dates, URLs).
- Confirmation of chain-id / L2 specifics if claiming deployment-specific features.
- Whether the GNN ranking loss (ListMLE) is claimed as part of the invention or only
  as an embodiment (recommend: embodiment + fallback language).

---

*This checklist is informational. Engage a registered patent attorney or agent.*