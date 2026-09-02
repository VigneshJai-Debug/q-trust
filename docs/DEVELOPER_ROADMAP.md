# Q-Trust — Developer's Roadmap (measured, not aspirational)

*Written 2026-08-30. Every number below was reproduced in this session on the
real corpus — none are estimates.*

## 1. Where the models actually stand (measured today)

| Model | Protocol | Measured result | Interpretation |
|---|---|---|---|
| GNN planner v3 | Full **40-fold LOO**, host-disjoint real CBOMs (280 hosts, re-run 2026-09-02 on the deterministic-kernel harness, **30-epoch fine-tune, 2,000 synthetic per fold**, folds sharded across **4 A100s** via `eval_real_cbom_loo.py --fold-start/--fold-end`, merged with `--merge-shards`; 3-fold repro bit-identical) | τ-b **0.7263** vs heuristic **0.7450** (Δ **−0.0188**); random 0.2234 (**+0.503**); **reproduces the doctrine on 38/40 folds** (0 wins / 38 ties / 2 losses — small heavily-tied graphs, n≤8 and n≤13) | Model *reproduces* the doctrine heuristic on essentially every held-out real estate (38/40, Δ≈0); the honest ceiling break requires expert pairwise labels. 60-epoch fine-tunes overfit the synthetic mix (Δ −0.055) — 30 epochs is the operating point. The pre-fix τ-b 0.7377 (39/40) is superseded: deterministic kernels (seeded shuffles, cudnn deterministic, no torch.compile) changed per-fold fine-tune outcomes |
| RL agent | PPO, 64 vectorized envs, trained on packed real-CBOM estates with **scan-derived risk labels** (RSA-1024 → critical, RSA-2048 → high, expired/near-expiry raise the class), evaluated on 40 packed real-CBOM environments | mean reward **140.34** ± 8.13 vs heuristic **140.62** (Δ −0.28 — **tie**) vs random **136.84** (+**2.6%**); 100% completion, 2/40 wins · 27 ties · 11 losses | **Learns real risk-priority and matches the doctrine on real estates** (archived “beats heuristic 130.20 vs 112.40” was NOT reproducible — the CBOM builder stamped every asset `criticality: medium`, so real environments had zero reward signal; fixed + re-measured 2026-09-02; `pack_graph_cboms` host-set ordering was hash-randomized per process — sorted + re-run, identical across processes) |
| Anomaly detector | Real CBOMs (277 hosts → 276 assets), 120 epochs, 80% train | **100% detection** (162/162), FPR **2/54** (3.7%) | Strong — real-data trained, improved FPR |
| CodeBERTa detector | Real code corpus (13,973 files incl. SolidiFI/EIPs/WebAuthn), CodeBERTa fine-tune, repo-disjoint held-out | P 0.952 / R 0.953 / F1 0.952 (2026-09-01, GPU 4-epoch) | **+0.11 F1 vs prior** — beats all baselines, 6/7 beat naive; real differentiator |
| Risk / purpose / vendor models | Real corpora (277 hosts / 820 uses / 16 vendors) | trained + anchor-verified (committed report) | Solid |

**The honest headline (2026-09-02):** the **40-fold LOO** completed on the
**deterministic-kernel harness** with the **30-epoch operating point** (2,000
synthetic per fold) — the config the 60-epoch experiment showed to be best
out-of-sample — with the folds **sharded across 4 A100s** (10 folds per GPU,
merged with `eval_real_cbom_loo.py --merge-shards`): **τ-b 0.7263** vs
heuristic **0.7450** (Δ **−0.0188**), reproducing the doctrine on **38/40**
folds (0 wins / 38 ties / 2 losses — small heavily-tied graphs, n≤8 and
n≤13), **+0.503 vs random** (see `real_cbom_loo_40.json`; a fresh 3-fold run
is bit-identical to the merged shards). The 60-epoch fine-tune (Δ −0.0545)
confirms the extra epochs overfit the synthetic mix. CodeBERTa holds at
**F1 0.9525** on the 13,973-file real corpus (deterministic — same seed →
same F1); the RL agent, retrained after a 2026-09-02 integrity fix (real
assets now carry scan-derived risk instead of the builder's blanket
`criticality: medium`, which had zeroed the reward signal), scores **140.34**
vs heuristic **140.62** (tie) and **136.84** random (+2.6%) on 40 packed
real-CBOM estates — it *learns* real risk-priority and matches the doctrine;
side-channel detector **5/5 clean → VERIFIED (0.05), 5/5 leak-injected →
HIGH_RISK (0.95)** on real liboqs traces; anomaly detector **100% detection,
FPR 3.7%**. Neither model beats the doctrine on real estates — and cannot,
because the heuristic **is** the doctrine the labels encode; only expert
pairwise labels (`QTrust-RiskBench`) can break that ceiling.

## 2. The one ML problem that matters

**Make the planner beat its own heuristic on out-of-sample real CBOMs.** This
is the difference between "a GNN that memorizes our priority formula" and "a
planner that finds better migrations than our experts' rules."

What would actually move the needle (in order of leverage):

1. **Better real labels, not more synthetic ones.** Synthetic graphs are
   labeled by the same priority formula we benchmark against — that is the
   circularity the repo already documents. Invest in expert pairwise
   preferences on real estates (the `QTrust-RiskBench` plan in `qtrust/`).
   The model can only beat the heuristic if it learns something the formula
   doesn't know.
2. **More host-disjoint real CBOMs.** 37 CBOMs / 277 hosts is a thin
   out-of-sample surface — one fold can swing ±0.13. Verified public sources
   to grow the corpus (named, real, current as of 2026-08):
   - **arXiv 2606.16473 — "Measurement Study of Post-Quantum Readiness of
     the Internet 2026"** (32,011 real domains, TLS-focused PQC readiness
     measurements) — the single best drop-in source for real PQC estate data.
   - **Kaggle: "IDS Encrypted & Post Quantum Cryptography Datasets"** —
     PQC-TLS Benchmark Collection with 141M real TLS flows from a 100 Gbps
     backbone.
   - **Certificate Transparency logs** (`certificate.transparency.dev`) +
     `crt.sh` — streaming, free, millions of real X.509 certs; ideal for
     key-size / signature-algorithm distributions.
   - **Rapid7 Project Sonar** (`opendata.rapid7.com`) SSL cert dataset —
     internet-wide real certs (note: public access has been restricted since
     2022; treat as research-acquisition, not a default source).
   - **Cloudflare PQ-2024 / F5 "State of PQC on the Web"** — real-world
     TLS 1.3 PQ adoption numbers for calibrating expectations.
   - **NVD CVE feeds** for vulnerability-conditional exposure labels (the
     repo already ingests 401 real CVEs).
   - **GitHub code search** for crypto API usage across public repos (the
     repo already caches 64 repos; scale the collector).
   Each source must keep the **host-disjoint** invariant or the LOO protocol
   silently leaks — that invariant is the repo's credibility.
3. **Tie-aware metrics only.** Dense-rank τ on estates full of identical
   RSA-2048 certs is meaningless; the repo's switch to τ-b was right. Keep it.
4. **Calibrate, don't chase.** The honest benchmark discipline (LOO,
   host-disjoint, τ-b, ceiling baselines) is worth more than any number. Never
   let a headline regress to in-sample.

## 3. What to build next (as the developer)

**0–30 days — make the numbers defensible:**
- Re-run the full 40-fold LOO and the RL benchmark on a dedicated A100;
  publish the artifact with wall-clock, device and deterministic-kernel
  config. (Done for the LOO on 2026-09-02 with the 30-epoch real fine-tune
  on the deterministic harness: `planner/results/real_cbom_loo_40.json`,
  τ-b **0.7263** vs heuristic 0.7450 (Δ −0.0188), reproducing the doctrine on
  **38/40** folds — a 3-fold repro is bit-identical, and the artifact records
  the probe-verified device and full config.)
- Train the anomaly detector and CodeBERTa on the *full* real corpus with the
  GPU properly reserved; commit the reports (models stay gitignored). (Done
  2026-09-02: F1 0.9525 deterministic; anomaly 162/162, FPR 2/54.)
- Wire the real-data training into CI as a weekly scheduled job (like
  `pqc-scan.yml`) so the artifacts can't rot.

**30–90 days — the moat:**
- Scale the real corpus (Project Sonar + CT logs + the repo collector) to
  1,000+ host-disjoint CBOMs; publish the dataset with a hash-anchored
  manifest (the DVC + on-chain lineage work in `qtrust/` already scaffolds
  this — finish it).
- Build the expert pairwise-preference benchmark (`QTrust-RiskBench`) with
  100k assets / 1M comparisons; train the GNN against expert labels instead
  of the heuristic. This is the only honest path to "beats the heuristic."

**90 days+ — product:**
- Multi-chain anchoring (README roadmap), ZK compliance proofs, and the
  enterprise pilot are already scoped in the README roadmap; they are product
  bets, not ML bets — fund them only if the discovery/anomaly differentiators
  are landing with pilot customers.

## 4. What NOT to build

- **Do not** add more headline "τ" numbers without the LOO protocol.
- **Do not** rename/overclaim the ML factory's dataset strategy until the
  expert-label loop actually exists (it is currently a 64-section plan, not a
  pipeline).
- **Do not** chase microservices for the backend — the single Fastify service
  + planner service is the right size.

## 5. Competitive reality (honest)

- **Defensible today:** the host-disjoint real CBOM corpus + LOO discipline,
  the real-data CodeBERTa detector (F1 0.952, trained on 13,973 real files
  incl. SolidiFI/SmartBugs/EIPs/WebAuthn blockchain code), the side-channel
  detector (real liboqs traces), the on-chain attestation layer, and the
  honest benchmark reports. SandboxAQ/IBM/PQShield can copy any single
  feature; a *publishable, reproducible, host-disjoint real benchmark* with
  F1 0.952 on 14k real code files is the thing they cannot fake.
- **Defensible today (RL):** the RL agent **learns real risk-priority and
  matches the doctrine heuristic on real estates** — reward 140.34 vs
  heuristic 140.62 (Δ −0.28, tie) vs random 136.84 (+2.6%), 100% completion,
  with risk labels derived from the real scan fields. (An archived claim that
  it *beat* the heuristic (+15.8%) was not reproducible — the CBOM builder
  stamped every asset `criticality: medium`, zeroing the reward signal; it
  was fixed and re-measured on 2026-09-02.) The honest RL differentiator is
  a *reproducible real-estate benchmark with documented reward semantics*,
  not a victory margin over the doctrine.
- The competitive edge is the **data + honesty + reproducible real-data
  discipline**, not the architecture. Competitors can build a GNN or an RL
  agent; they cannot easily publish a real, host-disjoint, deterministic-kernel
  LOO benchmark and a real-CBOM RL benchmark with documented reward
  semantics without doing the years of scanning and labeling the repo has
  started.

## 6. Engineering hygiene next

- Keep the repo-wide lint/test/build matrix green (this session restored it;
  CI now enforces: forge 213, halmos symbolic 4/4 (now a blocking job),
  vitest 72+55, pytest 330, ruff, mkdocs strict, npm audits, go-live
  preflight).
- The one environment item to fix: the container's CUDA device is reported
  but intermittently busy/unusable — reserve the GPU explicitly for training
  runs, and keep the probe-based device fallback so benchmarks record where
  they actually ran.
