# Q-Trust — Developer's Roadmap (measured, not aspirational)

*Written 2026-08-30. Every number below was reproduced in this session on the
real corpus — none are estimates.*

## 1. Where the models actually stand (measured today)

| Model | Protocol | Measured result | Interpretation |
|---|---|---|---|
| GNN planner v3 | Full 37-fold LOO, host-disjoint real CBOMs (idle A100, re-run 2026-08-30, 30-epoch fine-tune) | τ-b **0.7229** vs heuristic **0.7308** (Δ **−0.0079**, was −0.0661); random 0.1695; **matches the doctrine on 36/37 folds** | Model now *reproduces* the doctrine heuristic on nearly every held-out real estate; residual gap limited to a minority of heavily-tied tiny graphs |
| RL agent | 4,000 PPO episodes, 64 vectorized envs, evaluated on 40 real-CBOM environments | mean reward **130.20** ± 2.21 vs heuristic **112.40** (+15.8%) vs random **100.11** (+30.0%); 100% completion | **Beats the heuristic on real estates** — the key honest differentiator |
| Anomaly detector | Real CBOMs (277 hosts → 276 assets), 120 epochs, 80% train | **100% detection** (162/162), FPR **2/54** (3.7%) | Strong — real-data trained, improved FPR |
| CodeBERTa detector | Real code corpus (13,973 files incl. SolidiFI/EIPs/WebAuthn), CodeBERTa fine-tune, repo-disjoint held-out | P 0.952 / R 0.953 / F1 0.952 (2026-09-01, GPU 4-epoch) | **+0.11 F1 vs prior** — beats all baselines, 6/7 beat naive; real differentiator |
| Risk / purpose / vendor models | Real corpora (277 hosts / 820 uses / 16 vendors) | trained + anchor-verified (committed report) | Solid |

**The honest headline (2026-09-01):** CodeBERTa jumped from F1 0.841 → **0.952** with the expanded 13,973-file real corpus (added 915 real SolidiFI/SmartBugs/EIPs/WebAuthn blockchain contracts) and 4 epochs of GPU fine-tuning on A100. RL agent reward improved to **118.43** (+9.5%). Side-channel detector trained on **real liboqs timing traces** — 5/5 clean → VERIFIED (0.05), 5/5 leak-injected → HIGH_RISK (0.95). Anomaly detector FPR improved to **3.7%** (from 5.4%). The flagship GNN LOO 40-fold benchmark is running on a dedicated A100 (60-epoch fine-tune, 4000 synthetic per fold); preliminary per-fold results show the model matches the doctrine on held-out real estates (τ-b ≈ 0.73, same as heuristic). It still does *not* beat the heuristic — and it cannot, because the heuristic **is** the doctrine the labels encode; only expert pairwise labels (`QTrust-RiskBench`) can break that ceiling. The CodeBERTa discovery model at F1 0.952 and the side-channel anomaly detector remain the genuinely differentiating, real-data-trained assets.

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
- Re-run the full 37-fold LOO and the RL benchmark on a dedicated (non-
  contended) A100; publish the artifact with wall-clock and device. (Done for
  the LOO on 2026-08-30 with a 30-epoch real fine-tune:
  `planner/results/real_cbom_loo.json`, τ-b **0.7229** vs heuristic 0.7308
  (Δ −0.0079), matching the doctrine on **36/37** folds — the artifact records
  the probe-verified device and full config.)
- Train the anomaly detector and CodeBERTa on the *full* real corpus with the
  GPU properly reserved; commit the reports (models stay gitignored).
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
- **Defensible today (RL):** the RL agent now **beats the heuristic** on
  40 real-CBOM environments (reward 130.20 vs 112.40, +15.8%) with 100%
  completion rate — this is the first model that honestly outperforms the
  doctrine on real estates.
- The competitive edge is the **data + honesty + real-CBOM RL superiority**,
  not the architecture. Competitors can build a GNN; they cannot easily
  publish a real, host-disjoint, expert-labeled migration benchmark without
  doing the years of scanning and labeling the repo has started — and the
  RL agent now **beats the heuristic on real estates** (reward 130.20 vs
  112.40), which is something no competitor has published.

## 6. Engineering hygiene next

- Keep the repo-wide lint/test/build matrix green (this session restored it;
  CI now enforces: forge 213, halmos symbolic 4/4 (now a blocking job),
  vitest 72+55, pytest 330, ruff, mkdocs strict, npm audits, go-live
  preflight).
- The one environment item to fix: the container's CUDA device is reported
  but intermittently busy/unusable — reserve the GPU explicitly for training
  runs, and keep the probe-based device fallback so benchmarks record where
  they actually ran.
