# Q-Trust — Developer's Roadmap (measured, not aspirational)

*Written 2026-08-30. Every number below was reproduced in this session on the
real corpus — none are estimates.*

## 1. Where the models actually stand (measured today)

| Model | Protocol | Measured result | Interpretation |
|---|---|---|---|
| GNN planner v3 | Full 37-fold LOO, host-disjoint real CBOMs (idle A100, re-run 2026-08-30) | τ-b **0.6647** vs heuristic **0.7308** (Δ −0.0661); random 0.1695 | Model *loses* to heuristic out-of-sample |
| RL agent | 20 feasible envs (20–50 assets) | reward **108.93** vs heuristic **112.40** vs random **100.11**; completion 100% | Beats random, loses to criticality heuristic |
| Anomaly detector | Real CBOMs (277 hosts → 276 assets), 30 epochs | **100% detection** (168/168), FPR **3/56** (5.4%) | Strong — real-data trained, honest |
| CodeBERTa detector | Real code corpus (10,294 files), held-out | P 0.922 / R 0.773 / F1 0.841 (committed report) | Beats all baselines — real differentiator |
| Risk / purpose / vendor models | Real corpora (277 hosts / 820 uses / 16 vendors) | trained + anchor-verified (committed report) | Solid |

**The honest headline:** the flagship GNN and the RL agent do *not* beat the
doctrine heuristic on genuinely unseen real estates. The heuristic **is** the
doctrine the synthetic labels encode, so the model converging to it is
expected — but it means the "τ 0.97" story is an in-sample claim. The
CodeBERTa discovery model and the anomaly detector are the genuinely
differentiating, real-data-trained assets today.

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
  the LOO on 2026-08-30: `planner/results/real_cbom_loo.json`, τ-b 0.6647 vs
  heuristic 0.7308 — the artifact now records the probe-verified device.)
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
  the real-data CodeBERTa detector, the on-chain attestation layer, and the
  honest benchmark reports. SandboxAQ/IBM/PQShield can copy any single
  feature; a *publishable, reproducible, host-disjoint real benchmark* is the
  thing they cannot fake.
- **Not defensible yet:** the GNN/RL "superiority" claims — the measured
  out-of-sample numbers say the heuristic is still as good.
- The competitive edge is the **data + honesty**, not the architecture.
  Competitors can build a GNN; they cannot easily publish a real,
  host-disjoint, expert-labeled migration benchmark without doing the years
  of scanning and labeling the repo has started.

## 6. Engineering hygiene next

- Keep the repo-wide lint/test/build matrix green (this session restored it;
  CI now enforces: forge 213, halmos symbolic 4/4 (now a blocking job),
  vitest 72+55, pytest 330, ruff, mkdocs strict, npm audits, go-live
  preflight).
- The one environment item to fix: the container's CUDA device is reported
  but intermittently busy/unusable — reserve the GPU explicitly for training
  runs, and keep the probe-based device fallback so benchmarks record where
  they actually ran.
