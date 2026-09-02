#!/usr/bin/env python3
"""Build the Q-Trust "real-data training campaign" Jupyter notebook.

Emits ``research/notebooks/03_train_and_benchmark_real.ipynb`` — a single
notebook that orchestrates the FULL rigorous campaign from BrevLab/Jupyter:
real corpora -> train every model on real data -> honest OOS benchmarks.

Every cell shells out to the canonical scripts (the same ones CI and the docs
use), so the notebook is a reproducible control panel, not a parallel
implementation. ``FULL = True`` runs the complete campaign (multi-GPU LOO,
4000-episode RL retrain, 4-epoch CodeBERTa fine-tune); ``FULL = False`` is a
CI-sized smoke pass that still exercises every stage.

Regenerate with:  python scripts/build_campaign_notebook.py
Execute with:     jupyter nbconvert --to notebook --inplace --execute \\
                      --ExecutePreprocessor.timeout=-1 \\
                      research/notebooks/03_train_and_benchmark_real.ipynb
"""
from __future__ import annotations

import json
from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "research" / "notebooks" / "03_train_and_benchmark_real.ipynb"

nb = nbf.v4.new_notebook()
nb.metadata = {
    "kernelspec": {"display_name": "Python 3 (fignn)", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.13"},
}
cells = []


def md(src: str) -> None:
    cells.append(nbf.v4.new_markdown_cell(src))


def code(src: str) -> None:
    cells.append(nbf.v4.new_code_cell(src))


md("""# Q-Trust — Rigorous Real-Data Training Campaign

> Reproduces, cell by cell, the flagship numbers in the README / Truth Audit:
> CodeBERTa code discovery on **13,973 real code files**, the **40-fold
> host-disjoint LOO** GNN planner benchmark on 280 real TLS hosts (τ-b 0.7263,
> deterministic kernels, folds sharded across 4 A100s), the PPO migration
> agent on **real-CBOM estates with scan-derived risk labels** (140.34 vs
> doctrine heuristic 140.62 — a tie, Δ −0.28 — vs random 136.84, +2.6%;
> bit-reproducible across processes), the side-channel detector on **real
> liboqs timing traces**, and all 15
> `qtrust_ai` intelligence-layer models trained on real datasets (code corpus
> / TLS scan / NVD vendor data).
>
> **Hardware:** 8× NVIDIA A100-SXM4-80GB · 24 cores · 1.7 TiB RAM (BrevLab)
>
> Run this notebook (or execute it headlessly with `nbconvert --execute`).
> `FULL = False` runs a CI-sized smoke pass; set `FULL = True` for the complete
> campaign. Background jobs launched from cells are tracked with their logs in
> `logs/`; Long-running stages print `tail` of their log so you can watch.""")

code("""import os

# 0. Configuration
FULL = False            # True = rigorous campaign (LOO 40-fold merge, RL retrain, 4-epoch CodeBERTa)
GPU = "2"               # CUDA_VISIBLE_DEVICES for GPU stages ("" = let torch decide)
N_LOO_EPOCHS = 30 if FULL else 2
N_LOO_SYNTH = 2000 if FULL else 300
N_HF = 4 if FULL else 0   # smoke skips the transformer fine-tune (code detector stays deterministic-layer in smoke)
# 4000 PPO episodes costs ~3 h on one A100 (~2.9 s/rollout); the canonical
# committed agent (rl_agent_real.pt, 2026-09-02) was trained for 190 episodes
# (reward converged 8.86 @100 -> 8.82 @190, best 8.86) on real-CBOM packs with
# scan-derived risk labels and a per-process-deterministic packing. Set 4000
# for a longer-horizon agent.
N_RL_EPISODES = 190 if FULL else 64
N_SIDE_EPOCHS = 60 if FULL else 12
N_ANOMALY_EPOCHS = 120 if FULL else 25
# Smoke mode writes to scratch artifacts so the canonical benchmark JSONs
# (cited by the README / Truth Audit) are only refreshed by FULL runs.
SUFFIX = "" if FULL else "_notebook"
TR = f"qtrust_ai/artifacts/training_report_real{SUFFIX}.json"
BC = f"qtrust_ai/artifacts/benchmark_comparison{SUFFIX}.json"
LOO = f"planner/results/real_cbom_loo{SUFFIX}.json"
RL = f"planner/results/rl_benchmark_real_cbom{SUFFIX}.json"
if GPU:
    os.environ["CUDA_VISIBLE_DEVICES"] = GPU
os.environ.setdefault("QTRUST_DISABLE_COMPILE", "1")  # dynamic graphs: compile is 10x slower
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
print("FULL =", FULL, "| CUDA_VISIBLE_DEVICES =", GPU, "| artifact suffix:", repr(SUFFIX))""")

md("## 1. Environment & dataset inventory")

code("""import glob
import json
import subprocess
import sys
import time
from pathlib import Path

import torch
import torch_geometric
import transformers

# The notebook may be executed from anywhere (BrevLab root, research/notebooks,
# or a subprocess cwd) — always anchor at the repo root, like the scripts do.
ROOT = Path.cwd()
if not (ROOT / "scripts").exists():
    for cand in [ROOT.parent, ROOT.parent.parent]:
        if (cand / "scripts").exists():
            ROOT = cand
            break
if not (ROOT / "scripts").exists():
    raise SystemExit(f"repo root not found from {Path.cwd()}")
print("repo root:", ROOT)
print("torch", torch.__version__, "| cuda available:", torch.cuda.is_available(),
      "| devices:", torch.cuda.device_count())
if torch.cuda.is_available():
    for i in range(torch.cuda.device_count()):
        p = torch.cuda.get_device_properties(i)
        print(f"  GPU {i}: {p.name} ({p.total_memory/1e9:.0f} GiB)")
print("pyg", torch_geometric.__version__, "| transformers", transformers.__version__)
datasets = ROOT / "qtrust_ai" / "artifacts" / "real_datasets"
code_corpus = json.loads((datasets / "code_corpus.json").read_text())
tls = json.loads((datasets / "tls_inventory.json").read_text())
n_crypto = sum(1 for r in code_corpus["corpus"] if r["is_crypto"])
print(f"real code corpus: {len(code_corpus['corpus'])} files ({n_crypto} crypto) "
      f"| languages: {sorted({r['language'] for r in code_corpus['corpus']})}")
print(f"real TLS inventory: {len(tls.get('cboms', []))} CBOMs / {tls.get('n_findings')} findings")
cboms = sorted((ROOT / "planner" / "data" / "real_cboms").glob("*.json"))
print(f"host-disjoint real CBOM corpus: {len(cboms)} CBOMs "
      f"({sum(len(json.loads(open(c).read())['assets']) for c in cboms)} assets)")
traces = sorted(glob.glob("/tmp/real_data/traces_*.txt"))
print(f"real liboqs timing traces: {[Path(t).stem.removeprefix('traces_') for t in traces]}")""")

md("## 2. Train all 15 `qtrust_ai` models on the real datasets\n\nRuns `scripts/train_qtrust_all.py --real`: discovery (CodeBERTa fine-tune, GPU), purpose classifier, blast radius, temporal GNN, quantum-exposure risk, PQC recommender, cost/failure/interop (labels proprietary → synthetic, stated), multi-objective RL, anomaly, regression, vendor supply-chain, copilot, policy — **plus** the baseline comparison (models vs naive baselines on the same real splits).")

code("""print(">>> train_qtrust_all.py --real (hf_epochs =", N_HF, ")")
t0 = time.time()
r = subprocess.run(
    [sys.executable, "scripts/train_qtrust_all.py", "--real", "--epochs", "5",
     "--hf-epochs", str(N_HF), "--report", TR, "--benchmark-out", BC],
    capture_output=True, text=True, cwd=ROOT)
print(r.stdout[-3000:])
print(r.stderr[-800:] if r.returncode else "", flush=True)
print("exit:", r.returncode, "| wall:", round(time.time()-t0, 1), "s")
rep = json.loads((ROOT / TR).read_text())
s = rep["summary"]
print(f"summary: {s['trained']} trained / {s['anchor_fail']} anchor-fail / {s['errors']} errors")
for e in rep["results"]:
    ev = (e.get("train") or {}).get("_eval") or {}
    if isinstance(ev, dict) and ("accuracy" in ev or "f1" in ev):
        print(f"  {e['model']:<40} { {k: round(ev[k],3) for k in ('accuracy','f1','precision','recall') if k in ev} }")""")

md("## 3. GNN planner — honest out-of-sample benchmark (40-fold LOO)\n\n`scripts/eval_real_cbom_loo.py` runs the host-disjoint leave-one-out protocol: for each real CBOM, fine-tune a fresh model on the other 39 (+ synthetic doctrine mix) and evaluate on the held-out estate only. Baselines (priority heuristic, random) are scored on the identical folds. In `FULL` mode the cell first tries to **merge the 4 GPU shards** already produced by the 4-A100 campaign (`--merge-shards`); if they are missing it prints the exact shard commands to launch. Smoke mode runs `--quick` (3 folds) into a suffixed artifact.")

code("""print(">>> eval_real_cbom_loo.py (FULL: merge 4-GPU shards; else quick smoke)")
t0 = time.time()
shards = sorted((ROOT / "planner" / "results").glob(f"{Path(LOO).name}_shard*.json"))
if FULL and len(shards) == 4:
    print(f"found {len(shards)} shards -> merging")
    r = subprocess.run([sys.executable, "scripts/eval_real_cbom_loo.py", "--merge-shards", "--out", LOO],
                       capture_output=True, text=True, cwd=ROOT)
    print(r.stdout[-1500:])
    print(r.stderr[-500:] if r.returncode else "")
    print("exit:", r.returncode)
elif FULL:
    print("No 4-GPU shards found. Launch on 4 A100s and merge here, e.g.:")
    print("  CUDA_VISIBLE_DEVICES=0 python scripts/eval_real_cbom_loo.py --epochs 30 --n-synthetic 2000 --fold-start 0  --fold-end 10")
    print("  CUDA_VISIBLE_DEVICES=1 python scripts/eval_real_cbom_loo.py --epochs 30 --n-synthetic 2000 --fold-start 10 --fold-end 20")
    print("  CUDA_VISIBLE_DEVICES=2 python scripts/eval_real_cbom_loo.py --epochs 30 --n-synthetic 2000 --fold-start 20 --fold-end 30")
    print("  CUDA_VISIBLE_DEVICES=3 python scripts/eval_real_cbom_loo.py --epochs 30 --n-synthetic 2000 --fold-start 30 --fold-end 40")
    print("  python scripts/eval_real_cbom_loo.py --merge-shards")
    print("Skipping the single-process 40-fold run here (~3 h); see docs/DEVELOPER_ROADMAP.md.")
else:
    cmd = [sys.executable, "scripts/eval_real_cbom_loo.py", "--quick",
           "--epochs", str(N_LOO_EPOCHS), "--n-synthetic", str(N_LOO_SYNTH), "--out", LOO]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    print(r.stdout[-1800:])
    print(r.stderr[-500:] if r.returncode else "", flush=True)
    print("exit:", r.returncode, "| wall:", round(time.time()-t0, 1), "s")
loo_path = ROOT / LOO
if loo_path.exists():
    rep = json.loads(loo_path.read_text())
    a = rep["aggregate"]
    print("aggregate τ-b  model", round(a["model"]["kendall"]["mean"],4),
          "| heuristic", round(a["heuristic"]["kendall"]["mean"],4),
          "| random", round(a["random"]["kendall"]["mean"],4),
          "| Δmodel-heur", round(rep["model_vs_heuristic_tau_b"],4))""")

md("## 4. RL migration agent — retrain on real CBOMs, benchmark vs heuristic/random\n\nReal TLS findings carry only the CBOM builder's blanket `criticality: medium`, which would leave the reward with no sequencing signal — the retrain and eval scripts derive risk labels from the real scan fields (`risk_criticality_from_scan`: RSA-1024 → critical, RSA-2048 → high, expired/self-signed/near-expiry raise the class). `scripts/retrain_rl_real_cbom.py` runs PPO (64 vectorized envs, deterministic kernels) on 100 packed real-CBOM estates; `scripts/eval_rl_real_cbom.py` then does greedy rollouts of agent vs criticality heuristic vs random on 40 packed real environments.")

code("""if FULL:
    print(">>> retrain_rl_real_cbom.py", N_RL_EPISODES, "episodes")
    r = subprocess.run([sys.executable, "scripts/retrain_rl_real_cbom.py", str(N_RL_EPISODES)],
                      capture_output=True, text=True, cwd=ROOT)
    print(r.stdout[-1500:])
    print(r.stderr[-600:] if r.returncode else "")
    print("exit:", r.returncode)
print(">>> eval_rl_real_cbom.py")
r = subprocess.run([sys.executable, "scripts/eval_rl_real_cbom.py", "--out", RL],
                   capture_output=True, text=True, cwd=ROOT)
print(r.stdout[-2500:])
print(r.stderr[-600:] if r.returncode else "", flush=True)
print("exit:", r.returncode)""")

md("## 5. Side-channel detector on real liboqs traces\n\nTrains a CNN on bootstrap-resampled windows of **real** liboqs ML-KEM-512/768 and ML-DSA-44 timing traces (+ keyed leak injection on the same noise floor), then validates clean vs leak-injected held-out real trace sets.")

code("""print(">>> train_real_side_channel.py", N_SIDE_EPOCHS, "epochs")
SIDE_SAVE = "inspector/side_channel_model_real.pt" if FULL else \
            "inspector/side_channel_model_real_notebook.pt"  # smoke never clobbers canonical
r = subprocess.run([sys.executable, "scripts/train_real_side_channel.py",
                    "--traces-dir", "/tmp/real_data", "--epochs", str(N_SIDE_EPOCHS),
                    "--save-path", SIDE_SAVE],
                   capture_output=True, text=True, cwd=ROOT)
print(r.stdout[-2200:])
print(r.stderr[-600:] if r.returncode else "", flush=True)
print("exit:", r.returncode, "| saved:", SIDE_SAVE)""")

md("## 6. Anomaly detector on the real host-disjoint CBOM corpus\n\nVAE trained on 80% of the real CBOMs (per-host), evaluated on the held-out 20% plus three real-world attack injections (weak-key rollback, config drift, renewal failure).")

code("""print(">>> train_real_models.py --model anomaly (epochs =", N_ANOMALY_EPOCHS, ")")
r = subprocess.run([sys.executable, "scripts/train_real_models.py", "--model", "anomaly",
                    "--epochs", str(N_ANOMALY_EPOCHS)], capture_output=True, text=True, cwd=ROOT)
print(r.stdout[-2000:])
print(r.stderr[-600:] if r.returncode else "", flush=True)
print("exit:", r.returncode)
if not FULL:
    print("NOTE: smoke retrains the canonical anomaly_model_real.pt at reduced epochs;",
          "re-run `python scripts/train_real_models.py --model anomaly --epochs 120` for the canonical artifact")""")

md("## 7. Recap — the honest headline table\n\nEvery number above is out-of-sample on real data (host-disjoint CBOMs, repo-disjoint code splits, held-out liboqs trace sets), with device + config recorded in the artifacts. The GNN reproduces the migration doctrine on 38/40 held-out real CBOMs (τ-b 0.7263) and the RL agent matches the doctrine heuristic on real estates (Δ −0.28) while beating random (+2.6%) — neither beats the doctrine, because the doctrine is the label; the ceiling break requires expert pairwise labels (`QTrust-RiskBench`).")

code("""print("campaign artifacts:")
for name in [TR, BC, LOO, RL]:
    p = ROOT / name
    if p.exists():
        d = json.loads(p.read_text())
        when = d.get("generated_at", "?")
        dev = d.get("device", "?")
        print(f"  {name:<58} {when}  [{dev}]")
print("\\nNow audit against docs/TRUTH_AUDIT.md — and enjoy the GPUs. 🚀")""")

nb["cells"] = cells
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(nb, indent=1, ensure_ascii=False))
print(f"Wrote {OUT} ({len(cells)} cells)")