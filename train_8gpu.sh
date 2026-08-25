#!/bin/bash
# ============================================================
# Q-Trust Multi-GPU Full Utilization Script
# ============================================================
# Trains every GPU feature concurrently, adapting to GPUs that
# are already busy (the node is shared with other workloads):
#
#   DDP_GPUS          (default "1,2") — distributed GNN v3, 400K graphs
#   QTRUST_GPU_RL     (default 5)     — RL migration agent, 10K episodes
#   QTRUST_GPU_INSPECTOR (default 6)  — side-channel -> anomaly -> Shor N=77
#
# Override before running, e.g. on an idle 8-GPU box:
#   DDP_GPUS="0,1,2,3" QTRUST_GPU_RL=4 \
#   QTRUST_GPU_INSPECTOR=5 bash train_8gpu.sh
#
# Usage:
#   bash train_8gpu.sh            # full run (~2h wall)
#   bash train_8gpu.sh --check    # only show GPU inventory
#   QUICK=1 bash train_8gpu.sh    # smoke pass
# ============================================================

set -e

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
TORCHRUN_LAUNCH="$PYTHON -m torch.distributed.run"
DDP_GPUS="${DDP_GPUS:-1,2}"
export QTRUST_GPU_RL="${QTRUST_GPU_RL:-5}"
export QTRUST_GPU_INSPECTOR="${QTRUST_GPU_INSPECTOR:-6}"
export QTRUST_GPU_QUANTUM="$QTRUST_GPU_INSPECTOR"

echo "=== Q-Trust multi-GPU utilization ==="
echo ""
"$PYTHON" - <<'EOF'
import torch
n = torch.cuda.device_count()
print(f"{n} CUDA device(s) visible:")
for i in range(n):
    props = torch.cuda.get_device_properties(i)
    free, total = torch.cuda.mem_get_info(i)
    print(f"  cuda:{i}: {props.name} {total/1e9:.0f}GB "
          f"(free {free/1e9:.0f}GB, used {(total-free)/1e9:.0f}GB)")
EOF
echo ""
echo "Assignment: DDP_GNN=[$DDP_GPUS] RL=[$QTRUST_GPU_RL] INSPECTOR=[$QTRUST_GPU_INSPECTOR]"
echo ""

if [ "$1" = "--check" ]; then
    echo "GPU check complete."
    exit 0
fi

mkdir -p logs

# ── Phase 1: parallel jobs (RL + inspector suite) ────────────
echo "=== Phase 1: launching parallel jobs ==="
QUICK_FLAG=""
[ -n "$QUICK" ] && QUICK_FLAG="--quick"

CUDA_VISIBLE_DEVICES="$QTRUST_GPU_RL" "$PYTHON" train_all_parallel.py $QUICK_FLAG \
    > logs/parallel_jobs.log 2>&1 &
PID_PARALLEL=$!
echo "  RL/inspector/quantum jobs launched (log: logs/parallel_jobs.log)"

# ── Phase 2: DDP GNN training ────────────────────────────────
echo ""
echo "=== Phase 2: DDP GNN training on GPUs [$DDP_GPUS] ==="

DDP_ARGS="--epochs 200 --n-graphs 400000 --batch-size 256 --lr 1e-3 --seed 42"
[ -n "$QUICK" ] && DDP_ARGS="--quick"

PYTHONPATH="$PWD/planner${PYTHONPATH:+:$PYTHONPATH}" \
CUDA_VISIBLE_DEVICES="$DDP_GPUS" \
    $TORCHRUN_LAUNCH --nproc_per_node=$(echo "$DDP_GPUS" | tr ',' '\n' | wc -l) \
        --master_port="${MASTER_PORT:-12355}" \
        -m qtrust_planner.train_ddp $DDP_ARGS \
        --model-path planner/model_ddp_v3.pt \
    > logs/ddp_gnn.log 2>&1 &
PID_DDP=$!
echo "  DDP GNN launched (log: logs/ddp_gnn.log)"

# ── Phase 3: wait and summarize ──────────────────────────────
echo ""
echo "=== Phase 3: waiting for all jobs ==="
FAIL=0

wait $PID_PARALLEL || FAIL=1
grep -E "\[(SUCCESS|FAILED)\]|OK |MISS |complete in" logs/parallel_jobs.log | tail -12 || true

wait $PID_DDP || FAIL=1
tail -8 logs/ddp_gnn.log || true

echo ""
echo "============================================================"
if [ "$FAIL" = "0" ]; then echo "MULTI-GPU TRAINING COMPLETE"; else echo "TRAINING FINISHED WITH FAILURES (see logs/)"; fi
echo "============================================================"
echo ""
echo "Model files produced:"
for f in planner/model_ddp_v3.pt planner/rl_agent.pt \
         inspector/side_channel_model.pt inspector/anomaly_model.pt \
         notebooks/quantum_threat_report.json; do
    if [ -f "$f" ]; then
        echo "  OK   $f ($(du -h "$f" | cut -f1))"
    else
        echo "  MISS $f"
    fi
done

echo ""
echo "Next steps:"
echo "  1. Benchmark: cd planner && python -m qtrust_planner.benchmark_v3 --model model_ddp_v3.pt"
echo "  2. git add -f planner/model_ddp_v3.pt && git commit"
echo "============================================================"
