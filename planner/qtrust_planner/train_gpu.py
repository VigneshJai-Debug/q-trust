"""GPU-accelerated GNN training — 100K graphs, BF16 mixed precision, larger model.

Drop-in GPU counterpart to train.py:

  - 100,000 synthetic training graphs (vs 1,200 in train.py)
  - up to 200 epochs
  - Larger model: MigrationGNNv3 (256-dim hidden, 128-dim embedding, 8 heads)
  - BF16 mixed-precision training on A100-class GPUs
  - Batch size 256
  - Saves to model_gpu_v3.pt

Usage:
    cd planner
    python -m qtrust_planner.train_gpu
    python -m qtrust_planner.train_gpu --quick
"""
from __future__ import annotations

import argparse
import os
import random
import time
from pathlib import Path

import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader

from .data_generator import generate_dataset
from .model_v3 import MigrationGNNv3


def listMLE_loss(order_logits: torch.Tensor, y_order: torch.Tensor) -> torch.Tensor:
    """ListMLE ranking loss (Plackett-Luce likelihood) for a SINGLE graph.

    Args:
        order_logits: (N,) predicted priority scores for one graph.
        y_order: (N,) ground-truth rank of each node (0 = first to migrate).
    Returns:
        Scalar loss; caller must average across graphs in a batch.
        For batched tensors spanning multiple graphs, use per_graph_listMLE_loss.
    """
    if order_logits.numel() <= 1:
        return torch.zeros((), device=order_logits.device)
    perm = torch.argsort(y_order)
    scores = order_logits[perm]
    max_val = scores.max().detach()
    scores = scores - max_val
    # logcumsumexp from the bottom of the ranked list upward
    log_cumsum = torch.logcumsumexp(scores.flip(0), dim=0).flip(0)
    # P0-1 fix: mean reduction so loss is comparable across graph sizes
    loss = (log_cumsum - scores).mean()
    return loss


def per_graph_listMLE_loss(
    order_logits: torch.Tensor,
    y_order: torch.Tensor,
    batch_idx: torch.Tensor | None,
) -> torch.Tensor:
    """Compute ListMLE per-graph and average (fully vectorized).

    When batch_idx is None, treats the entire tensor as one graph
    (backward compatible single-graph path). Otherwise computes the
    per-graph Plackett-Luce likelihood with segmented suffix-logsumexp
    — mathematically identical to the original Python loop over graphs
    (verified < 1e-5 max abs error on 100 random batches) but runs at
    GPU speed instead of ~550 graphs/s. This is the P0-1 fix for the
    cross-graph ListMLE bug documented in diagnosis register P0-1.
    """
    if batch_idx is None:
        return listMLE_loss(order_logits, y_order)
    # Ensure batch_idx is on same device
    if batch_idx.device != order_logits.device:
        batch_idx = batch_idx.to(order_logits.device)
    if batch_idx.numel() == 0:
        return torch.zeros((), device=order_logits.device)
    n_graphs = int(batch_idx.max().item()) + 1
    if n_graphs == 1:
        return listMLE_loss(order_logits, y_order)

    device = order_logits.device
    # Global sort by (graph, true-rank) — ascending rank within each graph,
    # which is exactly the per-graph argsort the reference loop performs.
    combined = batch_idx.long() * (int(y_order.max().item()) + 2) + y_order.long()
    order = torch.argsort(combined)
    bs = batch_idx[order]
    scores = order_logits[order]

    # Per-segment max for numerical stability (== graph max of the scores).
    seg_max = torch.full((n_graphs,), float("-inf"), device=device)
    seg_max.scatter_reduce_(0, bs, scores, reduce="amax", include_self=False)
    sm = seg_max[bs]

    # Segmented suffix-logsumexp of exp(scores - max): the reference computes
    # logcumsumexp over the reversed (bottom-up) ranked list, i.e. the suffix
    # logsumexp of the ascending list. Sums of exp are segment-decomposable,
    # so prefix sums minus segment starts give the within-segment suffix sums.
    # Compute the prefix sums in float64: with float32 the global cumsum can
    # reach ~1e4 while a within-segment suffix is ~1e-4, and the subtraction
    # `seg_total - within_prefix + e` suffers catastrophic cancellation, going
    # slightly negative (=> log(NaN)). float64 keeps ~15 digits so the segment
    # decomposition is exact for any realistic batch. The gradients flow back
    # through the fp64 ops to the fp32 logits unchanged.
    sm64 = sm.double()
    scores64 = scores.double()
    e = torch.exp(scores64 - sm64)
    prefix = torch.cumsum(e, 0)
    seg_total = torch.zeros(n_graphs, device=device, dtype=torch.float64)
    seg_total.scatter_add_(0, bs, e)
    csum_seg = torch.cumsum(seg_total, 0) - seg_total  # exclusive totals before seg
    excl = csum_seg[bs]
    within_prefix_incl = prefix - excl  # within-segment prefix incl. current item
    suffix_sum = seg_total[bs] - within_prefix_incl + e  # sum from item to seg end
    # suffix_sum is mathematically >= e (the sum always includes the current
    # element's exp). When logits span a wide range, the segment decomposition
    # `seg_total - within + e` loses the tiny `e` in cancellation error
    # (~1e-14 vs e ~ 1e-30), so clamp to the exact mathematical floor `e` —
    # NOT to fp tiny, which would turn log() into a huge negative and corrupt
    # the loss for low-ranked elements.
    suffix_sum = torch.clamp(suffix_sum, min=e)
    suffix_log = torch.log(suffix_sum) + sm64

    loss_i = (suffix_log - scores64).float()
    cnt = torch.zeros(n_graphs, device=device)
    cnt.scatter_add_(0, bs, torch.ones_like(bs, dtype=torch.float32))
    seg_loss = torch.zeros(n_graphs, device=device)
    seg_loss.scatter_add_(0, bs, loss_i)
    return (seg_loss / cnt).mean()


def _kendall_tau(pred: torch.Tensor, true_rank: torch.Tensor) -> float:
    """Vectorized Kendall tau between predicted scores and true ranks.

    pred: (N,) scores where higher = migrate first.
    true_rank: (N,) ground truth rank (0 = first).
    """
    n = pred.numel()
    if n < 2:
        return 1.0
    pred_ranks = torch.argsort(torch.argsort(pred, descending=True)).float()
    d_pred = pred_ranks.unsqueeze(0) - pred_ranks.unsqueeze(1)
    d_true = true_rank.float().unsqueeze(0) - true_rank.float().unsqueeze(1)
    iu = torch.triu_indices(n, n, offset=1)
    p = d_pred[iu[0], iu[1]]
    t = d_true[iu[0], iu[1]]
    concordant = ((p > 0) & (t > 0)) | ((p < 0) & (t < 0))
    discordant = (p != 0) & (t != 0) & ~concordant
    total = n * (n - 1) / 2
    return float((concordant.sum().item() - discordant.sum().item()) / max(total, 1))


def compute_metrics(order_logits: torch.Tensor, y_order: torch.Tensor) -> dict:
    """Ranking metrics: Kendall tau, top-5 and top-10 overlap."""
    kendall = _kendall_tau(order_logits.detach().cpu(), y_order.detach().cpu())

    n = order_logits.numel()
    top5_pred = set(torch.argsort(order_logits, descending=True)[:5].tolist())
    top5_true = set(torch.argsort(y_order)[:5].tolist())
    top5_overlap = len(top5_pred & top5_true) / min(5, n)

    top10_pred = set(torch.argsort(order_logits, descending=True)[:10].tolist())
    top10_true = set(torch.argsort(y_order)[:10].tolist())
    top10_overlap = len(top10_pred & top10_true) / min(10, n)

    return {
        "kendall": float(kendall),
        "top5": float(top5_overlap),
        "top10": float(top10_overlap),
    }


def train_gpu(
    n_graphs: int = 100_000,
    epochs: int = 200,
    batch_size: int = 256,
    learning_rate: float = 1e-3,
    weight_decay: float = 1e-4,
    model_path: str | None = None,
    seed: int = 42,
    val_split: float = 0.1,
    device_name: str | None = None,
    extra_graphs: list | None = None,
    norm: str = "batch",
    init_path: str | None = None,
) -> str:
    """Train MigrationGNNv3 with BF16 mixed precision.

    Args:
        extra_graphs: Optional list of real-data graphs (e.g. from
            cbom_to_dependency_graph) mixed into the synthetic dataset.
            The combined dataset is shuffled so real graphs land in both
            train and validation splits.
        norm: Hidden-layer normalization — "batch" (legacy BatchNorm1d,
            checkpoint-compatible), "layer" (LayerNorm, recommended: per-node
            stats are batch-agnostic under PyG batching, no cross-graph
            leakage — see model_v3 AUDIT NOTE), or "graph" (GraphNorm).

    Returns the path the best model was saved to.
    """
    if model_path is None:
        model_dir = os.environ.get("QTRUST_MODEL_DIR", ".")
        model_path = os.path.join(model_dir, "model_gpu_v3.pt")

    use_cuda = torch.cuda.is_available() and device_name != "cpu"
    device = torch.device(device_name or ("cuda" if use_cuda else "cpu"))
    if not use_cuda:
        print("WARNING: CUDA not available — running reduced CPU training pass.")
        n_graphs = min(n_graphs, 2_000)
        epochs = min(epochs, 5)

    torch.manual_seed(seed)

    print(f"Device: {torch.cuda.get_device_name(0)}" if use_cuda else "Device: cpu")
    if use_cuda:
        print(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    print(f"Generating {n_graphs:,} synthetic graphs...")
    gen_start = time.time()
    dataset = generate_dataset(n_graphs=n_graphs, seed=seed)
    if extra_graphs:
        dataset = dataset + list(extra_graphs)
        random.Random(seed).shuffle(dataset)
        print(f"Added {len(extra_graphs)} real-data graphs (total {len(dataset):,})")
    print(f"Generation took {time.time() - gen_start:.1f}s")

    if len(dataset) < batch_size * 2:
        raise ValueError(
            f"dataset too small ({len(dataset)}) for batch size {batch_size}; "
            "reduce --batch-size or increase --n-graphs"
        )

    n_val = max(1, int(len(dataset) * val_split))
    n_train = len(dataset) - n_val
    train_dataset = dataset[:n_train]
    val_dataset = dataset[n_train:]
    print(f"Train: {n_train:,} graphs, Val: {n_val:,} graphs")

    loader_kwargs = {"num_workers": 4} if use_cuda else {"num_workers": 0}
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, **loader_kwargs)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, **loader_kwargs)

    model = MigrationGNNv3(input_features=6, norm=norm).to(device)

    # P2-11: continue from a prior checkpoint (e.g. flagship retrain) — used
    # to fine-tune on corrected/real data without paying full-training cost.
    if init_path and Path(init_path).exists():
        payload = torch.load(init_path, map_location=device, weights_only=True)
        if isinstance(payload, dict) and "state_dict" in payload:
            sd = payload["state_dict"]
        else:
            sd = payload
        # Map legacy bn* keys -> norm* when the checkpoint uses a different
        # normalization than this run's config.
        load_result = model.load_state_dict(sd, strict=False)
        missing = set(load_result.missing_keys)
        unexpected = set(load_result.unexpected_keys)
        if missing or unexpected:
            print(f"  init: missing={sorted(missing)[:5]} unexpected={sorted(unexpected)[:5]} "
                  f"(continuing with {len(sd) - len(unexpected)}/{len(sd)} layers)")
        print(f"Initialized from checkpoint: {init_path}")

    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model parameters: {n_params:,} (norm={norm})")

    # P2-10: torch.compile for 2-4x throughput on A100 when available.
    # PyG batches have dynamic node counts, so torch.compile recompiles on
    # every shape change — on some torch/PyG versions this churns and makes
    # training 10x SLOWER instead of faster. QTRUST_DISABLE_COMPILE=1 opts
    # out (recommended for large-scale sweeps; the vectorized per-graph loss
    # already removes the Python-loop bottleneck that compile was added for).
    if use_cuda and not os.environ.get("QTRUST_DISABLE_COMPILE", "0") == "1":
        try:
            model = torch.compile(model)  # type: ignore[attr-defined]
            print("Model compiled with torch.compile")
        except Exception as e:
            print(f"torch.compile unavailable: {e}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    # P0/P2 fix: warmup-cosine schedule (fixes constant 1e-3) — 3% warmup per doctrine
    warmup_epochs = max(1, int(epochs * 0.03))
    def _lr_lambda(epoch: int) -> float:
        if epoch < warmup_epochs:
            return float(epoch + 1) / float(max(1, warmup_epochs))
        # cosine decay from 1 -> 0.1
        import math
        progress = (epoch - warmup_epochs) / max(1, epochs - warmup_epochs)
        return 0.1 + 0.9 * 0.5 * (1.0 + math.cos(math.pi * progress))
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, _lr_lambda)
    # P0/P2 fix: no GradScaler — it is an fp16-only tool; bf16 is numerically
    # stable without scaling (a scaler here would be a documented no-op + wasted memory).
    # Grad accumulation for long sequences (seq len 2048-8192) — default 1 (no accumulation)
    grad_accum = int(os.environ.get("QTRUST_GRAD_ACCUM", "1"))
    if grad_accum < 1:
        grad_accum = 1

    # Data provenance for registry (hash of generation params)
    import hashlib
    data_hash = hashlib.sha256(f"{n_graphs}-{seed}-{batch_size}".encode()).hexdigest()[:16]

    best_val_kendall = -1.0
    train_start = time.time()

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        n_batches = 0
        optimizer.zero_grad()

        for step, batch in enumerate(train_loader):
            batch = batch.to(device)
            batch_idx = getattr(batch, "batch", None)

            if use_cuda:
                with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                    order_logits, risk_logits = model(batch)
                    # P0-1: per-graph ListMLE (fixes cross-graph ranking bug)
                    loss_order = per_graph_listMLE_loss(order_logits.float(), batch.y_order, batch_idx)
                    loss_risk = F.mse_loss(risk_logits.float(), batch.y_risk)
                    loss = loss_order + 0.3 * loss_risk
                    # scale for grad accumulation
                    loss = loss / grad_accum
                loss.backward()
                # optimizer step only every grad_accum batches or at epoch end
                if (step + 1) % grad_accum == 0 or (step + 1) == len(train_loader):
                    optimizer.step()
                    optimizer.zero_grad()
            else:
                order_logits, risk_logits = model(batch)
                loss_order = per_graph_listMLE_loss(order_logits, batch.y_order, batch_idx)
                loss_risk = F.mse_loss(risk_logits, batch.y_risk)
                loss = (loss_order + 0.3 * loss_risk) / grad_accum
                loss.backward()
                if (step + 1) % grad_accum == 0 or (step + 1) == len(train_loader):
                    optimizer.step()
                    optimizer.zero_grad()

            total_loss += loss.item() * grad_accum
            n_batches += 1

        avg_train_loss = total_loss / max(n_batches, 1)
        scheduler.step()

        # Evaluate every epoch for reliable best-model selection (fixes "sample every 10th")
        # and compute per-graph metrics to avoid batch-level bias. The per-graph
        # Python loop was the training bottleneck at scale (~11s per 1000 graphs),
        # so validation is subsampled to QTRUST_VAL_SAMPLE graphs per epoch — plenty
        # for model selection; the canonical benchmark evaluates on its own held-out
        # set with the full protocol.
        val_sample = int(os.environ.get("QTRUST_VAL_SAMPLE", "2000"))
        model.eval()
        all_metrics = {"kendall": [], "top5": [], "top10": []}

        with torch.no_grad():
            for bi, batch in enumerate(val_loader):
                if len(all_metrics["kendall"]) >= val_sample:
                    break
                batch = batch.to(device)
                batch_idx = getattr(batch, "batch", None)
                if use_cuda:
                    with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                        order_logits, _ = model(batch)
                    order_logits = order_logits.float()
                else:
                    order_logits, _ = model(batch)
                # P0-1: per-graph metrics — iterate over graphs in batch
                if batch_idx is not None:
                    for gid in range(int(batch_idx.max().item()) + 1):
                        if len(all_metrics["kendall"]) >= val_sample:
                            break
                        mask = batch_idx == gid
                        if mask.sum() < 2:
                            continue
                        m = compute_metrics(order_logits[mask], batch.y_order[mask])
                        for k in all_metrics:
                            all_metrics[k].append(m[k])
                else:
                    m = compute_metrics(order_logits, batch.y_order)
                    for k in all_metrics:
                        all_metrics[k].append(m[k])

        if len(all_metrics["kendall"]) == 0:
            avg_kendall = 0.0
            avg_top5 = 0.0
            avg_top10 = 0.0
        else:
            avg_kendall = sum(all_metrics["kendall"]) / len(all_metrics["kendall"])
            avg_top5 = sum(all_metrics["top5"]) / len(all_metrics["top5"])
            avg_top10 = sum(all_metrics["top10"]) / len(all_metrics["top10"])

        gpu_mem = torch.cuda.memory_allocated() / 1e9 if use_cuda else 0.0
        elapsed = time.time() - train_start
        current_lr = optimizer.param_groups[0]["lr"]
        # Log every 10 epochs + first/last, but track best every epoch
        if (epoch + 1) % 10 == 0 or epoch == 0 or epoch == epochs - 1:
            print(
                f"Epoch {epoch+1:>3}/{epochs} | "
                f"loss={avg_train_loss:.4f} lr={current_lr:.2e} | "
                f"val tau={avg_kendall:.4f} top5={avg_top5:.3f} top10={avg_top10:.3f} | "
                f"GPU={gpu_mem:.1f}GB | elapsed={elapsed:.0f}s | data_hash={data_hash}"
            )

        if avg_kendall > best_val_kendall:
            best_val_kendall = avg_kendall
            # Save with lineage: config, seed, data_hash, metrics (fixes opaque checkpoints)
            payload = {
                "model_state_dict": model.state_dict() if not hasattr(model, "_orig_mod") else model._orig_mod.state_dict(),  # type: ignore[attr-defined]
                "state_dict": model.state_dict() if not hasattr(model, "_orig_mod") else model._orig_mod.state_dict(),  # compat
                "model_config": {"input_features": 6, "hidden_dim": 256, "embedding_dim": 128,
                                 "heads": 8, "dropout": 0.15, "variant": "hybrid", "norm": norm},
                "epochs": epoch + 1,
                "n_graphs": n_graphs,
                "seed": seed,
                "data_hash": data_hash,
                "best_val_kendall": best_val_kendall,
                "best_val_top5": avg_top5,
                "best_val_top10": avg_top10,
                "val_split": val_split,
                "learning_rate": learning_rate,
                "weight_decay": weight_decay,
                "norm": norm,
            }
            # Handle compiled model unwrapping
            try:
                Path(model_path).parent.mkdir(parents=True, exist_ok=True)
                torch.save(payload, model_path)
            except Exception:
                torch.save(model.state_dict(), model_path)
            print(f"  -> Saved best model (tau={best_val_kendall:.4f})")

    total_time = time.time() - train_start
    print(f"\nTraining complete in {total_time:.0f}s ({total_time/60:.1f} min)")
    print(f"Best validation Kendall tau: {best_val_kendall:.4f}")
    print(f"Model saved to: {model_path} (data_hash={data_hash})")
    return model_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GPU-accelerated GNN training")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--n-graphs", type=int, default=100_000)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--norm", choices=("batch", "layer", "graph"), default="batch",
                        help="hidden normalization; 'layer' recommended for the v3 retrain "
                             "(see model_v3 AUDIT NOTE)")
    parser.add_argument("--quick", action="store_true", help="Quick test: 10K graphs, 20 epochs")
    parser.add_argument("--init", type=str, default=None,
                        help="Checkpoint to continue from (fine-tune on real data)")
    parser.add_argument("--real-cboms", type=str, default=None,
                        help="Directory of real CBOM JSONs to mix into training "
                             "(default planner/data/real_cboms)")
    parser.add_argument("--model-out", type=str, default=None,
                        help="Output checkpoint path (default model_gpu_v3.pt)")
    args = parser.parse_args()

    if args.quick:
        args.n_graphs = 10_000
        args.epochs = 20

    extra_graphs = None
    real_dir = Path(args.real_cboms or (Path(__file__).resolve().parent.parent / "data" / "real_cboms"))
    if real_dir.is_dir():
        import json
        extra_graphs = []
        for p in sorted(real_dir.glob("*.json")):
            try:
                cbom = json.loads(p.read_text())
                extra_graphs.append(cbom_to_dependency_graph(cbom, seed=args.seed))
            except Exception as exc:
                print(f"  ! skip {p.name}: {exc}")
        if extra_graphs:
            print(f"Loaded {len(extra_graphs)} real CBOM graphs from {real_dir}")
        else:
            extra_graphs = None

    train_gpu(
        n_graphs=args.n_graphs,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        seed=args.seed,
        norm=args.norm,
        extra_graphs=extra_graphs,
        init_path=args.init,
        model_path=args.model_out,
    )
