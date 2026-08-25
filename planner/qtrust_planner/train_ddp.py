"""Distributed Data Parallel (DDP) GNN training for multi-GPU nodes.

Trains MigrationGNNv3 across N GPUs simultaneously with NCCL, using
4x more data than the single-GPU pipeline (400K graphs by default).

Usage:
    # Launch on 2 free GPUs (recommended when GPUs are shared):
    CUDA_VISIBLE_DEVICES=1,2 torchrun --nproc_per_node=2 \
        -m qtrust_planner.train_ddp --epochs 200 --n-graphs 400000

    # Quick smoke test (no torchrun needed):
    python -m qtrust_planner.train_ddp --quick

    # Plain multi-GPU launch without torchrun (uses mp.spawn):
    CUDA_VISIBLE_DEVICES=1,2 python -m qtrust_planner.train_ddp \
        --epochs 200 --n-graphs 400000

Requires: 2+ NVIDIA GPUs (>=16GB VRAM each) and NCCL.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import torch
import torch.distributed as dist
import torch.multiprocessing as mp
import torch.nn.functional as F
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data.distributed import DistributedSampler

from torch_geometric.loader import DataLoader

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from model_v3 import MigrationGNNv3
    from data_generator import generate_dataset
    from train_gpu import listMLE_loss, compute_metrics
else:
    from .model_v3 import MigrationGNNv3
    from .data_generator import generate_dataset
    from .train_gpu import listMLE_loss, compute_metrics


def _setup(dist_backend_init: bool = True) -> tuple[int, int]:
    """Initialize the process group.

    Under ``torchrun`` the RANK/WORLD_SIZE/MASTER_* env vars are already set;
    in plain ``mp.spawn`` mode we supply localhost defaults.
    """
    if "RANK" not in os.environ:
        os.environ.setdefault("MASTER_ADDR", "localhost")
        os.environ.setdefault("MASTER_PORT", "12355")
    dist.init_process_group("nccl")
    rank = dist.get_rank()
    world_size = dist.get_world_size()
    torch.cuda.set_device(rank % torch.cuda.device_count())
    return rank, world_size


def cleanup() -> None:
    if dist.is_initialized():
        dist.destroy_process_group()


def train_ddp(
    n_graphs: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    weight_decay: float,
    model_path: str,
    seed: int,
    val_split: float = 0.1,
) -> None:
    """Train MigrationGNNv3 across all visible GPUs with DDP."""
    rank, world_size = _setup()
    device = torch.device(f"cuda:{rank}")
    torch.manual_seed(seed)

    if rank == 0:
        print(f"=== DDP Training: {world_size} GPUs ===", flush=True)
        for i in range(torch.cuda.device_count()):
            props = torch.cuda.get_device_properties(i)
            print(f"  cuda:{i} -> {props.name} ({props.total_memory / 1e9:.1f} GB)", flush=True)

    graphs_per_rank = n_graphs // world_size
    if rank == 0:
        print(f"Generating {n_graphs:,} graphs ({graphs_per_rank:,} per GPU)...", flush=True)

    gen_start = time.time()
    dataset = generate_dataset(n_graphs=graphs_per_rank, seed=seed + rank)
    gen_secs = time.time() - gen_start
    if rank == 0:
        print(f"Generation took {gen_secs:.1f}s per GPU", flush=True)

    n_val = max(1, int(len(dataset) * val_split))
    n_train = len(dataset) - n_val
    train_dataset = dataset[:n_train]
    val_dataset = dataset[n_train:]
    if rank == 0:
        print(f"Train: {n_train:,}/rank, Val: {n_val:,}/rank", flush=True)

    sampler = DistributedSampler(
        train_dataset, num_replicas=world_size, rank=rank, shuffle=True
    )
    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, sampler=sampler, num_workers=4
    )
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=2)

    model = MigrationGNNv3(
        input_features=6,
        hidden_dim=256,
        embedding_dim=128,
        heads=8,
        dropout=0.15,
        use_centrality=True,
        variant="hybrid",
    ).to(device)
    if rank == 0:
        print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}", flush=True)

    ddp_model = DDP(model, device_ids=[device.index])
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scaler = torch.amp.GradScaler("cuda")

    best_val_kendall = -1.0
    train_start = time.time()

    for epoch in range(epochs):
        ddp_model.train()
        sampler.set_epoch(epoch)

        total_loss = 0.0
        n_batches = 0

        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()

            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                order_logits, risk_logits = ddp_model(batch)
                loss_order = listMLE_loss(order_logits.float(), batch.y_order)
                loss_risk = F.mse_loss(risk_logits.float(), batch.y_risk)
                loss = loss_order + 0.3 * loss_risk

            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            total_loss += loss.item()
            n_batches += 1

        avg_loss = total_loss / max(n_batches, 1)

        if (epoch + 1) % 10 == 0 or epoch == 0 or epoch == epochs - 1:
            ddp_model.eval()
            all_metrics = {"kendall": [], "top5": [], "top10": []}

            with torch.no_grad():
                for batch in val_loader:
                    batch = batch.to(device)
                    with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                        order_logits, _ = ddp_model(batch)
                    metrics = compute_metrics(order_logits.float(), batch.y_order)
                    for k in all_metrics:
                        all_metrics[k].append(metrics[k])

            local = torch.tensor(
                [sum(all_metrics["kendall"]) / max(len(all_metrics["kendall"]), 1)],
                device=device,
            )
            dist.all_reduce(local, op=dist.ReduceOp.AVG)
            avg_kendall = local.item()

            if rank == 0:
                gpu_mem = torch.cuda.memory_allocated() / 1e9
                elapsed = time.time() - train_start
                print(
                    f"Epoch {epoch + 1:>3}/{epochs} | "
                    f"loss={avg_loss:.4f} | "
                    f"val tau={avg_kendall:.4f} top5={sum(all_metrics['top5']) / len(all_metrics['top5']):.3f} | "
                    f"GPU0={gpu_mem:.1f}GB | {elapsed:.0f}s",
                    flush=True,
                )

                if avg_kendall > best_val_kendall:
                    best_val_kendall = avg_kendall
                    torch.save(model.state_dict(), model_path)
                    print(f"  -> Saved best model (tau={best_val_kendall:.4f})", flush=True)

    if rank == 0:
        total_time = time.time() - train_start
        print(f"\nDDP training complete in {total_time:.0f}s ({total_time / 60:.1f} min)", flush=True)
        print(f"Best validation Kendall tau: {best_val_kendall:.4f}", flush=True)
        print(f"Model saved to: {model_path}", flush=True)
        print(f"Trained on {world_size} GPUs with {n_graphs:,} total graphs", flush=True)

    cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description="Distributed GNN training")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--n-graphs", type=int, default=400_000)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val-split", type=float, default=0.1)
    parser.add_argument(
        "--model-path",
        type=str,
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model_ddp_v3.pt"),
    )
    parser.add_argument("--nproc", type=int, default=0, help="GPUs for plain-script mp.spawn mode (0 = all)")
    parser.add_argument("--quick", action="store_true", help="Quick test: 1K graphs, 10 epochs")
    args = parser.parse_args()

    if args.quick:
        args.n_graphs = min(args.n_graphs, 1000)
        args.epochs = min(args.epochs, 10)

    if "RANK" in os.environ:
        # Launched via torchrun — env vars already describe this rank.
        train_ddp(
            n_graphs=args.n_graphs,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            weight_decay=args.weight_decay,
            model_path=args.model_path,
            seed=args.seed,
            val_split=args.val_split,
        )
        return

    world_size = args.nproc or torch.cuda.device_count()
    if world_size < 2:
        print(f"Only {world_size} visible GPU — falling back to single-GPU trainer.", flush=True)
        from train_gpu import train_gpu as _single

        _single(
            n_graphs=args.n_graphs,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            weight_decay=args.weight_decay,
            seed=args.seed,
            model_path=args.model_path,
        )
        return

    print(f"Launching DDP with {world_size} GPUs (mp.spawn)...", flush=True)
    mp.spawn(
        _spawn_entry,
        args=(world_size, args),
        nprocs=world_size,
        join=True,
    )


def _spawn_entry(rank: int, world_size: int, args: argparse.Namespace) -> None:
    os.environ["RANK"] = str(rank)
    os.environ["WORLD_SIZE"] = str(world_size)
    train_ddp(
        n_graphs=args.n_graphs,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=args.weight_decay,
        model_path=args.model_path,
        seed=args.seed,
        val_split=args.val_split,
    )


if __name__ == "__main__":
    main()
