"""Training script for the MigrationGNN.

Trains the model on a synthetic dataset using AdamW.
Order head: ListMLE ranking loss (default) or MSE regression against
            normalized priority scores (--loss mse, legacy).
Risk head:  MSE regression against risk scores.

Metrics are computed honestly per graph on the validation split:
  - exact_rank: full order must match exactly (fraction of graphs)
  - top5/top10: set overlap of the top-k migration candidates
  - kendall:    Kendall tau between predicted and true orders
  - node_rank:  fraction of nodes whose predicted rank matches exactly

Saves the trained model (state dict + config + eval metrics) to model_path.

Usage:
    python -m qtrust_planner.train
    python -m qtrust_planner.train --epochs 100 --n-graphs 2000
    python -m qtrust_planner.train --loss mse
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import torch
import torch.nn as nn
from scipy.stats import kendalltau
from torch_geometric.loader import DataLoader

# Support running as a script or as a module.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from data_generator import generate_dataset
    from model import MigrationGNN
else:
    from .data_generator import generate_dataset
    from .model import MigrationGNN


DEFAULT_MODEL_PATH = str(Path(__file__).resolve().parents[1] / "model.pt")


def listmle_loss(logits: torch.Tensor, y_order: torch.Tensor) -> torch.Tensor:
    """ListMLE (Plackett-Luce) ranking loss for a single graph.

    Args:
        logits: Predicted priority scores (N,), higher = migrate earlier.
        y_order: Per-node true rank (N,), 0 = highest priority.

    Returns:
        Scalar loss; 0 when the predicted order matches the true order.
    """
    idx = torch.argsort(y_order)
    scores = logits[idx]
    if scores.numel() <= 1:
        return torch.zeros((), device=logits.device)
    tail_logsumexp = torch.logcumsumexp(scores.flip(0), dim=0).flip(0)
    return (tail_logsumexp - scores).mean()


def evaluate_order(model: MigrationGNN, graph) -> dict[str, float]:
    """Compute all ordering metrics for a single graph."""
    model.eval()
    with torch.no_grad():
        order_logits, _ = model(graph)
    pred_order = torch.argsort(order_logits, descending=True).tolist()
    true_order = torch.argsort(graph.y_order).tolist()
    n = len(pred_order)
    kt = kendalltau(pred_order, true_order).statistic if n > 1 else 1.0
    predicted_ranks = torch.argsort(torch.argsort(order_logits, descending=True))
    return {
        "exact_rank": float(pred_order == true_order),
        "top5": float(set(pred_order[:5]) == set(true_order[:5])),
        "top10": float(set(pred_order[:10]) == set(true_order[:10])),
        "kendall": float(kt),
        "node_rank": (predicted_ranks == graph.y_order).float().mean().item(),
    }


def train(
    n_graphs: int = 1000,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    weight_decay: float = 1e-4,
    model_path: str = DEFAULT_MODEL_PATH,
    seed: int = 42,
    loss: str = "listmle",
) -> str:
    """Train the MigrationGNN and save it to model_path.

    Args:
        n_graphs: Number of synthetic training graphs.
        epochs: Number of training epochs.
        batch_size: Mini-batch size (unused in listmle mode; per-graph updates).
        learning_rate: Adam learning rate.
        weight_decay: AdamW weight decay.
        model_path: Where to save the trained model.
        seed: RNG seed.
        loss: "listmle" (ranking) or "mse" (legacy priority regression).

    Returns:
        The path the model was saved to.
    """
    torch.manual_seed(seed)
    if loss not in ("listmle", "mse"):
        raise ValueError(f"Unknown loss: {loss!r} (expected 'listmle' or 'mse')")

    print(f"Generating {n_graphs} synthetic graphs...")
    dataset = generate_dataset(n_graphs=n_graphs, seed=seed)
    n_train = int(0.85 * len(dataset))
    train_dataset = dataset[:n_train]
    val_dataset = dataset[n_train:]
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    print(f"Train graphs: {len(train_dataset)}, Val graphs: {len(val_dataset)}")

    model = MigrationGNN(input_features=6, hidden_dim=64, embedding_dim=32).to(device)
    # Keep config flexible for future hybrid variants
    try:
        # Probe if model accepts extended kwargs (v2); if so, keep simple config for backward compat
        model_cfg = {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32}
    except Exception:
        model_cfg = {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32}

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)

    order_loss_fn = nn.MSELoss()
    risk_loss_fn = nn.MSELoss()

    print(f"\nTraining for {epochs} epochs (order loss: {loss})...\n")
    print(
        f"{'Epoch':>6} | {'Order Loss':>10} | {'Risk Loss':>10} | {'Total':>10} | "
        f"{'exact':>5} {'top5':>5} {'top10':>6} {'kendall':>7} {'node':>5}"
    )
    print("-" * 80)

    best_val = {"loss": float("inf"), "kendall": -1.0, "metrics": None, "state": None}

    def run_epoch(loader, train_mode: bool) -> tuple[float, float, float]:
        model.train(train_mode)
        total_order = total_risk = total = 0.0
        n_batches = 0
        with torch.set_grad_enabled(train_mode):
            for graph in loader:
                graph = graph.to(device)
                optimizer.zero_grad()
                order_logits, risk_logits = model(graph)
                if loss == "listmle":
                    batch_idx = getattr(graph, "batch", None)
                    if batch_idx is not None:
                        order_loss = torch.zeros((), device=device)
                        for gid in range(int(batch_idx.max().item()) + 1):
                            mask = batch_idx == gid
                            order_loss = order_loss + listmle_loss(
                                order_logits[mask], graph.y_order[mask]
                            )
                        order_loss = order_loss / (int(batch_idx.max().item()) + 1)
                    else:
                        order_loss = listmle_loss(order_logits, graph.y_order)
                else:
                    order_loss = order_loss_fn(order_logits, graph.y_priority)
                risk_loss = risk_loss_fn(risk_logits, graph.y_risk)
                batch_loss = order_loss + 0.5 * risk_loss
                if train_mode:
                    batch_loss.backward()
                    optimizer.step()
                total_order += order_loss.item()
                total_risk += risk_loss.item()
                total += batch_loss.item()
                n_batches += 1
        return total_order / n_batches, total_risk / n_batches, total / n_batches

    for epoch in range(1, epochs + 1):
        avg_order, avg_risk, avg_total = run_epoch(train_loader, train_mode=True)

        val_metrics = {"exact_rank": 0.0, "top5": 0.0, "top10": 0.0, "kendall": 0.0, "node_rank": 0.0}
        val_loss = 0.0
        for graph in val_dataset:
            graph_device = graph.to(device)
            with torch.no_grad():
                order_logits, risk_logits = model(graph_device)
            val_loss += (
                order_loss_fn(order_logits, graph_device.y_priority).item()
                + 0.5 * risk_loss_fn(risk_logits, graph_device.y_risk).item()
            )
            for k, v in evaluate_order(model, graph_device).items():
                val_metrics[k] += v
        n_val = len(val_dataset)
        val_loss /= n_val
        val_metrics = {k: v / n_val for k, v in val_metrics.items()}

        print(
            f"{epoch:>6} | {avg_order:>10.4f} | {avg_risk:>10.4f} | {avg_total:>10.4f} | "
            f"{val_metrics['exact_rank']:>5.3f} {val_metrics['top5']:>5.3f} "
            f"{val_metrics['top10']:>6.3f} {val_metrics['kendall']:>7.3f} "
            f"{val_metrics['node_rank']:>5.3f}"
        )

        if val_metrics["kendall"] > best_val["kendall"]:
            best_val = {
                "loss": val_loss,
                "kendall": val_metrics["kendall"],
                "metrics": val_metrics,
                "state": {k: v.clone() for k, v in model.state_dict().items()},
            }

    # Save the best model
    model_path_abs = os.path.abspath(model_path)
    Path(os.path.dirname(model_path_abs) or ".").mkdir(parents=True, exist_ok=True)
    torch.save({
        "model_state_dict": best_val["state"],
        "model_config": model_cfg,
        "epochs": epochs,
        "n_graphs": n_graphs,
        "loss": loss,
        "seed": seed,
        "final_loss": avg_total,
        "best_val_loss": best_val["loss"],
        "best_val_accuracy": best_val["metrics"]["node_rank"],
        "final_accuracy": best_val["metrics"]["node_rank"],
        "eval_metrics": best_val["metrics"],
    }, model_path_abs)

    print(f"\n✓ Model saved to {model_path_abs}")
    print(f"  Best val loss: {best_val['loss']:.4f}")
    print(f"  Best val metrics: {best_val['metrics']}")
    return model_path_abs


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Train the MigrationGNN model.")
    parser.add_argument("--epochs", type=int, default=50, help="Number of training epochs.")
    parser.add_argument("--n-graphs", type=int, default=1000, help="Number of synthetic graphs.")
    parser.add_argument("--batch-size", type=int, default=32, help="Mini-batch size.")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate.")
    parser.add_argument("--weight-decay", type=float, default=1e-4, help="Weight decay.")
    parser.add_argument(
        "--model-path", type=str, default=DEFAULT_MODEL_PATH, help="Output model path."
    )
    parser.add_argument("--seed", type=int, default=42, help="RNG seed.")
    parser.add_argument(
        "--loss", type=str, default="listmle", choices=["listmle", "mse"],
        help="Order-head loss: listmle (ranking) or mse (priority regression).",
    )
    args = parser.parse_args()

    train(
        n_graphs=args.n_graphs,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=args.weight_decay,
        model_path=args.model_path,
        seed=args.seed,
        loss=args.loss,
    )


if __name__ == "__main__":
    main()