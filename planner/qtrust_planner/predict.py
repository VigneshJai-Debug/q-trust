"""Prediction script for the MigrationGNN.

Loads a trained model and a CBOM JSON file + dependency graph, and outputs a
recommended migration order (list of asset IDs sorted by priority).

Usage:
    python -m qtrust_planner.predict cbom.json
    python -m qtrust_planner.predict cbom.json --model-path model.pt --deps deps.json

The CBOM JSON is produced by `cryptography-inspector scan`. The optional
`deps.json` file describes the dependency graph; if absent, we infer a trivial
dependency graph (every asset is independent).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import torch
from torch_geometric.data import Data

# Support running as a script or as a module.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from model import MigrationGNN, encode_algorithm_type
else:
    from .model import MigrationGNN, encode_algorithm_type


DEFAULT_MODEL_PATH = str(Path(__file__).resolve().parents[1] / "model.pt")

logger = logging.getLogger("qtrust_planner.predict")

_DEFAULT_GNN_CONFIG = {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32}


def _warn_heuristic_mode(reason: str) -> None:
    """Emit a structured warning whenever trained weights are unavailable."""
    logger.warning(
        json.dumps({
            "event": "planner_heuristic_mode",
            "level": "WARNING",
            "message": "PQC planner weights unavailable — serving heuristic mode",
            "reason": reason,
        })
    )


def _load_trained_model(model_path: str) -> tuple[Any, dict[str, Any]]:
    """Load the MigrationGNN checkpoint. Either fully succeeds or raises —
    there is no partial/silent-load path.
    """
    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    config = checkpoint.get("model_config", _DEFAULT_GNN_CONFIG)
    state_dict = checkpoint.get("model_state_dict")
    if not isinstance(state_dict, dict) or len(state_dict) == 0:
        raise ValueError("checkpoint contains no usable model_state_dict")
    model = MigrationGNN(**config)
    model.load_state_dict(state_dict)
    model.eval()
    return model, checkpoint


def load_cbom(cbom_path: str) -> dict[str, Any]:
    """Load a CBOM JSON file."""
    with open(cbom_path, encoding="utf-8") as f:
        return json.load(f)


def load_dependency_graph(deps_path: str | None, n_assets: int) -> list[list[int]]:
    """Load or synthesize a dependency graph.

    Args:
        deps_path: Path to a deps.json file, or None.
        n_assets: Number of assets (used to synthesize a trivial graph).

    Returns:
        A list of [source, target] pairs where target depends on source
        (i.e., source must be migrated before target).
    """
    if deps_path and os.path.exists(deps_path):
        with open(deps_path, encoding="utf-8") as f:
            deps_data = json.load(f)
        return [[d["source"], d["target"]] for d in deps_data.get("dependencies", [])]

    # Synthesize a trivial graph: asset 0 is a root that everything depends on.
    # This is a sensible default for orgs without an explicit dependency map.
    edges: list[list[int]] = []
    for i in range(1, n_assets):
        edges.append([0, i])
    return edges


def cbom_to_graph(cbom: dict[str, Any], deps_path: str | None = None) -> tuple[Data, list[dict]]:
    """Convert a CBOM JSON + dependency file into a PyG Data object.

    Args:
        cbom: The CBOM dict (from load_cbom).
        deps_path: Optional path to a dependency JSON file.

    Returns:
        A tuple of (Data object, list of asset dicts with IDs).
    """
    assets = cbom.get("assets", [])
    n = len(assets)
    if n == 0:
        raise ValueError("CBOM has no assets to plan a migration for.")

    # Graph-level deadline (days) drives features 5-6. Absent -> 0 (no pressure).
    days_to_deadline = float(cbom.get("days_to_deadline", 0) or 0)
    deadline_pressure = 2.0 if 0 < days_to_deadline < 180 else (1.0 if days_to_deadline > 0 else 0.0)

    # Build node features
    features = torch.zeros((n, 6), dtype=torch.float32)
    asset_records: list[dict] = []

    for i, asset in enumerate(assets):
        algorithm = asset.get("algorithm", "unknown")
        # Extract the algorithm family (e.g. "RSA-2048" -> "RSA")
        family = algorithm.split("-")[0] if "-" in algorithm else algorithm
        type_code = encode_algorithm_type(family)

        key_size = int(asset.get("key_size", 0) or 0)
        vendor_pqc_ready = bool(asset.get("pqc_ready", False))
        criticality_map = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        criticality = criticality_map.get(asset.get("criticality", "Medium"), 3)
        required_rate = min(deadline_pressure * criticality / 5.0, 1.0)

        features[i] = torch.tensor([
            type_code / 14.0,
            min(key_size / 4096.0, 1.0),
            1.0 if vendor_pqc_ready else 0.0,
            criticality / 5.0,
            min(days_to_deadline / 730.0, 1.0),
            required_rate,
        ], dtype=torch.float32)

        asset_records.append({
            "index": i,
            "asset_id": asset.get("asset_id", f"asset-{i:04d}"),
            "algorithm": algorithm,
            "host": asset.get("host", ""),
            "port": asset.get("port", 0),
            "key_size": key_size,
            "criticality": asset.get("criticality", "Medium"),
            "pqc_ready": vendor_pqc_ready,
        })

    # Build edge index
    edges = load_dependency_graph(deps_path, n)
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    data = Data(x=features, edge_index=edge_index)
    data.asset_records = asset_records  # type: ignore[attr-defined]
    return data, asset_records


def _heuristic_priority(asset: dict[str, Any]) -> float:
    """Rule-based priority score for an asset record. Higher = migrate first."""
    criticality_weights = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    crit = criticality_weights.get(asset.get("criticality", "Medium"), 3)
    key_size = int(asset.get("key_size", 0) or 0)
    pqc_ready = bool(asset.get("pqc_ready", False))
    algorithm = asset.get("algorithm", "unknown")
    family = algorithm.split("-")[0] if "-" in algorithm else algorithm

    score = float(crit)
    if not pqc_ready:
        if family in ("RSA", "ECC", "DSA", "DH", "ECDH", "ECDSA"):
            score += 3.0
        elif family in ("EdDSA",):
            score += 2.0
        else:
            score += 1.0
    if key_size >= 4096:
        score += 2.0
    elif key_size >= 2048:
        score += 1.0
    if pqc_ready:
        score -= 2.0
    return score


def _heuristic_risk(asset: dict[str, Any]) -> float:
    """Rule-based risk score. Higher = riskier to migrate now."""
    criticality_weights = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    crit = criticality_weights.get(asset.get("criticality", "Medium"), 3)
    if bool(asset.get("pqc_ready", False)):
        return 0.1
    return crit / 5.0


def predict_migration_order(cbom_path: str, model_path: str = DEFAULT_MODEL_PATH) -> list[str]:
    """Predict the recommended migration order for a CBOM.

    Uses the trained GNN when the checkpoint exists and loads cleanly;
    otherwise serves an explicit, logged heuristic ordering.

    Args:
        cbom_path: Path to a CBOM JSON file.
        model_path: Path to the trained model checkpoint.

    Returns:
        A list of asset IDs sorted by priority (migrate first -> last).
    """
    cbom = load_cbom(cbom_path)
    data, asset_records = cbom_to_graph(cbom)

    if not os.path.exists(model_path):
        _warn_heuristic_mode(f"model file not found at {model_path}")
        return _heuristic_order(asset_records)

    try:
        model, _checkpoint = _load_trained_model(model_path)
    except Exception as exc:  # noqa: BLE001 - any load failure degrades to heuristic mode
        _warn_heuristic_mode(f"model load failed: {type(exc).__name__}: {exc}")
        return _heuristic_order(asset_records)

    with torch.no_grad():
        order_logits, _risk_logits = model(data)

    priority_scores = order_logits.cpu().numpy()

    sorted_indices = sorted(range(len(asset_records)), key=lambda i: -priority_scores[i])

    return [asset_records[i]["asset_id"] for i in sorted_indices]


def _heuristic_order(asset_records: list[dict[str, Any]]) -> list[str]:
    indices = sorted(range(len(asset_records)), key=lambda i: -_heuristic_priority(asset_records[i]))
    return [asset_records[i]["asset_id"] for i in indices]


def predict_detailed(
    cbom_path: str,
    model_path: str = DEFAULT_MODEL_PATH,
    deps_path: str | None = None,
) -> dict[str, Any]:
    """Predict a detailed migration plan including risk scores.

    Args:
        cbom_path: Path to a CBOM JSON file.
        model_path: Path to the trained model checkpoint.
        deps_path: Optional path to a dependency JSON file.

    Returns:
        A dict with: migration_order (list of dicts), total_assets, model_info.
    """
    cbom = load_cbom(cbom_path)
    data, asset_records = cbom_to_graph(cbom, deps_path)

    if not os.path.exists(model_path):
        _warn_heuristic_mode(f"model file not found at {model_path}")
        return _heuristic_detailed(cbom, asset_records, model_path)

    try:
        model, checkpoint = _load_trained_model(model_path)
    except Exception as exc:  # noqa: BLE001 - any load failure degrades to heuristic mode
        _warn_heuristic_mode(f"model load failed: {type(exc).__name__}: {exc}")
        return _heuristic_detailed(cbom, asset_records, model_path)

    with torch.no_grad():
        order_logits, risk_logits = model(data)

    priority_scores = order_logits.cpu().numpy()
    risk_scores = risk_logits.cpu().numpy()

    sorted_indices = sorted(range(len(asset_records)), key=lambda i: -priority_scores[i])

    migration_order = []
    for rank, idx in enumerate(sorted_indices):
        asset = asset_records[idx]
        migration_order.append({
            "rank": rank + 1,
            "asset_id": asset["asset_id"],
            "algorithm": asset["algorithm"],
            "host": asset["host"],
            "port": asset["port"],
            "key_size": asset["key_size"],
            "criticality": asset["criticality"],
            "pqc_ready": asset["pqc_ready"],
            "priority_score": float(priority_scores[idx]),
            "risk_score": float(risk_scores[idx]),
        })

    eval_metrics = checkpoint.get("eval_metrics", {})
    model_accuracy = eval_metrics.get("kendall", checkpoint.get("final_accuracy", 0.0))
    return {
        "mode": "gnn",
        "model_path": model_path,
        "model_accuracy": float(model_accuracy),
        "model_metrics": {k: float(v) for k, v in eval_metrics.items()},
        "cbom_schema": cbom.get("schema_version", "unknown"),
        "total_assets": len(asset_records),
        "migration_order": migration_order,
    }


def _heuristic_detailed(
    cbom: dict[str, Any],
    asset_records: list[dict[str, Any]],
    model_path: str,
) -> dict[str, Any]:
    """Build a detailed plan using rule-based scores (no trained weights)."""
    scored = [(_heuristic_priority(a), _heuristic_risk(a)) for a in asset_records]
    sorted_indices = sorted(range(len(asset_records)), key=lambda i: -scored[i][0])

    migration_order = []
    for rank, idx in enumerate(sorted_indices):
        asset = asset_records[idx]
        migration_order.append({
            "rank": rank + 1,
            "asset_id": asset["asset_id"],
            "algorithm": asset["algorithm"],
            "host": asset.get("host", ""),
            "port": asset.get("port", 0),
            "key_size": asset["key_size"],
            "criticality": asset["criticality"],
            "pqc_ready": asset["pqc_ready"],
            "priority_score": float(scored[idx][0]),
            "risk_score": float(scored[idx][1]),
        })

    return {
        "mode": "heuristic",
        "model_path": model_path,
        "model_accuracy": 0.0,
        "model_metrics": {},
        "cbom_schema": cbom.get("schema_version", "unknown"),
        "total_assets": len(asset_records),
        "migration_order": migration_order,
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Predict migration order from a CBOM.")
    parser.add_argument("cbom_path", help="Path to a CBOM JSON file.")
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to trained model.")
    parser.add_argument("--deps", default=None, help="Optional path to dependency JSON.")
    parser.add_argument(
        "--detailed", action="store_true", help="Print detailed plan with risk scores."
    )
    args = parser.parse_args()

    if args.detailed:
        result = predict_detailed(args.cbom_path, args.model_path, args.deps)
        print(json.dumps(result, indent=2))
    else:
        order = predict_migration_order(args.cbom_path, args.model_path)
        print(json.dumps({"migration_order": order}, indent=2))


if __name__ == "__main__":
    main()
