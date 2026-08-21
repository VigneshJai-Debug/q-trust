"""Q-Trust planner microservice (FastAPI).

Exposes the trained MigrationGNN as an HTTP service so the backend can proxy
migration planning requests to it. Adds deadline-aware scheduling on top of
the GNN priority ordering.

Endpoints:
    GET  /health           — liveness + model info
    POST /plan             — plan a migration from a CBOM (+ optional deadline)
    POST /plan/deadline    — deadline feasibility + schedule
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from torch_geometric.data import Data

from qtrust_planner.model import MigrationGNN, encode_algorithm_type
from qtrust_planner.predict import cbom_to_graph

app = FastAPI(title="Q-Trust Planner", version="0.2.0")

MODEL_PATH = os.environ.get("QTRUST_MODEL_PATH", str(Path(__file__).resolve().parents[1] / "model.pt"))
DEADLINES_PATH = os.environ.get(
    "QTRUST_DEADLINES_PATH", str(Path(__file__).resolve().parents[1] / "data" / "algorithms.json")
)

_model: MigrationGNN | None = None
_model_info: dict[str, Any] = {}
_deadlines: dict[str, Any] = {}

try:
    with open(DEADLINES_PATH, encoding="utf-8") as f:
        _deadlines = json.load(f).get("algorithm_profiles", {})
except FileNotFoundError:
    _deadlines = {}


def _load_model() -> None:
    global _model, _model_info
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train it first (qtrust_planner.train).")
    checkpoint = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
    config = checkpoint.get("model_config", {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32})
    _model = MigrationGNN(**config)
    _model.load_state_dict(checkpoint["model_state_dict"])
    _model.eval()
    _model_info = {
        "path": MODEL_PATH,
        "config": config,
        "eval_metrics": checkpoint.get("eval_metrics", {}),
    }


class PlanRequest(BaseModel):
    cbom: dict[str, Any] = Field(..., description="CBOM JSON (assets list required)")
    deps: dict[str, Any] | None = None
    deadline: str | None = Field(None, description="ISO date (YYYY-MM-DD) of the migration deadline")


class DeadlineRequest(BaseModel):
    cbom: dict[str, Any]
    deadline: str


def _estimate_migrate_days(algorithm: str, key_size: int) -> float:
    """Estimated days of effort to migrate one asset."""
    family = algorithm.split("-")[0] if "-" in algorithm else algorithm
    for name, profile in _deadlines.items():
        if algorithm.upper() == name.upper() or (
            algorithm.upper().startswith(name.upper()) and len(algorithm) <= len(name) + 4
        ):
            return float(profile.get("migrate_days", 1.0))
    if family in ("RSA", "ECC", "DSA", "DH", "ECDH", "ECDSA"):
        return 1.5
    return 0.5


@app.on_event("startup")
def _startup() -> None:
    _load_model()


@app.get("/health")
def health() -> dict[str, Any]:
    if _model is None:
        _load_model()
    return {"status": "ok", "model": _model_info}


@app.post("/plan")
def plan(req: PlanRequest) -> dict[str, Any]:
    if _model is None:
        _load_model()
    try:
        data, asset_records = cbom_to_graph(req.cbom, None if req.deps is None else str(req.deps))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    with torch.no_grad():
        order_logits, risk_logits = _model(data)

    priority_scores = order_logits.cpu().numpy()
    risk_scores = risk_logits.cpu().numpy()
    sorted_indices = sorted(range(len(asset_records)), key=lambda i: -priority_scores[i])

    deadline_date = None
    if req.deadline:
        try:
            deadline_date = datetime.fromisoformat(req.deadline).date()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="deadline must be ISO date YYYY-MM-DD") from exc

    migration_order: list[dict[str, Any]] = []
    for rank, idx in enumerate(sorted_indices):
        asset = asset_records[idx]
        algorithm = asset["algorithm"]
        migrate_days = _estimate_migrate_days(algorithm, asset["key_size"])
        migration_order.append({
            "rank": rank + 1,
            "asset_id": asset["asset_id"],
            "algorithm": algorithm,
            "host": asset["host"],
            "port": asset["port"],
            "key_size": asset["key_size"],
            "criticality": asset["criticality"],
            "pqc_ready": asset["pqc_ready"],
            "priority_score": float(priority_scores[idx]),
            "risk_score": float(risk_scores[idx]),
            "migrate_days": migrate_days,
        })

    schedule = None
    if deadline_date:
        schedule = _build_schedule(migration_order, deadline_date)

    return {
        "planner": "qtrust-planner",
        "model": _model_info,
        "total_assets": len(asset_records),
        "deadline": deadline_date.isoformat() if deadline_date else None,
        "migration_order": migration_order,
        "schedule": schedule,
    }


@app.post("/plan/deadline")
def plan_with_deadline(req: DeadlineRequest) -> dict[str, Any]:
    return plan(PlanRequest(cbom=req.cbom, deadline=req.deadline))


def _build_schedule(migration_order: list[dict[str, Any]], deadline: date) -> dict[str, Any]:
    """Greedy schedule: migrate in GNN order, one asset at a time, backfilled
    from the deadline so the most critical assets finish first.
    """
    today = date.today()
    days_available = max((deadline - today).days, 0)

    total_effort = sum(float(a["migrate_days"]) for a in migration_order)
    feasible = total_effort <= max(days_available, 1)

    # Backfill: last asset ends on the deadline; earlier assets stack behind it.
    cursor = deadline
    windows: list[dict[str, Any]] = []
    for asset in reversed(migration_order):
        effort = timedelta(days=float(asset["migrate_days"]))
        start = cursor - effort
        windows.append({
            "asset_id": asset["asset_id"],
            "start": start.isoformat(),
            "end": cursor.isoformat(),
            "migrate_days": asset["migrate_days"],
        })
        cursor = start

    windows.reverse()
    daily_rate = total_effort / max(days_available, 1) if days_available else None

    return {
        "deadline": deadline.isoformat(),
        "days_available": days_available,
        "total_effort_days": total_effort,
        "feasible": feasible,
        "suggested_daily_rate": round(daily_rate, 2) if daily_rate else None,
        "windows": windows,
    }