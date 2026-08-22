"""Q-Trust planner microservice (FastAPI).

Exposes the trained MigrationGNN as an HTTP service so the backend can proxy
migration planning requests to it. Adds deadline-aware scheduling on top of
the GNN priority ordering.

Falls back to a rule-based heuristic when no trained model is available.

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

import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model at startup, cleanup on shutdown."""
    _load_model()
    yield


app = FastAPI(title="Q-Trust Planner", version="0.3.0", lifespan=lifespan)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter: 60 requests per minute per IP."""

    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - self.window_seconds
        self._requests[client_ip] = [t for t in self._requests[client_ip] if t > cutoff]
        if len(self._requests[client_ip]) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )
        self._requests[client_ip].append(now)
        return await call_next(request)


app.add_middleware(RateLimitMiddleware)

MODEL_PATH = os.environ.get("QTRUST_MODEL_PATH", str(Path(__file__).resolve().parents[1] / "model.pt"))
DEADLINES_PATH = os.environ.get(
    "QTRUST_DEADLINES_PATH", str(Path(__file__).resolve().parents[1] / "data" / "algorithms.json")
)

_model = None
_model_info: dict[str, Any] = {}
_deadlines: dict[str, Any] = {}

try:
    with open(DEADLINES_PATH, encoding="utf-8") as f:
        _deadlines = json.load(f).get("algorithm_profiles", {})
except FileNotFoundError:
    _deadlines = {}


def _load_model() -> None:
    global _model, _model_info
    try:
        import torch
        from qtrust_planner.model import MigrationGNN
    except ImportError:
        _model_info = {"mode": "heuristic", "reason": "torch not installed"}
        return

    if not os.path.exists(MODEL_PATH):
        _model_info = {"mode": "heuristic", "reason": "model.pt not found"}
        return

    try:
        checkpoint = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
        config = checkpoint.get("model_config", {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32})
        _model = MigrationGNN(**config)
        _model.load_state_dict(checkpoint["model_state_dict"])
        _model.eval()
        _model_info = {
            "mode": "gnn",
            "path": MODEL_PATH,
            "config": config,
            "eval_metrics": checkpoint.get("eval_metrics", {}),
        }
    except Exception as exc:
        _model_info = {"mode": "heuristic", "reason": f"model load failed: {exc}"}


def _heuristic_priority(asset: dict[str, Any]) -> float:
    """Rule-based priority score for an asset. Higher = migrate first."""
    criticality_map = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    crit = criticality_map.get(asset.get("criticality", "Medium"), 3)
    key_size = asset.get("key_size", 0)
    pqc_ready = asset.get("pqc_ready", False)
    algorithm = asset.get("algorithm", "unknown")
    family = algorithm.split("-")[0] if "-" in algorithm else algorithm

    score = 0.0

    # Criticality contribution (0-5)
    score += crit

    # Non-PQC algorithm bonus
    if not pqc_ready:
        if family in ("RSA", "ECC", "DSA", "DH", "ECDH", "ECDSA"):
            score += 3.0
        elif family in ("EdDSA",):
            score += 2.0
        else:
            score += 1.0

    # Large key bonus
    if key_size >= 4096:
        score += 2.0
    elif key_size >= 2048:
        score += 1.0

    # PQC-ready algorithm deduction (no migration needed)
    if pqc_ready:
        score -= 2.0

    return score


def _heuristic_risk(asset: dict[str, Any]) -> float:
    """Rule-based risk score. Higher = riskier to migrate now."""
    criticality_map = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    crit = criticality_map.get(asset.get("criticality", "Medium"), 3)
    pqc_ready = asset.get("pqc_ready", False)

    if pqc_ready:
        return 0.1
    return crit / 5.0


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


@app.get("/health")
def health() -> dict[str, Any]:
    if not _model_info:
        _load_model()
    return {"status": "ok", "model": _model_info}


@app.post("/plan")
def plan(req: PlanRequest) -> dict[str, Any]:
    if not _model_info:
        _load_model()

    try:
        from qtrust_planner.predict import cbom_to_graph
        data, asset_records = cbom_to_graph(req.cbom, None if req.deps is None else str(req.deps))
    except (ImportError, ValueError) as exc:
        # Fallback: parse CBOM directly without PyG
        assets = req.cbom.get("assets", [])
        if not assets:
            raise HTTPException(status_code=422, detail="CBOM has no assets") from exc
        asset_records = [
            {
                "index": i,
                "asset_id": a.get("asset_id", f"asset-{i:04d}"),
                "algorithm": a.get("algorithm", "unknown"),
                "host": a.get("host", ""),
                "port": a.get("port", 0),
                "key_size": int(a.get("key_size", 0) or 0),
                "criticality": a.get("criticality", "Medium"),
                "pqc_ready": bool(a.get("pqc_ready", False)),
            }
            for i, a in enumerate(assets)
        ]

    use_gnn = _model is not None

    if use_gnn:
        import torch
        with torch.no_grad():
            order_logits, risk_logits = _model(data)
        priority_scores = order_logits.cpu().numpy()
        risk_scores = risk_logits.cpu().numpy()
    else:
        priority_scores = [_heuristic_priority(a) for a in asset_records]
        risk_scores = [_heuristic_risk(a) for a in asset_records]

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
            "host": asset.get("host", ""),
            "port": asset.get("port", 0),
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
    """Greedy schedule: migrate in priority order, one asset at a time, backfilled
    from the deadline so the most critical assets finish first.
    """
    today = date.today()
    days_available = max((deadline - today).days, 0)

    total_effort = sum(float(a["migrate_days"]) for a in migration_order)
    feasible = total_effort <= max(days_available, 1)

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
