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
import logging
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

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

logger = logging.getLogger("qtrust_planner.server")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter backed by Redis, with in-memory fallback.

    Each client IP gets a ZSET key ``rl:{ip}`` of request timestamps, so the
    limit is enforced across all uvicorn workers. When ``QTRUST_REDIS_URL``
    is unset or Redis cannot be reached, falls back to the original
    per-worker in-memory limiter (logged warning, requests never fail).
    Expired entries are trimmed on every call, so no background cleanup is
    needed.
    """

    REDIS_RETRY_SECONDS = 30.0

    def __init__(
        self, app, max_requests: int | None = None, window_seconds: int | None = None,
    ):
        super().__init__(app)
        if max_requests is None:
            max_requests = int(os.environ.get("QTRUST_RATE_LIMIT_MAX", "30"))
        if window_seconds is None:
            window_seconds = int(os.environ.get("QTRUST_RATE_LIMIT_WINDOW", "60"))
        self.max_requests = int(max_requests)
        self.window_seconds = int(window_seconds)
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._redis_url = os.environ.get("QTRUST_REDIS_URL")
        self._redis: Any = None
        self._last_redis_failure = 0.0

    def _warn_fallback(self, reason: str) -> None:
        logger.warning(
            json.dumps({
                "event": "rate_limiter_fallback",
                "level": "WARNING",
                "message": "Redis rate limiter unavailable — using in-memory fallback",
                "reason": reason,
            })
        )

    def _get_redis(self):
        """Return a live Redis client, or None when unavailable.

        Connects lazily on first use; retries at most once per
        REDIS_RETRY_SECONDS after a failure so an outage doesn't spam logs
        or add latency to every request.
        """
        if not self._redis_url:
            return None
        if self._redis is not None:
            return self._redis
        now = time.time()
        if now - self._last_redis_failure < self.REDIS_RETRY_SECONDS:
            return None
        try:
            import redis as redis_lib

            client = redis_lib.Redis.from_url(
                self._redis_url,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
            )
            client.ping()
            self._redis = client
            logger.info(
                json.dumps({
                    "event": "rate_limiter_redis",
                    "level": "INFO",
                    "message": "Rate limiter using Redis sliding window",
                })
            )
            return client
        except Exception as exc:
            self._last_redis_failure = now
            self._warn_fallback(f"{type(exc).__name__}: {exc}")
            return None

    def _redis_check(self, key: str, now: float) -> tuple[bool, int] | None:
        """Sliding-window check via Redis pipeline. Returns (allowed, retry_after).

        Returns None if Redis should be skipped for this request.
        """
        client = self._get_redis()
        if client is None:
            return None
        try:
            cutoff = now - self.window_seconds
            pipe = client.pipeline(transaction=False)
            pipe.zremrangebyscore(key, "-inf", cutoff)  # trim expired entries each call
            pipe.zcard(key)
            count = pipe.execute()[1]
            if count < self.max_requests:
                member = f"{now:.6f}:{uuid.uuid4().hex}"
                pipe = client.pipeline(transaction=False)
                pipe.zadd(key, {member: now})
                pipe.expire(key, self.window_seconds * 2)  # bound growth of idle keys
                pipe.execute()
                return True, 0
            oldest = client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = max(1, int(oldest[0][1] + self.window_seconds - now))
            else:
                retry_after = self.window_seconds
            return False, retry_after
        except Exception as exc:
            # Degrade gracefully: serve this request through the fallback and
            # let _get_redis retry the connection later.
            self._redis = None
            self._last_redis_failure = time.time()
            self._warn_fallback(f"{type(exc).__name__}: {exc}")
            return None

    def _memory_check(self, client_ip: str, now: float) -> tuple[bool, int]:
        """Original in-memory sliding window (per-worker fallback)."""
        cutoff = now - self.window_seconds
        self._requests[client_ip] = [t for t in self._requests[client_ip] if t > cutoff]
        if len(self._requests[client_ip]) >= self.max_requests:
            oldest = min(self._requests[client_ip])
            return False, max(1, int(oldest + self.window_seconds - now))
        self._requests[client_ip].append(now)
        return True, 0

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        outcome = self._redis_check(f"rl:{client_ip}", now)
        if outcome is None:
            outcome = self._memory_check(client_ip, now)
        allowed, retry_after = outcome
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)


app.add_middleware(RateLimitMiddleware)

MODEL_PATH = os.environ.get("QTRUST_MODEL_PATH", str(Path(__file__).resolve().parents[1] / "model.pt"))
DEADLINES_PATH = os.environ.get(
    "QTRUST_DEADLINES_PATH", str(Path(__file__).resolve().parents[1] / "data" / "algorithms.json")
)

_model = None
_model_info: dict[str, Any] = {}
_deadlines: dict[str, Any] = {}


def _warn_heuristic_mode(reason: str) -> None:
    logger.warning(
        json.dumps({
            "event": "planner_heuristic_mode",
            "level": "WARNING",
            "message": "PQC planner weights unavailable — serving heuristic mode",
            "reason": reason,
        })
    )

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
    except ImportError as exc:
        _warn_heuristic_mode(f"torch/model deps not importable: {exc}")
        _model_info = {"mode": "heuristic", "reason": "torch not installed"}
        return

    if not os.path.exists(MODEL_PATH):
        _warn_heuristic_mode(f"model file not found at {MODEL_PATH}")
        _model_info = {"mode": "heuristic", "reason": "model.pt not found"}
        return

    try:
        # nosemgrep — torch.load with weights_only=True: safe deserialization
        checkpoint = torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
        config = checkpoint.get("model_config", {"input_features": 6, "hidden_dim": 64, "embedding_dim": 32})
        state_dict = checkpoint.get("model_state_dict")
        if not isinstance(state_dict, dict) or len(state_dict) == 0:
            raise ValueError("checkpoint contains no usable model_state_dict")
        model = MigrationGNN(**config)
        model.load_state_dict(state_dict)
        model.eval()
        _model = model
        _model_info = {
            "mode": "gnn",
            "path": MODEL_PATH,
            "config": config,
            "eval_metrics": checkpoint.get("eval_metrics", {}),
        }
    except Exception as exc:
        _warn_heuristic_mode(f"model load failed: {type(exc).__name__}: {exc}")
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
        data, asset_records = cbom_to_graph(req.cbom, req.deps)
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


_RL_BUDGET_SECONDS = 2.0
_RL_MODEL_PATH = Path(__file__).resolve().parent / "rl_agent.pt"
_RL_AGENT_CACHE: dict[str, Any] | None = None


def _rl_migration_order(req: PlanRequest) -> tuple[list[dict[str, Any]], str] | None:
    """Greedy-rollout decode with the trained RL agent.

    Returns (migration_order, method) or None when the RL checkpoint is
    missing or torch/PyG are unavailable.
    """
    if not _RL_MODEL_PATH.exists():
        return None

    try:
        import torch
        from qtrust_planner.rl_agent import MigrationAgent
    except ImportError:
        return None

    assets = req.cbom.get("assets", [])
    if not assets:
        raise HTTPException(status_code=422, detail="CBOM has no assets")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # Audit P-08: cache the loaded agent across requests (checkpoint is read
    # once; a 30-80ms disk hit per inference adds up under load).
    global _RL_AGENT_CACHE  # noqa: PLW0603
    cached = _RL_AGENT_CACHE
    if cached is not None and cached["path"] == _RL_MODEL_PATH and cached["device"] == device:
        agent = cached["agent"]
    else:
        agent = MigrationAgent(n_features=6, hidden_dim=128).to(device)
        try:
            agent.load_state_dict(
                # nosemgrep — torch.load with weights_only=True: safe deserialization
                torch.load(str(_RL_MODEL_PATH), map_location=device, weights_only=True)
            )
        except Exception as exc:
            logger.warning("rl_agent checkpoint unusable: %s", exc)
            return None
        agent.eval()
        _RL_AGENT_CACHE = {"path": _RL_MODEL_PATH, "device": device, "agent": agent}

    crit_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    from qtrust_planner.model_v3 import encode_algorithm_type

    records = []
    features = []
    for i, a in enumerate(assets):
        algorithm = a.get("algorithm", "unknown")
        key_size = int(a.get("key_size", 0) or 0)
        criticality = a.get("criticality", "Medium")
        crit = crit_map.get(str(criticality).lower(), 2)
        features.append([
            encode_algorithm_type(algorithm) / 14.0,
            min(key_size / 4096.0, 1.0),
            1.0 if a.get("pqc_ready", False) else 0.0,
            crit / 5.0,
            365.0 / 3650.0,
            0.5,
        ])
        records.append({
            "asset_id": a.get("asset_id", f"asset-{i:04d}"),
            "algorithm": algorithm,
            "host": a.get("host", ""),
            "port": a.get("port", 0),
            "key_size": key_size,
            "criticality": criticality,
            "pqc_ready": bool(a.get("pqc_ready", False)),
        })

    n = len(records)
    x = torch.tensor(features, dtype=torch.float32, device=device)

    dep_pairs: list[tuple[int, int]] = []
    deps = req.deps or {}
    raw_edges = deps.get("edges", []) if isinstance(deps, dict) else []
    for e in raw_edges:
        try:
            b, a_ = int(e[0]), int(e[1])
            if 0 <= b < n and 0 <= a_ < n and b != a_:
                dep_pairs.append((b, a_))
        except (TypeError, ValueError, IndexError, KeyError):
            continue
    if dep_pairs:
        edge_index = torch.tensor(dep_pairs, dtype=torch.long).t().contiguous().to(device)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long, device=device)

    migrated: list[bool] = [False] * n
    order_idx: list[int] = []
    start = time.time()
    with torch.no_grad():
        while len(order_idx) < n:
            if time.time() - start > _RL_BUDGET_SECONDS:
                return None
            policy_logits, _ = agent(x, edge_index)
            mask = torch.full_like(policy_logits, float("-inf"))
            for i in range(n):
                if not migrated[i]:
                    deps_ok = all(migrated[b] for b, tgt in dep_pairs if tgt == i)
                    if deps_ok:
                        mask[i] = 0.0
            if not torch.isfinite(mask).any():
                break
            action = int(torch.argmax(policy_logits + mask).item())
            migrated[action] = True
            order_idx.append(action)

    migration_order: list[dict[str, Any]] = []
    for rank, idx in enumerate(order_idx):
        asset = records[idx]
        migration_order.append({
            "rank": rank + 1,
            **asset,
            "priority_score": float(policy_logits[idx].item()),
            "risk_score": float(_heuristic_risk({**asset, "index": idx})),
            "migrate_days": _estimate_migrate_days(asset["algorithm"], asset["key_size"]),
        })
    return migration_order, "rl_policy"


@app.post("/rl/plan")
def rl_plan(req: PlanRequest) -> dict[str, Any]:
    """Migration plan decoded by the trained RL agent.

    Falls back to heuristic ordering with an honest method label whenever
    the RL checkpoint is absent or inference fails.
    """
    if not _model_info:
        _load_model()

    result = None
    try:
        result = _rl_migration_order(req)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("RL decode failed (%s); falling back to heuristic", exc)

    if result is not None:
        migration_order, method = result
    else:
        assets = req.cbom.get("assets", [])
        if not assets:
            raise HTTPException(status_code=422, detail="CBOM has no assets")
        records = [
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
        scores = [_heuristic_priority(a) for a in records]
        sorted_indices = sorted(range(len(records)), key=lambda i: -scores[i])
        migration_order = []
        for rank, idx in enumerate(sorted_indices):
            asset = records[idx]
            migration_order.append({
                "rank": rank + 1,
                **{k: v for k, v in asset.items() if k != "index"},
                "priority_score": float(scores[idx]),
                "risk_score": float(_heuristic_risk(asset)),
                "migrate_days": _estimate_migrate_days(asset["algorithm"], asset["key_size"]),
            })
        method = "heuristic_fallback"

    deadline_date = None
    if req.deadline:
        try:
            deadline_date = datetime.fromisoformat(req.deadline).date()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="deadline must be ISO date YYYY-MM-DD") from exc

    schedule = None
    if deadline_date:
        schedule = _build_schedule(migration_order, deadline_date)

    return {
        "planner": "qtrust-planner",
        "model": _model_info,
        "method": method,
        "total_assets": len(migration_order),
        "deadline": deadline_date.isoformat() if deadline_date else None,
        "migration_order": migration_order,
        "schedule": schedule,
    }


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
