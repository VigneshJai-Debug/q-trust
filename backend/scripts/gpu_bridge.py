"""GPU feature bridge — stdin-JSON in, single-line JSON out.

Invoked by the backend as:
    python3 gpu_bridge.py <subcommand>   < payload.json

Subcommands: status | side-channel | analyze is side-channel; anomaly;
quantum-estimate. All request data arrives via stdin (never argv
interpolation). Exit codes: 0 ok, 1 generic error, 3 untrained detector.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[2]
for sub in ("inspector", "planner"):
    pkg_dir = _REPO_ROOT / sub
    marker = "qtrust_inspector" if sub == "inspector" else "qtrust_planner"
    if (pkg_dir / marker).exists() and str(pkg_dir) not in sys.path:
        sys.path.insert(0, str(pkg_dir))


def _emit(payload: dict, code: int = 0) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def _read_payload() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("payload must be a JSON object")
    return data


def cmd_status(_payload: dict) -> None:
    info = {"available": False, "device_name": None, "memory_total_gb": None, "models_loaded": []}
    try:
        import torch

        if torch.cuda.is_available():
            props = torch.cuda.get_device_properties(0)
            # P2-11 fix: report real model state instead of hardcoded empty list
            models_loaded: list[str] = []
            # Planner models
            for env_key, label in [
                ("QTRUST_MODEL_PATH", "planner_v2"),
                ("QTRUST_MODEL_PATH_V3", "planner_v3_gpu"),
                ("QTRUST_MODEL_PATH_DDP", "planner_v3_ddp"),
                ("QTRUST_PLANNER_MODEL_REAL", "planner_v3_real"),
                ("QTRUST_PLANNER_MODEL", "planner_generic"),
            ]:
                p = os.environ.get(env_key, "")
                if p and os.path.exists(p):
                    models_loaded.append(label + ":" + os.path.basename(p))
            # Inspect fallbacks — check common locations
            for p, label in [
                (os.environ.get("QTRUST_SIDE_CHANNEL_MODEL", ""), "side_channel"),
                (os.environ.get("QTRUST_ANOMALY_MODEL", ""), "anomaly"),
                (_REPO_ROOT / "inspector" / "side_channel_model.pt", "side_channel_default"),
                (_REPO_ROOT / "inspector" / "anomaly_model.pt", "anomaly_default"),
                (_REPO_ROOT / "planner" / "model.pt", "planner_v2_default"),
                (_REPO_ROOT / "planner" / "model_gpu_v3.pt", "planner_v3_default"),
                (_REPO_ROOT / "planner" / "model_ddp_v3.pt", "planner_ddp_default"),
                (_REPO_ROOT / "planner" / "rl_agent.pt", "rl_agent_default"),
            ]:
                try:
                    if str(p) and os.path.exists(str(p)) and str(p) not in [os.environ.get(k, "") for k in ("QTRUST_MODEL_PATH","QTRUST_MODEL_PATH_V3","QTRUST_MODEL_PATH_DDP","QTRUST_PLANNER_MODEL_REAL","QTRUST_SIDE_CHANNEL_MODEL","QTRUST_ANOMALY_MODEL")]:
                        # Avoid duplicates, only add if file exists and not already counted via env var
                        models_loaded.append(label)
                except Exception:
                    pass
            # Also try importing and checking loaded state
            try:
                from qtrust_inspector.side_channel import SideChannelAnalyzer
                # Check if default model would load
                default_sc = str(_REPO_ROOT / "inspector" / "side_channel_model.pt")
                if os.path.exists(default_sc):
                    try:
                        a = SideChannelAnalyzer(model_path=default_sc)
                        if a.model_trained:
                            if "side_channel_default" not in models_loaded:
                                models_loaded.append("side_channel_default")
                    except Exception:
                        pass
            except Exception:
                pass
            info = {
                "available": True,
                "device_name": props.name,
                "memory_total_gb": round(props.total_memory / 1e9, 1),
                "models_loaded": sorted(set(models_loaded)),
            }
        else:
            # Even without GPU, report CPU-available models
            models_loaded: list[str] = []
            for p, label in [
                (_REPO_ROOT / "inspector" / "side_channel_model.pt", "side_channel_cpu"),
                (_REPO_ROOT / "inspector" / "anomaly_model.pt", "anomaly_cpu"),
                (_REPO_ROOT / "planner" / "model.pt", "planner_v2_cpu"),
                (_REPO_ROOT / "planner" / "model_gpu_v3.pt", "planner_v3_cpu"),
            ]:
                if os.path.exists(str(p)):
                    models_loaded.append(label)
            info = {"available": False, "device_name": None, "memory_total_gb": None, "models_loaded": sorted(set(models_loaded))}
    except Exception:
        pass
    _emit(info)


def cmd_side_channel(payload: dict) -> None:
    simulated = bool(payload.get("simulated", True))
    n_traces = int(payload.get("n_traces", 10_000))
    seed = int(payload.get("seed", 42))

    analyzer = _get_side_channel_analyzer()
    if not analyzer.model_trained:
        _emit({"error": "untrained_detector"}, 3)

    if simulated:
        result = analyzer.analyze_simulated(
            leakage_prob=float(payload.get("leakage_prob", 0.0)),
            n_traces=n_traces,
            seed=seed,
        )
    else:
        cmd = payload.get("implementation_cmd")
        if not isinstance(cmd, list) or not cmd or not all(isinstance(c, str) for c in cmd):
            raise ValueError("implementation_cmd must be a non-empty array of strings")
        result = analyzer.analyze_implementation(cmd, n_traces=n_traces)

    _emit({
        "implementation": result.implementation,
        "traces_collected": result.traces_collected,
        "leakage_probability": result.leakage_probability,
        "verdict": result.verdict,
        "evidence_hash": result.evidence_hash,
        "timestamp": result.timestamp,
        "gpu_used": result.gpu_used,
    })


def cmd_anomaly(payload: dict) -> None:
    cbom = payload.get("cbom")
    if not isinstance(cbom, dict):
        raise ValueError("cbom object is required")

    detector = _get_anomaly_detector()
    if not detector.trained:
        _emit({"error": "untrained_detector"}, 3)

    result = detector.score_cbom(cbom)
    _emit({
        "anomaly_score": result.anomaly_score,
        "is_anomalous": result.is_anomalous,
        "threshold": result.threshold,
        "asset_count": result.asset_count,
        "top_anomalous_assets": result.top_anomalous_assets,
        "evidence_hash": result.evidence_hash,
        "timestamp": result.timestamp,
    })


def cmd_quantum_estimate(payload: dict) -> None:
    from qtrust_planner.quantum_estimator import QuantumThreatEstimator

    bits = int(payload.get("bits", 0))
    est = QuantumThreatEstimator().estimate_qubits_for_rsa(bits)
    _emit({
        "rsa_key_size": est.rsa_key_size,
        "logical_qubits_needed": est.logical_qubits_needed,
        "physical_qubits_needed": est.physical_qubits_needed,
        "estimated_breakable_year": est.estimated_breakable_year,
        "based_on": est.based_on,
    })


# P2-11: warm model cache so repeated spawns within same process don't reload weights
_SIDE_CHANNEL_CACHE: dict = {}
_ANOMALY_CACHE: dict = {}

def _get_side_channel_analyzer():
    """Return cached analyzer, loading once."""
    key = os.environ.get("QTRUST_SIDE_CHANNEL_MODEL", "") or str(_REPO_ROOT / "inspector" / "side_channel_model.pt")
    if key in _SIDE_CHANNEL_CACHE:
        return _SIDE_CHANNEL_CACHE[key]
    from qtrust_inspector.side_channel import SideChannelAnalyzer
    # Try explicit env path first
    model_path = os.environ.get("QTRUST_SIDE_CHANNEL_MODEL", "")
    if model_path and os.path.exists(model_path):
        a = SideChannelAnalyzer(model_path=model_path)
    elif os.path.exists(str(_REPO_ROOT / "inspector" / "side_channel_model.pt")):
        a = SideChannelAnalyzer(model_path=str(_REPO_ROOT / "inspector" / "side_channel_model.pt"))
    else:
        a = SideChannelAnalyzer()
    _SIDE_CHANNEL_CACHE[key] = a
    return a

def _get_anomaly_detector():
    key = os.environ.get("QTRUST_ANOMALY_MODEL", "") or str(_REPO_ROOT / "inspector" / "anomaly_model.pt")
    if key in _ANOMALY_CACHE:
        return _ANOMALY_CACHE[key]
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector
    model_path = os.environ.get("QTRUST_ANOMALY_MODEL", "")
    if model_path and os.path.exists(model_path):
        d = CBOMAnomalyDetector(model_path=model_path)
    elif os.path.exists(str(_REPO_ROOT / "inspector" / "anomaly_model.pt")):
        d = CBOMAnomalyDetector(model_path=str(_REPO_ROOT / "inspector" / "anomaly_model.pt"))
    else:
        d = CBOMAnomalyDetector()
    _ANOMALY_CACHE[key] = d
    return d


def cmd_daemon(_payload: dict) -> None:
    """P2-11 persistent inference service — warm models, single process, line-delimited JSON.

    Protocol: backend spawns ``python3 gpu_bridge.py daemon`` and then for each
    request writes one JSON line: {"id": str, "cmd": "side-channel"|"anomaly"|"status"|"quantum-estimate", "payload": {...}}
    and reads one response line: {"id": str, "code": int, "result": {...}}.
    The daemon keeps models loaded between requests; torch import and CUDA init happen once.
    """
    import sys
    # Warm models eagerly so first request is fast
    try:
        _get_side_channel_analyzer()
    except Exception:
        pass
    try:
        _get_anomaly_detector()
    except Exception:
        pass
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            req_id = msg.get("id", "0")
            cmd = msg.get("cmd")
            payload = msg.get("payload", {})
            if cmd not in _COMMANDS:
                resp = {"id": req_id, "code": 1, "result": {"error": f"unknown cmd {cmd}"}}
            else:
                # Capture _emit without exiting
                import io
                old_stdout = sys.stdout
                buf = io.StringIO()
                try:
                    # Temporarily redirect _emit to capture
                    def _capture(payload: dict, code: int = 0):
                        raise StopIteration((payload, code))
                    # Monkey-patch _emit locally
                    saved_emit = globals()["_emit"]
                    def _capturing_emit(payload: dict, code: int = 0):
                        raise StopIteration((payload, code))
                    globals()["_emit"] = _capturing_emit
                    try:
                        _COMMANDS[cmd](payload)
                        result, code = {}, 0
                    except StopIteration as e:
                        result, code = e.value
                    finally:
                        globals()["_emit"] = saved_emit
                    resp = {"id": req_id, "code": code, "result": result}
                finally:
                    sys.stdout = old_stdout
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            try:
                sys.stdout.write(json.dumps({"id": msg.get("id", "0") if 'msg' in locals() else "0", "code": 1, "result": {"error": f"{type(exc).__name__}: {exc}"}}) + "\n")
                sys.stdout.flush()
            except Exception:
                pass

_COMMANDS = {
    "status": cmd_status,
    "side-channel": cmd_side_channel,
    "anomaly": cmd_anomaly,
    "quantum-estimate": cmd_quantum_estimate,
    "daemon": cmd_daemon,
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in _COMMANDS:
        _emit({"error": "usage: gpu_bridge.py {status|side-channel|anomaly|quantum-estimate|daemon}"}, 1)
    try:
        if sys.argv[1] == "daemon":
            # daemon reads line-delimited JSON, not single stdin payload
            _COMMANDS["daemon"]({})
            return
        payload = _read_payload()
        _COMMANDS[sys.argv[1]](payload)
    except SystemExit:
        raise
    except json.JSONDecodeError as exc:
        _emit({"error": f"invalid JSON payload: {exc}"}, 1)
    except Exception as exc:
        _emit({"error": f"{type(exc).__name__}: {exc}"}, 1)


if __name__ == "__main__":
    main()
