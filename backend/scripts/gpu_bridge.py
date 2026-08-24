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
            info = {
                "available": True,
                "device_name": props.name,
                "memory_total_gb": round(props.total_memory / 1e9, 1),
                "models_loaded": [],
            }
    except Exception:
        pass
    _emit(info)


def cmd_side_channel(payload: dict) -> None:
    from qtrust_inspector.side_channel import SideChannelAnalyzer

    simulated = bool(payload.get("simulated", True))
    n_traces = int(payload.get("n_traces", 10_000))
    seed = int(payload.get("seed", 42))

    analyzer = SideChannelAnalyzer()
    if not analyzer.model_trained:
        model_path = os.environ.get("QTRUST_SIDE_CHANNEL_MODEL", "")
        if model_path and os.path.exists(model_path):
            analyzer = SideChannelAnalyzer(model_path=model_path)
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
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector

    cbom = payload.get("cbom")
    if not isinstance(cbom, dict):
        raise ValueError("cbom object is required")

    detector = CBOMAnomalyDetector()
    model_path = os.environ.get("QTRUST_ANOMALY_MODEL", "")
    if model_path and os.path.exists(model_path):
        detector = CBOMAnomalyDetector(model_path=model_path)
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


_COMMANDS = {
    "status": cmd_status,
    "side-channel": cmd_side_channel,
    "anomaly": cmd_anomaly,
    "quantum-estimate": cmd_quantum_estimate,
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in _COMMANDS:
        _emit({"error": "usage: gpu_bridge.py {status|side-channel|anomaly|quantum-estimate}"}, 1)
    try:
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
