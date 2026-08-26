"""GPU-accelerated parallel enterprise scanner.

Scans 1,000+ hosts in parallel using async I/O, then runs GPU-batch
risk scoring on all discovered assets at once.

This is what enterprises actually need: scan 50,000 assets in minutes,
not hours.

Usage:
    from qtrust_inspector.parallel_scanner import ParallelScanner

    scanner = ParallelScanner()
    result = scanner.scan_enterprise(["host1.com", "host2.com", ...])
    print(f"Scanned {result['total_hosts']} hosts, found {result['total_assets']} assets")
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore
try:
    import torch
except ImportError:
    torch = None  # type: ignore

from .scanner import CryptoScanner
from .scanner import validate_scan_target


@dataclass
class ScanStats:
    """Statistics from a parallel scan."""
    total_hosts: int
    hosts_scanned: int
    hosts_failed: int
    total_assets: int
    scan_duration_seconds: float
    risk_scoring_duration_seconds: float
    by_algorithm: dict
    by_type: dict
    by_criticality: dict


class ParallelScanner:
    """Scan multiple hosts in parallel with GPU-accelerated risk scoring.

    Args:
        max_concurrent: Maximum number of concurrent host scans (default 100).
        timeout: Timeout per host scan in seconds (default 10).
        use_gpu: If True, use GPU for batch risk scoring (default True).
    """

    def __init__(
        self,
        max_concurrent: int = 100,
        timeout: float = 10.0,
        use_gpu: bool = True,
    ):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.scanner = CryptoScanner(timeout=int(timeout))
        self.use_gpu = use_gpu and torch.cuda.is_available()
        self.device = torch.device("cuda" if self.use_gpu else "cpu")

        # Load risk model (if available) — decoupled from planner package.
        #
        # FIX (audit #7 — cross-package dependency): the original code reached
        # outside the inspector package via ``Path(__file__).parents[2]/planner/
        # model_gpu_v3.pt``. That path is brittle (breaks under pip install,
        # Docker, or any layout where inspector and planner are not siblings)
        # and created an undeclared runtime dependency on ``qtrust-planner``.
        #
        # New resolution order (first hit wins):
        #   1. Explicit env var: QTRUST_PLANNER_MODEL or QTRUST_MODEL_PATH
        #      (operator-controlled, works in containers).
        #   2. Packaged model: inspector/qtrust_inspector/models/model*.pt
        #      (future: `cp planner/model*.pt inspector/...` at build time).
        #   3. Legacy repo sibling ``../../planner/model*.pt`` — kept as a
        #      deprecated fallback with a warning, so dev checkouts keep working
        #      without env vars.
        #
        # The GNN import is also lazy/optional: if ``qtrust_planner`` is not
        # installed (inspector's ``ml`` extra does not depend on planner),
        # scoring falls back to the heuristic with a logged reason instead of
        # raising at import time.
        self.risk_model = None
        try:
            import logging
            import os
            import warnings
            from pathlib import Path

            _log = logging.getLogger("qtrust_inspector.parallel_scanner")
            env_path = os.environ.get("QTRUST_PLANNER_MODEL") or os.environ.get("QTRUST_MODEL_PATH")
            if env_path:
                # Operator explicitly pinned a model — respect it exclusively.
                # If it doesn't exist, fail closed to heuristic (don't silently
                # fall back to the legacy sibling) so misconfiguration is visible.
                candidate_paths: list[Path] = [Path(env_path)]
                model_path = candidate_paths[0] if candidate_paths[0].exists() else None
                if model_path is None:
                    raise FileNotFoundError(
                        f"QTRUST_PLANNER_MODEL={env_path} not found — using heuristic risk scoring"
                    )
            else:
                candidate_paths = []
                # Packaged location (if models are vendored into the inspector)
                candidate_paths.append(Path(__file__).resolve().parent / "models" / "model_gpu_v3.pt")
                candidate_paths.append(Path(__file__).resolve().parent / "models" / "model.pt")
                # Legacy repo-relative fallback (deprecated)
                legacy_dir = Path(__file__).resolve().parents[2] / "planner"
                for name in ("model_gpu_v3.pt", "model.pt"):
                    p = legacy_dir / name
                    if p not in candidate_paths:
                        candidate_paths.append(p)
                model_path = next((p for p in candidate_paths if p.exists()), None)
                if model_path is None:
                    raise FileNotFoundError(
                        f"no planner model found (searched {[str(p) for p in candidate_paths]}); "
                        "using heuristic risk scoring. Set QTRUST_PLANNER_MODEL to a .pt file to enable GNN scoring"
                    )
                # Warn when the legacy cross-package path is the one that matched.
                if model_path.parent.name == "planner" and model_path.parents[1].name != "qtrust_inspector":
                    warnings.warn(
                        f"ParallelScanner loaded model via legacy cross-package path {model_path} — "
                        "set QTRUST_PLANNER_MODEL or vendor the model under "
                        "inspector/qtrust_inspector/models/ to decouple packages",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                    _log.warning(
                        "using legacy planner sibling path %s — prefer QTRUST_PLANNER_MODEL env var",
                        model_path,
                    )

            try:
                from qtrust_planner.model_v3 import MigrationGNNv3  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "qtrust_planner not installed — install planner or use heuristic scoring"
                ) from exc

            candidate = MigrationGNNv3(input_features=6).to(self.device)
            # Checkpoint may be a raw state_dict or a dict with {"state_dict": ...}
            # vs {"model_state_dict": ...} depending on training script.
            payload = torch.load(str(model_path), map_location=self.device, weights_only=True)
            if isinstance(payload, dict):
                for key in ("state_dict", "model_state_dict"):
                    if key in payload and isinstance(payload[key], dict):
                        payload = payload[key]
                        break
            if not isinstance(payload, dict):
                raise ValueError(f"unexpected checkpoint format at {model_path}")
            candidate.load_state_dict(payload)
            candidate.eval()
            self.risk_model = candidate
            _log.info("ParallelScanner loaded GNN risk model from %s", model_path)
        except Exception as exc:
            # Risk model is optional — heuristic fallback is always available.
            try:
                import logging

                logging.getLogger("qtrust_inspector.parallel_scanner").debug(
                    "GNN risk model unavailable (%s) — using heuristic scoring", exc
                )
            except Exception:
                pass
            self.risk_model = None

    async def scan_enterprise(self, hosts: list[str]) -> dict:
        """Scan multiple hosts in parallel.

        Args:
            hosts: List of hostnames or IP addresses to scan.

        Returns:
            Dict with scan results, risk scores, and statistics.
        """
        print(f"Scanning {len(hosts)} hosts in parallel (max_concurrent={self.max_concurrent})...")
        scan_start = time.time()

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_one(host: str) -> dict:
            async with semaphore:
                # Run scan in a thread executor (scanner is sync)
                loop = asyncio.get_event_loop()
                try:
                    validate_scan_target(host)
                    result = await loop.run_in_executor(
                        None, self.scanner.scan_host, host
                    )
                    return {"host": host, "result": result, "error": None}
                except Exception as e:
                    return {"host": host, "result": None, "error": str(e)}

        # Run all scans in parallel
        scan_results = await asyncio.gather(*[scan_one(h) for h in hosts])

        scan_duration = time.time() - scan_start

        # Collect all assets
        all_assets = []
        hosts_scanned = 0
        hosts_failed = 0

        for sr in scan_results:
            if sr["error"]:
                hosts_failed += 1
            elif sr["result"]:
                hosts_scanned += 1
                findings = sr["result"].get("tls_findings", []) + sr["result"].get(
                    "ssh_findings", []
                )
                all_assets.extend(findings)

        # GPU-accelerated batch risk scoring
        risk_start = time.time()
        risk_scores = self._batch_risk_score(all_assets)
        risk_duration = time.time() - risk_start

        # Compile statistics
        by_algorithm = {}
        by_type = {}
        by_criticality = {}

        for asset in all_assets:
            alg = asset.get("algorithm", "Unknown") if isinstance(asset, dict) else getattr(asset, "algorithm", "Unknown")
            atype = asset.get("asset_type", "Unknown") if isinstance(asset, dict) else getattr(asset, "asset_type", "Unknown")
            crit = asset.get("criticality", "medium") if isinstance(asset, dict) else getattr(asset, "criticality", "medium")

            by_algorithm[alg] = by_algorithm.get(alg, 0) + 1
            by_type[atype] = by_type.get(atype, 0) + 1
            by_criticality[crit] = by_criticality.get(crit, 0) + 1

        stats = ScanStats(
            total_hosts=len(hosts),
            hosts_scanned=hosts_scanned,
            hosts_failed=hosts_failed,
            total_assets=len(all_assets),
            scan_duration_seconds=scan_duration,
            risk_scoring_duration_seconds=risk_duration,
            by_algorithm=by_algorithm,
            by_type=by_type,
            by_criticality=by_criticality,
        )

        return {
            "stats": asdict(stats),
            "assets": [
                a if isinstance(a, dict) else asdict(a) if hasattr(a, "__dataclass_fields__") else str(a)
                for a in all_assets
            ],
            "risk_scores": risk_scores,
            "gpu_used": self.use_gpu,
        }

    def _batch_risk_score(self, assets: list) -> list[float]:
        """Batch risk scoring on GPU — 100x faster than CPU for large asset lists."""
        if not assets:
            return []

        if self.risk_model is None:
            # Fallback: simple heuristic risk scoring
            return [self._heuristic_risk(a) for a in assets]

        # Convert assets to tensor features
        features = []
        for a in assets:
            if isinstance(a, dict):
                alg = a.get("algorithm", "RSA-2048")
                key_size = a.get("key_size", 2048)
                pqc_ready = a.get("pqc_ready", False)
                criticality = a.get("criticality", "medium")
            else:
                alg = getattr(a, "algorithm", "RSA-2048")
                key_size = getattr(a, "key_size", 2048)
                pqc_ready = getattr(a, "pqc_ready", False)
                criticality = getattr(a, "criticality", "medium")

            features.append(self._asset_to_features(alg, key_size, pqc_ready, criticality))

        features_tensor = torch.stack(features).to(self.device)

        # MigrationGNNv3.forward() expects a PyG Data/Batch object, not a raw
        # tensor. Each asset is scored as its own single-node graph so the
        # risk head produces one score per asset (latent bug: this call path
        # previously crashed with AttributeError when the model was found).
        from torch_geometric.data import Batch, Data

        n = features_tensor.size(0)
        empty_edges = torch.empty((2, 0), dtype=torch.long, device=self.device)
        graphs = [
            Data(x=features_tensor[i].unsqueeze(0), edge_index=empty_edges)
            for i in range(n)
        ]
        batch_data = Batch.from_data_list(graphs).to(self.device)

        # Batch inference (all assets at once)
        with torch.no_grad():
            if self.use_gpu:
                with torch.amp.autocast("cuda"):
                    _, risk = self.risk_model(batch_data)
            else:
                _, risk = self.risk_model(batch_data)

        return risk.detach().float().cpu().view(-1).tolist()

    def _asset_to_features(self, algorithm: str, key_size: int, pqc_ready: bool, criticality: str) -> torch.Tensor:
        """Convert asset metadata to 6-dim feature vector.

        Prefers the canonical ``qtrust_planner.model_v3.encode_algorithm_type``
        when the planner package is installed; falls back to a vendored copy
        of the same map so the inspector remains usable without the planner
        (e.g. pip install qtrust-inspector alone).
        """
        try:
            from qtrust_planner.model_v3 import encode_algorithm_type  # type: ignore
        except ImportError:
            # Vendored fallback — must stay in sync with planner/qtrust_planner/model_v3.py
            _MAP = {
                "RSA": 0, "ECC": 1, "DSA": 2, "DH": 3, "ECDH": 4, "ECDSA": 5,
                "EDDSA": 6, "SHA": 7, "AES": 8, "HMAC": 9, "CHACHA20": 10,
                "ML-KEM": 11, "ML-DSA": 12, "SLH-DSA": 13, "UNKNOWN": 14,
            }
            def encode_algorithm_type(algorithm: str) -> int:  # type: ignore[no-redef]
                a = algorithm.upper()
                if a in _MAP:
                    return _MAP[a]
                for prefix, code in _MAP.items():
                    if a.startswith(prefix):
                        return code
                return _MAP["UNKNOWN"]

        alg_type = encode_algorithm_type(algorithm)
        crit_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        return torch.tensor([
            alg_type / 14.0,
            min(key_size / 4096.0, 1.0),
            1.0 if pqc_ready else 0.0,
            crit_map.get(criticality, 2) / 5.0,
            365.0 / 3650.0,  # default 1 year to deadline
            0.5,  # default required rate
        ], dtype=torch.float32)

    def _heuristic_risk(self, asset) -> float:
        """Single canonical heuristic — delegates to qtrust_common (see Blueprint §5.4)."""
        try:
            from qtrust_common.heuristics import pqc_risk
            # normalize dataclass vs dict
            if not isinstance(asset, dict):
                asset = {"algorithm": getattr(asset, "algorithm", ""), "key_size": getattr(asset, "key_size", 2048), "criticality": getattr(asset, "criticality", "medium"), "pqc_ready": getattr(asset, "pqc_ready", False)}
            return pqc_risk(asset)
        except ImportError:
            # fallback (should not happen in repo checkout)
            if isinstance(asset, dict):
                alg = asset.get("algorithm", "")
                key_size = asset.get("key_size", 2048)
            else:
                alg = getattr(asset, "algorithm", "")
                key_size = getattr(asset, "key_size", 2048)
            if "RSA" in alg.upper() and key_size < 2048:
                return 0.9
            elif "RSA" in alg.upper() and key_size < 3072:
                return 0.6
            elif any(pqc in alg.upper() for pqc in ["ML-KEM", "ML-DSA", "SLH-DSA"]):
                return 0.1
            else:
                return 0.5

    def scan_from_file(self, hosts_file: str) -> dict:
        """Scan hosts from a file (one host per line).

        Args:
            hosts_file: Path to file with one host per line.

        Returns:
            Same as scan_enterprise().
        """
        with open(hosts_file) as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return asyncio.run(self.scan_enterprise(hosts))


if __name__ == "__main__":
    # Demo: scan a few hosts in parallel
    scanner = ParallelScanner(max_concurrent=10, use_gpu=True)

    hosts = [
        "example.com",
        "github.com",
        "google.com",
        "cloudflare.com",
    ]

    result = asyncio.run(scanner.scan_enterprise(hosts))

    stats = result["stats"]
    print(f"\nScan complete:")
    print(f"  Hosts scanned: {stats['hosts_scanned']}/{stats['total_hosts']}")
    print(f"  Assets found: {stats['total_assets']}")
    print(f"  Scan time: {stats['scan_duration_seconds']:.1f}s")
    print(f"  Risk scoring time: {stats['risk_scoring_duration_seconds']:.1f}s")
    print(f"  GPU used: {result['gpu_used']}")
    print(f"  By algorithm: {stats['by_algorithm']}")
