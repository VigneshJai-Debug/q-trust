"""Train ALL qtrust_ai intelligence-layer models (32-point plan).

Every model in the Q-Trust AI intelligence layer (``qtrust_ai/``) is a
CPU-friendly trainable stub: ``train()`` fits weights on synthetic /
anchor-calibrated data (optionally fitting sklearn / torch layers when
available) with deterministic heuristic fallbacks. This script runs
``train()`` (and ``calibrate()`` where applicable) across the whole stack,
then evaluates each model and verifies the spec anchors:

    discovery   code detector + purpose classifier (12 languages)
    graph       dependency graph, blast radius (calibrate), temporal GNN 73→61→42
    risk        quantum exposure / HNDL (RSA HIGH vs ML-KEM LOW)
    migration   recommender (RSA-sig → ML-DSA, RSA-KEM → ML-KEM),
                cost (banking anchor ≈ 84h/31h/12d), failure (modern low vs
                legacy high), interop (OpenSSL 3.x + ML-KEM-768 ≈ 99.1%/+4.8%),
                multi-objective RL (bank vs startup steering)
    monitoring  anomaly (RSA spike) + regression gate (ML-KEM→RSA blocked)
    vendor      supply-chain risk + readiness (vendorA > vendorC)
    copilot     evidence-backed answers (canonical payment-API case)
    policy      NL → constraints (spec §22 patterns)

Companion to ``scripts/train_real_models.py`` (which trains the legacy
planner GNN / RL / anomaly models on real scans). This one covers the
``qtrust_ai`` intelligence layer and writes a JSON report to
``qtrust_ai/artifacts/training_report.json``.

Usage:
    python scripts/train_qtrust_all.py [--epochs 5] [--rl-episodes 40]
                                       [--report qtrust_ai/artifacts/training_report.json]
    python scripts/train_qtrust_all.py --real   # train on real datasets (see build_real_datasets.py)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

RESULTS: List[Dict[str, Any]] = []


def run(name: str, fn: Callable[[], Dict[str, Any]],
        anchors: Optional[List[Callable[[Dict[str, Any]], str]]] = None,
        data_source: str = "synthetic") -> Dict[str, Any]:
    """Execute a training step, record result + anchor checks."""
    t0 = time.time()
    entry: Dict[str, Any] = {"model": name, "status": "error", "seconds": 0.0,
                             "train": None, "evaluate": None, "anchors": [],
                             "data_source": data_source}
    try:
        out = fn()
        entry["train"] = out
        entry["status"] = "trained"
        for anchor in anchors or []:
            try:
                msg = anchor(out)
                entry["anchors"].append({"check": msg, "passed": True})
            except AssertionError as exc:
                entry["anchors"].append({"check": str(exc) or anchor.__doc__ or "anchor", "passed": False})
                entry["status"] = "anchor-fail"
    except Exception as exc:  # noqa: BLE001 — report any training failure
        entry["error"] = f"{type(exc).__name__}: {exc}"
        entry["traceback"] = traceback.format_exc(limit=3)
    entry["seconds"] = round(time.time() - t0, 2)
    RESULTS.append(entry)
    _print_entry(entry)
    return entry


def _print_entry(entry: Dict[str, Any]) -> None:
    status = entry["status"].ljust(12)
    train = entry.get("train") or {}
    summary = _summarize(train)
    anchors = entry.get("anchors") or []
    a_ok = sum(1 for a in anchors if a["passed"])
    print(f"  [{status}] {entry['model']:<34s} {entry['seconds']:>6.1f}s  {summary}"
          f"{f'  anchors {a_ok}/{len(anchors)}' if anchors else ''}")


def _summarize(train: Dict[str, Any]) -> str:
    """Compact one-line summary of a train() result dict."""
    if not train:
        return ""
    keys = ["mae", "accuracy", "auroc", "mean_reward", "examples", "train_accuracy"]
    bits = []
    for k in keys:
        if k in train:
            v = train[k]
            bits.append(f"{k}={round(float(v), 3) if isinstance(v, (int, float)) else v}")
    for k in ("has_torch", "has_sklearn"):
        if k in train and train[k]:
            bits.append(k)
    return " ".join(bits)


# ---------------------------------------------------------------------------
# Real dataset loading + converters
# ---------------------------------------------------------------------------

def _code_splits(corpus: List[Dict[str, Any]], seed: int = 42) -> tuple:
    """Split real code corpus by source repo (no cross-split leakage)."""
    rnd = random.Random(seed)
    sources = sorted({c.get("source", "unknown") for c in corpus})
    rnd.shuffle(sources)
    n_train = max(1, int(len(sources) * 0.8))
    train_src, eval_src = set(sources[:n_train]), set(sources[n_train:])
    train = [c for c in corpus if c.get("source") in train_src]
    ev = [c for c in corpus if c.get("source") in eval_src]
    return train, ev


def load_real_datasets(datasets_dir: str) -> Dict[str, Any]:
    """Load the datasets built by scripts/build_real_datasets.py."""
    d = Path(datasets_dir)
    real: Dict[str, Any] = {}
    code_path = d / "code_corpus.json"
    if code_path.exists():
        real["code"] = json.loads(code_path.read_text())
        print(f"  real code corpus: {len(real['code']['corpus'])} files "
              f"(crypto={sum(1 for c in real['code']['corpus'] if c['is_crypto'])})")
    tls_path = d / "tls_inventory.json"
    if tls_path.exists():
        real["tls"] = json.loads(tls_path.read_text())
        print(f"  real TLS: {real['tls'].get('n_findings', 0)} findings across "
              f"{len(real['tls'].get('cboms', []))} hosts")
    vendor_path = d / "vendor_dataset.json"
    if vendor_path.exists():
        real["vendor"] = json.loads(vendor_path.read_text())
        print(f"  real vendor: {len(real['vendor'].get('records', []))} libraries")
    return real


_TLS_ALGO_MAP = {
    "sha256withrsaencryption": "RSA-2048",
    "sha384withrsaencryption": "RSA-4096",
    "sha512withrsaencryption": "RSA-4096",
    "ecdsa-with-sha256": "ECDSA-P256",
    "ecdsa-with-sha384": "ECDSA-P384",
    "ecdsa-with-sha512": "ECDSA-P521",
}

_ALGO_NAMES_RE = re.compile(
    r"\b(RSA(?:-2048|-4096|-1024)?|ECDSA-P(?:256|384|521)|ECDH-P256|X25519|ED25519|"
    r"AES-(?:128|192|256)|3DES|DES|SHA-(?:1|256|384|512)|SHA3-256|MD5|HMAC-SHA256|"
    r"ML-KEM-(?:512|768|1024)|ML-DSA-(?:44|65|87)|SLH-DSA|HQC-128|Falcon-512)\b",
    re.IGNORECASE,
)


def tls_algo_to_standard(algorithm: str) -> str:
    key = (algorithm or "").lower().replace("_", "-").strip()
    if key in _TLS_ALGO_MAP:
        return _TLS_ALGO_MAP[key]
    m = _ALGO_NAMES_RE.search(key)
    if m:
        return m.group(1).upper().replace("_", "-")
    return "RSA-2048"  # TLS certs default to RSA


_SENSITIVE_HOST_PARTS = ("bank", "pay", "fin", "card", "health", "gov", "sec", "mil", "tax", "insur")
_HIGH_PROFILE_HOSTS = ("amazon", "google", "apple", "meta", "microsoft", "github", "cloudflare",
                       "anthropic", "openai", "netflix", "linkedin", "zoom", "salesforce", "adobe")
_LOW_SENSITIVITY_HOSTS = ("cdn", "static", "edge", "img", "ad", "analytics", "test", "dev", "blog")


def _host_sensitivity(host: str) -> int:
    """Real hostname → data-sensitivity proxy (0-5) for exposure factors."""
    h = (host or "").lower()
    if any(k in h for k in _SENSITIVE_HOST_PARTS):
        return 5
    if any(k in h for k in _HIGH_PROFILE_HOSTS):
        return 4
    if any(k in h for k in _LOW_SENSITIVITY_HOSTS):
        return 2
    return 3


def tls_risk_samples(cboms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Real TLS findings → (ExposureFactors, deterministic label) pairs.

    Factors are grounded in the real certificate data: algorithm and key size
    come straight from the scanned cert; sensitivity is a host-category proxy
    (payment/gov hosts protect more sensitive data than CDN edges); exposure
    age is a stable deterministic function of the host. The label is the
    trusted deterministic reference scorer applied to those factors.
    """
    from qtrust_ai.risk.quantum_exposure import ExposureFactors, QuantumExposureModel
    ref = QuantumExposureModel()  # deterministic reference scorer
    samples: List[Dict[str, Any]] = []
    for cbom in cboms:
        host = cbom.get("target", "host")
        sens = _host_sensitivity(host)
        # deterministic, stable per-host exposure age 0-6y
        exposure_years = round((hashlib.md5(host.encode()).digest()[0] / 255.0) * 6.0, 1)
        for asset in cbom.get("assets", []):
            algo = tls_algo_to_standard(asset.get("algorithm", ""))
            factors = ExposureFactors(
                algorithm=algo,
                key_size=asset.get("key_size"),
                sensitivity=sens,
                lifetime_years=5,
                exposure_years=exposure_years,
                attractiveness=4,
                lead_time_years=2,
                purpose="key-establishment",
            )
            label = ref.predict(factors).score  # trusted deterministic reference
            samples.append({"factors": asdict(factors), "label": float(label),
                            "_algo": algo, "_host": host})
    return samples


def tls_snapshots(cboms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Real per-host CBOMs → CryptoSnapshot dicts (anomaly baseline)."""
    from qtrust_ai.monitoring.anomaly import CryptoSnapshot
    snaps: List[Dict[str, Any]] = []
    for cbom in cboms:
        counts: Dict[str, int] = {}
        for asset in cbom.get("assets", []):
            algo = tls_algo_to_standard(asset.get("algorithm", ""))
            counts[algo] = counts.get(algo, 0) + 1
        snaps.append(asdict(CryptoSnapshot(
            algorithm_counts=counts, total_assets=sum(counts.values()),
            source=f"tls:{cbom.get('target', 'host')}",
        )))
    return snaps


# A purpose-disambiguation sample is only answerable when the algorithm
# mention is actual *usage* — an import / package / include declaration or a
# quoted path (e.g. ``package rsa import ("crypto/rand" ...)``) carries no
# usage signal, and including such contexts just adds label noise.
_IMPORT_DECL_RE = re.compile(
    r"^\s*(import|package|use|include|require|#include|from\s+|using\s+)",
    re.IGNORECASE,
)


def purpose_triples_from_code(code: Dict[str, Any]) -> List[Dict[str, str]]:
    """Real code files → {"algorithm", "context", "purpose"} triples.

    Walks all algorithm mentions and keeps the first one that is a real usage
    (not an import/package declaration and not a quoted import path), so the
    purpose label is answerable from the surrounding context.
    """
    from qtrust_ai.benchmark.dataset import purpose_for
    triples: List[Dict[str, str]] = []
    for rec in code.get("corpus", []):
        if not rec.get("is_crypto"):
            continue
        text = rec.get("code", "")
        chosen: Optional[re.Match] = None
        for m in _ALGO_NAMES_RE.finditer(text):
            # inside a string literal (quoted import path / URL)?
            if text.count('"', 0, m.start()) % 2 == 1:
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if _IMPORT_DECL_RE.match(line):
                continue
            chosen = m
            break
        if chosen is None:
            continue
        algo = chosen.group(1).upper().replace("_", "-")
        purpose = purpose_for(algo)
        lo = max(0, chosen.start() - 120)
        context = text[lo:chosen.end() + 120].replace("\n", " ")
        triples.append({"algorithm": algo, "context": context[:240], "purpose": purpose})
    return triples


def vendor_objects_from_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Real vendor records → train()-ready {"vendor": {...}, "score": ...}."""
    out = []
    for rec in records:
        v = rec.get("vendor", {})
        libs = []
        for prod in v.get("products", []):
            for lib in prod.get("libraries", []):
                libs.append({
                    "name": lib.get("name", "openssl"),
                    "version": lib.get("version", "n/a"),
                    "crypto_algorithms": lib.get("crypto_algorithms", []),
                    "pqc_support": bool(lib.get("pqc_support")),
                    "known_vulns": int(lib.get("cve_count", 0)),
                })
        out.append({
            "vendor": {
                "name": v.get("name", "Vendor"),
                "products": [{"name": v.get("name", "product"), "libraries": libs}],
            },
            "score": float(rec.get("score", 50)),
        })
    return out


# ---------------------------------------------------------------------------
# Training steps
# ---------------------------------------------------------------------------

def train_discovery(epochs: int, real: Optional[Dict[str, Any]] = None, hf_epochs: int = 2) -> None:
    from qtrust_ai.discovery.code_detector import CryptoCodeDetector

    use_real = bool(real and real.get("code"))

    def _run() -> Dict[str, Any]:
        det = CryptoCodeDetector(seed=42)
        if use_real:
            train_corpus, eval_corpus = _code_splits(real["code"]["corpus"])
            res = det.train(corpus=train_corpus, epochs=epochs)
            if hf_epochs > 0:
                ft = det.fine_tune(
                    train_corpus, epochs=hf_epochs,
                    save_dir=str(REPO_ROOT / "qtrust_ai" / "artifacts" / "crypto_codebert"),
                )
                res["_fine_tune"] = ft
            res["_eval"] = det.evaluate(dataset=eval_corpus)
            res["_n_real"] = len(train_corpus)
        else:
            res = det.train(epochs=epochs)
            res["_eval"] = det.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        det = CryptoCodeDetector(seed=42)
        r = det.predict("import rsa; rsa.newkeys(2048)", language="python")
        assert r.is_crypto, "RSA snippet not flagged crypto"
        assert "RSA" in r.algorithm.upper(), f"wrong algo {r.algorithm}"
        return "RSA snippet → crypto"

    run("discovery/CryptoCodeDetector", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_purpose_classifier(epochs: int, real: Optional[Dict[str, Any]] = None) -> None:
    from qtrust_ai.discovery.algorithm_classifier import AlgorithmPurposeClassifier

    use_real = bool(real and real.get("code"))

    def _run() -> Dict[str, Any]:
        clf = AlgorithmPurposeClassifier(seed=42)
        if use_real:
            train_corpus, eval_corpus = _code_splits(real["code"]["corpus"])
            triples = purpose_triples_from_code({"corpus": train_corpus})
            eval_triples = purpose_triples_from_code({"corpus": eval_corpus})
            res = clf.train(corpus=triples, epochs=epochs)
            res["_eval"] = clf.evaluate(dataset=eval_triples)
            res["_n_real"] = len(triples)
        else:
            res = clf.train(epochs=epochs)
            res["_eval"] = clf.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        clf = AlgorithmPurposeClassifier(seed=42)
        r1 = clf.predict("RSA", context="private_key.sign(data)")
        r2 = clf.predict("ECDH", context="derive shared secret")
        assert r1.purpose.value == "signature", f"RSA ctx → {r1.purpose.value}"
        assert r2.purpose.value == "key-establishment", f"ECDH ctx → {r2.purpose.value}"
        return "RSA(sign ctx)→signature, ECDH→key-establishment"

    run("discovery/AlgorithmPurposeClassifier", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_blast_radius() -> None:
    from qtrust_ai.graph.blast_radius import BlastRadius
    from qtrust_ai.graph.dependency_graph import DependencyGraph

    def _run() -> Dict[str, Any]:
        g = DependencyGraph()
        g.build_from_findings(
            [{"algorithm": "RSA-2048", "file": "svc/payment/api.py", "criticality": "critical", "key_size": 2048},
             {"algorithm": "RSA-2048", "file": "svc/auth/auth.java", "criticality": "critical"},
             {"algorithm": "AES-256", "file": "svc/crypto.py", "criticality": "high"},
             {"algorithm": "ML-KEM-768", "file": "svc/ingress.rs", "criticality": "medium"}],
            app_name="bank", app_criticality="critical",
        )
        br = BlastRadius(g)
        res = br.calibrate([{"primitive": "RSA-2048", "direct": 12, "indirect": 35, "critical": 6, "datasets": 4, "observed_score": 85}])
        res["_rsa"] = br.compute("RSA-2048").score
        res["_mlkem"] = br.compute("ML-KEM-768").score
        return res

    def anchor(res: Dict[str, Any]) -> str:
        assert res["_rsa"] > res["_mlkem"], f"RSA blast {res['_rsa']} !> ML-KEM {res['_mlkem']}"
        return f"RSA blast ({res['_rsa']:.0f}) > ML-KEM ({res['_mlkem']:.0f})"

    run("graph/BlastRadius (calibrate)", _run, [anchor])


def train_temporal(epochs: int) -> None:
    from qtrust_ai.graph.temporal_gnn import GraphSnapshot, TemporalGNN

    def _run() -> Dict[str, Any]:
        gnn = TemporalGNN(seed=42)
        res = gnn.train(epochs=epochs)
        res["_eval"] = gnn.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        gnn = TemporalGNN(seed=42)
        traj = gnn.predict_trajectory(
            [GraphSnapshot(t=0, day=0, num_nodes=80, num_edges=220, num_pqc_nodes=2, num_critical=9, risk_score=73.0)],
            horizon_days=[30, 90, 180],
        )
        assert traj.risks == [61.0, 50.0, 42.0], f"anchor trajectory {traj.risks}"
        return "73 → 61 → 50 → 42 (30/90/180d)"

    run("graph/TemporalGNN", _run, [anchor])


def train_risk(epochs: int, real: Optional[Dict[str, Any]] = None) -> None:
    from qtrust_ai.risk.quantum_exposure import ExposureFactors, QuantumExposureModel

    use_real = bool(real and real.get("tls"))

    def _run() -> Dict[str, Any]:
        m = QuantumExposureModel()
        if use_real:
            samples = tls_risk_samples(real["tls"].get("cboms", []))
            res = m.train(dataset=samples, epochs=epochs)
            res["_eval"] = m.evaluate(dataset=samples)
            res["_n_real"] = len(samples)
        else:
            res = m.train(epochs=epochs)
            res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = QuantumExposureModel()
        rsa = m.predict(ExposureFactors(algorithm="RSA-2048", sensitivity=5, lifetime_years=5,
                                        exposure_years=5.0, attractiveness=5, lead_time_years=4))
        pqc = m.predict(ExposureFactors(algorithm="ML-KEM-768", sensitivity=5, lifetime_years=5,
                                        exposure_years=5.0, attractiveness=5, lead_time_years=4))
        assert rsa.score > 60, f"RSA exposure {rsa.score} not HIGH+"
        assert pqc.score < 10, f"ML-KEM exposure {pqc.score} should be ~0"
        return f"RSA-2048 {rsa.score:.0f}[{rsa.level}] vs ML-KEM {pqc.score:.0f}[{pqc.level}]"

    run("risk/QuantumExposureModel", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_recommender(epochs: int, real: Optional[Dict[str, Any]] = None) -> None:
    from qtrust_ai.migration.replacement_recommender import PQCRecommender

    use_real = bool(real and real.get("code"))

    def _run() -> Dict[str, Any]:
        r = PQCRecommender(seed=42)
        if use_real:
            train_corpus, _ = _code_splits(real["code"]["corpus"])
            triples = purpose_triples_from_code({"corpus": train_corpus})
            res = r.train(corpus=triples, epochs=epochs)
            res["_n_real"] = len(triples)
        else:
            res = r.train(epochs=epochs)
        res["_eval"] = r.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        r = PQCRecommender(seed=42)
        sig = r.recommend("RSA-2048", purpose="signature")
        kem = r.recommend("RSA-2048", purpose="key-establishment")
        aes = r.recommend("AES-128", purpose="encryption")
        assert sig.primary_pqc.startswith("ML-DSA") or sig.primary_pqc.startswith("SLH"), sig.primary_pqc
        assert kem.primary_pqc.startswith("ML-KEM") or kem.primary_pqc.startswith("HQC"), kem.primary_pqc
        assert aes.primary_pqc == "AES-256", aes.primary_pqc
        return f"RSA-sig→{sig.primary_pqc}, RSA-KEM→{kem.primary_pqc}, AES-128→{aes.primary_pqc}"

    run("migration/PQCRecommender", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_cost(epochs: int) -> None:
    from qtrust_ai.migration.cost_predictor import MigrationCostFeatures, MigrationCostPredictor

    def _run() -> Dict[str, Any]:
        m = MigrationCostPredictor(seed=42)
        res = m.train(epochs=epochs)
        res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = MigrationCostPredictor(seed=42)
        r = m.predict(MigrationCostFeatures(app_type="banking-api", legacy=True,
                                            target_pqc="hybrid", dependency_count=17))
        assert 60 < r.engineering_hours < 110, f"anchor eng {r.engineering_hours}"
        assert 20 < r.testing_hours < 45, f"anchor test {r.testing_hours}"
        assert r.duration_days >= 5
        return f"banking-api → {r.engineering_hours:.0f}h eng / {r.testing_hours:.0f}h test / {r.duration_days}d (spec ≈84/31/12)"

    run("migration/MigrationCostPredictor", _run, [anchor])


def train_failure(epochs: int) -> None:
    from qtrust_ai.migration.failure_predictor import FailureFeatures, MigrationFailurePredictor

    def _run() -> Dict[str, Any]:
        m = MigrationFailurePredictor(seed=42)
        res = m.train(epochs=epochs)
        res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = MigrationFailurePredictor(seed=42)
        low = m.predict(FailureFeatures(library="openssl", library_version="3.1.2", protocol="TLS1.3",
                                        hardware="x86", pqc_impl="ML-KEM-768", latency_ms=50,
                                        packet_size_bytes=1200, dependency_count=2, app_type="web"))
        high = m.predict(FailureFeatures(library="openssl", library_version="1.1.1w", protocol="TLS1.2",
                                         hardware="hsm", pqc_impl="ML-KEM-768", latency_ms=400,
                                         packet_size_bytes=9000, dependency_count=30, app_type="iot-firmware"))
        assert low.failure_prob < high.failure_prob, f"{low.failure_prob} !< {high.failure_prob}"
        assert low.top_reasons, "no reasons"
        return f"modern {low.failure_prob:.0%} < legacy {high.failure_prob:.0%}"

    run("migration/MigrationFailurePredictor", _run, [anchor])


def train_interop(epochs: int) -> None:
    from qtrust_ai.migration.interoperability import InteropFeatures, InteroperabilityPredictor

    def _run() -> Dict[str, Any]:
        m = InteroperabilityPredictor(seed=42)
        res = m.train(epochs=epochs)
        res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = InteroperabilityPredictor(seed=42)
        ok_ = m.predict(InteropFeatures(client_library="openssl", client_version="3.0.8",
                                        server_library="openssl", server_version="3.0.8",
                                        client_hardware="x86", server_hardware="x86",
                                        protocol="TLS1.3", pqc_alg="ML-KEM-768"))
        bad = m.predict(InteropFeatures(client_library="openssl", client_version="1.1.1w",
                                        server_library="openssl", server_version="1.1.1w",
                                        protocol="TLS1.2", pqc_alg="ML-KEM-768"))
        assert ok_.compatible and ok_.compatibility_prob > 0.95, ok_.compatibility_prob
        assert 3.0 <= ok_.latency_delta_percent <= 6.5, ok_.latency_delta_percent
        assert not bad.compatible, "legacy pair should be incompatible"
        return f"OpenSSL3+ML-KEM-768 {ok_.compatibility_prob:.1%} lat+{ok_.latency_delta_percent:.1f}% (spec 99.1%/+4.8%); legacy 1.1.1 → incompatible"

    run("migration/InteroperabilityPredictor", _run, [anchor])


def train_rl(episodes: int) -> None:
    from qtrust_ai.migration.multi_objective_rl import (
        MultiObjectiveRLAgent,
        RewardWeights,
    )

    def _run() -> Dict[str, Any]:
        agent = MultiObjectiveRLAgent(seed=42)
        res = agent.train(weights=RewardWeights.balanced_preset(), episodes=episodes)
        res["_eval"] = agent.evaluate(weights=RewardWeights.balanced_preset())
        # Richer asset mix (module demo set) so weight steering is observable
        assets = [
            {"id": "payment-api", "priority": 0.92, "risk": 85, "compliance_gain": 0.85, "cost": 55000, "downtime": 3, "failure_prob": 0.22, "latency_delta": 8, "dependencies": []},
            {"id": "auth-service", "priority": 0.88, "risk": 78, "compliance_gain": 0.75, "cost": 35000, "downtime": 4, "failure_prob": 0.18, "latency_delta": 6, "dependencies": []},
            {"id": "cheap-cache", "priority": 0.45, "risk": 20, "compliance_gain": 0.15, "cost": 3000, "downtime": 2, "failure_prob": 0.04, "latency_delta": 2, "dependencies": []},
            {"id": "vendor-hsm", "priority": 0.75, "risk": 90, "compliance_gain": 0.90, "cost": 70000, "downtime": 25, "failure_prob": 0.30, "latency_delta": 22, "dependencies": []},
            {"id": "web-frontend", "priority": 0.55, "risk": 25, "compliance_gain": 0.20, "cost": 8000, "downtime": 5, "failure_prob": 0.06, "latency_delta": 3, "dependencies": []},
        ]
        comp = agent.compare_presets(assets)
        res["_bank_seq"] = comp["rollouts"]["bank"]["sequence"]
        res["_startup_seq"] = comp["rollouts"]["startup"]["sequence"]
        res["_divergence"] = comp["divergence"]
        return res

    def anchor(res: Dict[str, Any]) -> str:
        assert res["_bank_seq"] != res["_startup_seq"], "bank/startup steering identical"
        assert res["_bank_seq"][0] in ("payment-api", "vendor-hsm"), f"bank first pick {res['_bank_seq'][0]} not high-risk"
        # Weight steering must pull the low-cost asset earlier for startup
        bank_i = res["_bank_seq"].index("cheap-cache")
        startup_i = res["_startup_seq"].index("cheap-cache")
        assert startup_i < bank_i, f"cheap-cache not earlier for startup (bank {bank_i} vs startup {startup_i})"
        return f"bank {res['_bank_seq']} vs startup {res['_startup_seq']} (cheap-cache {bank_i}→{startup_i})"

    run("migration/MultiObjectiveRLAgent", _run, [anchor])


def train_anomaly(epochs: int, real: Optional[Dict[str, Any]] = None) -> None:
    from qtrust_ai.monitoring.anomaly import CryptoAnomalyDetector, CryptoSnapshot

    use_real = bool(real and real.get("tls"))

    def _run() -> Dict[str, Any]:
        m = CryptoAnomalyDetector(seed=42)
        if use_real:
            snaps = tls_snapshots(real["tls"].get("cboms", []))
            res = m.train(snapshots=snaps, epochs=epochs)
            res["_n_real"] = len(snaps)
            # Honest real-data check: baseline on 80% of real hosts,
            # alert rate on held-out 20% (real hosts are all normal →
            # a good detector raises ~0 alerts).
            from qtrust_ai.monitoring.anomaly import CryptoSnapshot as CS
            n_base = max(1, int(len(snaps) * 0.8))
            m2 = CryptoAnomalyDetector(seed=42)

            def _agg(part: List[Dict[str, Any]]) -> CS:
                counts: Dict[str, int] = {}
                for s in part:
                    for algo, n in s["algorithm_counts"].items():
                        counts[algo] = counts.get(algo, 0) + n
                return CS(algorithm_counts=counts, total_assets=sum(counts.values()),
                          source="tls:agg")

            m2.establish_baseline([_agg(snaps[:n_base])])
            held = snaps[n_base:]
            alerts = len(m2.detect(_agg(held)))
            res["_eval_real"] = {"tested_hosts": len(held), "alerts": alerts}
        else:
            res = m.train(epochs=epochs)
        res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = CryptoAnomalyDetector(seed=42)
        baseline = CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "ECDSA-P256": 10, "AES-256": 30}, total_assets=80)
        spike = CryptoSnapshot(algorithm_counts={"RSA-2048": 70, "ECDSA-P256": 10, "AES-256": 30, "DES": 2}, total_assets=112)
        m.establish_baseline([baseline])
        alerts = m.detect(spike)
        assert alerts, "RSA spike not detected"
        return f"{len(alerts)} alert(s): " + "; ".join(a.alert_type for a in alerts[:3])

    run("monitoring/CryptoAnomalyDetector", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_regression(epochs: int) -> None:
    from qtrust_ai.monitoring.regression import CryptoRegressionDetector

    def _run() -> Dict[str, Any]:
        m = CryptoRegressionDetector(seed=42)
        res = m.train(epochs=epochs)
        res["_eval"] = m.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        m = CryptoRegressionDetector(seed=42)
        verdict = m.check_ci_gate(
            {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]},
            {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]},
        )
        assert verdict.blocked, "ML-KEM→RSA regression not blocked"
        assert verdict.severity == "CRITICAL", verdict.severity
        return "ML-KEM→RSA blocked (CRITICAL)"

    run("monitoring/CryptoRegressionDetector", _run, [anchor])


def train_vendor(epochs: int, real: Optional[Dict[str, Any]] = None) -> None:
    from qtrust_ai.vendor.readiness_model import VendorReadinessFeatures, VendorReadinessModel
    from qtrust_ai.vendor.supply_chain_risk import Library, Product, SupplyChainRiskModel, Vendor

    use_real = bool(real and real.get("vendor"))

    def _run() -> Dict[str, Any]:
        scm = SupplyChainRiskModel(seed=42)
        rm = VendorReadinessModel(seed=42)
        if use_real:
            records = real["vendor"].get("records", [])
            scm_res = scm.train(dataset=vendor_objects_from_records(records), epochs=epochs)
            rm_res = rm.train(dataset=[
                {"vendor_name": r.get("vendor", {}).get("name", "Vendor"), "score": float(r.get("score", 50))}
                for r in records
            ], epochs=epochs)
            scm_res["_n_real"] = len(records)
            rm_res["_n_real"] = len(records)
        else:
            scm_res = scm.train(epochs=epochs)
            rm_res = rm.train(epochs=epochs)
        a = Vendor(name="Vendor A", products=[Product(name="gw", libraries=[Library(name="openssl", version="3.2.1", crypto_algorithms=["ML-KEM-768", "ML-DSA-65"], pqc_support=True)])])
        c = Vendor(name="Vendor C", products=[Product(name="legacy", libraries=[Library(name="proprietary", version="1.0.0", crypto_algorithms=["RSA-2048"], pqc_support=False)])])
        score_a = scm.score_vendor(a)
        score_c = scm.score_vendor(c)
        feats = VendorReadinessFeatures(vendor_name="Vendor A")
        readiness = rm.predict(feats)
        return {"_scm": {"vendor_a": score_a.score, "vendor_c": score_c.score},
                "_readiness": {"vendor_a": readiness.readiness_score, "level": readiness.level.value},
                "_scm_train": scm_res, "_readiness_train": rm_res}

    def anchor(res: Dict[str, Any]) -> str:
        assert res["_scm"]["vendor_a"] > res["_scm"]["vendor_c"], "vendorA !> vendorC"
        assert res["_readiness"]["vendor_a"] >= 70, f"readiness {res['_readiness']}"
        return f"supply-chain A={res['_scm']['vendor_a']:.0f} vs C={res['_scm']['vendor_c']:.0f}; readiness A={res['_readiness']['vendor_a']:.0f}"

    run("vendor/SupplyChainRiskModel + VendorReadinessModel", _run, [anchor],
        data_source="real" if use_real else "synthetic")


def train_copilot() -> None:
    from qtrust_ai.copilot.explainer import SecurityCopilot
    from qtrust_ai.graph.dependency_graph import DependencyGraph

    def _run() -> Dict[str, Any]:
        g = DependencyGraph()
        g.build_from_findings(
            [{"algorithm": "RSA-2048", "file": "svc/payment/api.py", "criticality": "critical", "key_size": 2048},
             {"algorithm": "ECDSA-P256", "file": "svc/auth/tls.go", "criticality": "high"},
             {"algorithm": "ML-KEM-768", "file": "svc/ingress.rs", "criticality": "medium"}],
            app_name="payment-api", app_criticality="critical",
        )
        copilot = SecurityCopilot(seed=42)
        copilot.attach_graph(g)
        res = copilot.train()
        ans = copilot.answer("Why is our payment API critical?")
        res["_answer"] = ans.answer
        res["_intent"] = ans.intent
        res["_sources"] = ans.sources
        res["_eval"] = copilot.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        assert "RSA-2048" in res["_answer"], res["_answer"][:80]
        assert res["_eval"]["passed"] >= 2
        return f"canonical answer cites RSA-2048 (sources: {res['_sources']})"

    run("copilot/SecurityCopilot", _run, [anchor])


def train_policy() -> None:
    from qtrust_ai.policy.engine import PolicyEngine

    def _run() -> Dict[str, Any]:
        engine = PolicyEngine(seed=42)
        res = engine.train()
        res["_eval"] = engine.evaluate()
        return res

    def anchor(res: Dict[str, Any]) -> str:
        assert res["_eval"]["accuracy"] == 1.0, res["_eval"]
        return f"all {res['_eval']['total']} §22 policy patterns parsed"

    run("policy/PolicyEngine", _run, [anchor])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train all qtrust_ai intelligence-layer models")
    parser.add_argument("--epochs", type=int, default=5, help="epochs for weight-fitting models")
    parser.add_argument("--rl-episodes", type=int, default=40, help="episodes for the RL agent")
    parser.add_argument("--report", type=str, default=None,
                        help="output report path (default qtrust_ai/artifacts/training_report[_real].json)")
    parser.add_argument("--benchmark-out", type=str, default=None,
                        help="output path for the baseline comparison "
                             "(default qtrust_ai/artifacts/benchmark_comparison.json)")
    parser.add_argument("--real", action="store_true",
                        help="train on real datasets built by scripts/build_real_datasets.py "
                             "(code corpus / TLS inventory / NVD vendor data); models whose "
                             "labels are proprietary (cost/failure/interop/RL/etc.) stay synthetic")
    parser.add_argument("--hf-epochs", type=int, default=2,
                        help="transformer fine-tune epochs for the code detector (0 = skip; "
                             "runs on CUDA when available)")
    args = parser.parse_args()

    # Load real datasets when requested
    real: Dict[str, Any] = {}
    datasets_dir = REPO_ROOT / "qtrust_ai" / "artifacts" / "real_datasets"
    if args.real:
        if datasets_dir.exists():
            print("\n=== Loading real datasets ===\n")
            real = load_real_datasets(str(datasets_dir))
        else:
            print("\n! --real requested but real datasets not found; run scripts/build_real_datasets.py"
                  " first — falling back to synthetic data\n")

    report_path = Path(args.report) if args.report else (
        REPO_ROOT / "qtrust_ai" / "artifacts" / ("training_report_real.json" if args.real else "training_report.json")
    )

    print(f"=== Training all qtrust_ai models (epochs={args.epochs}, rl_episodes={args.rl_episodes},"
          f" real={bool(real)}) ===\n")
    t0 = time.time()

    train_discovery(args.epochs, real, args.hf_epochs)
    train_purpose_classifier(args.epochs, real)
    train_blast_radius()
    train_temporal(args.epochs)
    train_risk(args.epochs, real)
    train_recommender(args.epochs, real)
    train_cost(args.epochs)
    train_failure(args.epochs)
    train_interop(args.epochs)
    train_rl(args.rl_episodes)
    train_anomaly(args.epochs, real)
    train_regression(args.epochs)
    train_vendor(args.epochs, real)
    train_copilot()
    train_policy()

    total_s = round(time.time() - t0, 2)
    trained = [e for e in RESULTS if e["status"] == "trained"]
    anchor_fail = [e for e in RESULTS if e["status"] == "anchor-fail"]
    errors = [e for e in RESULTS if e["status"] == "error"]
    anchors_total = sum(len(e.get("anchors", [])) for e in RESULTS)
    anchors_ok = sum(1 for e in RESULTS for a in e.get("anchors", []) if a["passed"])
    n_real = sum(1 for e in RESULTS if e.get("data_source") == "real")

    print(f"\n=== Summary: {len(trained)} trained, {len(anchor_fail)} anchor-fail, {len(errors)} errors, "
          f"anchors {anchors_ok}/{anchors_total}, real-data models {n_real}/15, wall {total_s}s ===")
    for e in RESULTS:
        ds = "real" if e.get("data_source") == "real" else "synthetic"
        print(f"  · {e['model']:<38s} [{ds}]")
    for e in errors:
        print(f"  ✗ {e['model']}: {e['error']}")
    for e in anchor_fail:
        print(f"  ⚠ {e['model']}: failed anchors")
        for a in e["anchors"]:
            if not a["passed"]:
                print(f"      - {a['check']}")

    # Persist report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "epochs": args.epochs,
        "rl_episodes": args.rl_episodes,
        "real_datasets": bool(real),
        "datasets_used": {
            "code_corpus": len(real.get("code", {}).get("corpus", [])) if real.get("code") else 0,
            "tls_hosts": len(real.get("tls", {}).get("cboms", [])) if real.get("tls") else 0,
            "vendor_records": len(real.get("vendor", {}).get("records", [])) if real.get("vendor") else 0,
        },
        "results": RESULTS,
        "summary": {
            "trained": len(trained), "anchor_fail": len(anchor_fail), "errors": len(errors),
            "anchors_ok": anchors_ok, "anchors_total": anchors_total, "wall_seconds": total_s,
        },
    }
    report_path.write_text(json.dumps(payload, indent=2, default=str))
    print(f"\nReport written to {report_path}")

    # Baseline comparison: models vs naive baselines on the SAME real data
    # and splits (see qtrust_ai/benchmark/compare.py). This is what turns
    # "F1 0.97" into a defensible claim — the model must beat the obvious
    # weekend implementations. Only runs on real data where baselines exist.
    if real:
        try:
            from qtrust_ai.benchmark.compare import BaselineComparison

            print("\n=== Baseline comparison (models vs naive baselines) ===\n")
            comp = BaselineComparison(seed=42)
            comparison = comp.run_all(real, epochs=args.epochs)
            comp_path = Path(args.benchmark_out) if args.benchmark_out else (
                REPO_ROOT / "qtrust_ai" / "artifacts" / "benchmark_comparison.json")
            comp.to_json(str(comp_path), comparison)
            s = comparison.get("summary", {})
            print(
                f"Baseline comparison: {s.get('comparisons_run')} comparisons, "
                f"{s.get('models_beat_best_baseline')} models beat their best baseline, "
                f"mean relative gain {s.get('mean_relative_gain')}"
            )
            print(f"Written to {comp_path}")
        except Exception as exc:  # pragma: no cover - defensive: never fail the run
            print(f"\n! Baseline comparison skipped ({exc})")

    sys.exit(0 if not errors and not anchor_fail else 1)


if __name__ == "__main__":
    main()
