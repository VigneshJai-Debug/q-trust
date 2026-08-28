"""
Copilot evidence extraction — deterministic facts from the intelligence stack.

Architecture reference: ``qtrust_ai/README.md`` §20-21 (Security Copilot).

The copilot **never decides security outcomes**. It gathers *evidence* from the
deterministic scanners + ML models (crypto graph, blast radius, quantum
exposure, PQC recommender, cost / failure / interop predictors) and hands that
evidence to the explanation layer (``qtrust_ai.copilot.explainer``), which may
optionally be rephrased by an LLM (``qtrust_ai.copilot.llm``).

Pipeline:

    deterministic scanners + ML models (graph, blast radius, risk, cost, ...)
                        │
                        ▼
              EvidenceExtractor  ← this module
                        │
                        ▼
                CopilotEvidence  (trusted, structured)
                        │
                        ▼
              explainer + optional LLM polish → human-readable answer

Canonical example (spec §21):

    "Why is our payment API critical?"
      → Payment API → RSA-2048 → customer financial data → 17 dependencies
        → CNSA policy violation

All extraction is deterministic and CPU-friendly; every downstream model is
optional (try/except guarded) so evidence degrades gracefully when a model is
not importable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Downstream intelligence models — all optional, all with deterministic fallbacks
try:
    from qtrust_ai.graph.dependency_graph import DependencyGraph  # type: ignore
    HAS_DEPENDENCY_GRAPH = True
except Exception:  # pragma: no cover
    DependencyGraph = None  # type: ignore
    HAS_DEPENDENCY_GRAPH = False

try:
    from qtrust_ai.graph.blast_radius import BlastRadius, BlastRadiusResult  # type: ignore
    HAS_BLAST_RADIUS = True
except Exception:  # pragma: no cover
    BlastRadius = None  # type: ignore
    BlastRadiusResult = None  # type: ignore
    HAS_BLAST_RADIUS = False

try:
    from qtrust_ai.risk.quantum_exposure import QuantumExposureModel, ExposureFactors  # type: ignore
    HAS_QUANTUM_EXPOSURE = True
except Exception:  # pragma: no cover
    QuantumExposureModel = None  # type: ignore
    ExposureFactors = None  # type: ignore
    HAS_QUANTUM_EXPOSURE = False

try:
    from qtrust_ai.migration.replacement_recommender import PQCRecommender  # type: ignore
    HAS_RECOMMENDER = True
except Exception:  # pragma: no cover
    PQCRecommender = None  # type: ignore
    HAS_RECOMMENDER = False

try:
    from qtrust_ai.migration.cost_predictor import MigrationCostPredictor, MigrationCostFeatures  # type: ignore
    HAS_COST = True
except Exception:  # pragma: no cover
    MigrationCostPredictor = None  # type: ignore
    MigrationCostFeatures = None  # type: ignore
    HAS_COST = False

try:
    from qtrust_ai.migration.failure_predictor import MigrationFailurePredictor  # type: ignore
    HAS_FAILURE = True
except Exception:  # pragma: no cover
    MigrationFailurePredictor = None  # type: ignore
    HAS_FAILURE = False

try:
    from qtrust_ai.migration.interoperability import InteroperabilityPredictor  # type: ignore
    HAS_INTEROP = True
except Exception:  # pragma: no cover
    InteroperabilityPredictor = None  # type: ignore
    HAS_INTEROP = False

try:
    from qtrust_ai.discovery.algorithm_classifier import AlgorithmPurposeClassifier  # type: ignore
    HAS_PURPOSE = True
except Exception:  # pragma: no cover
    AlgorithmPurposeClassifier = None  # type: ignore
    HAS_PURPOSE = False

try:
    from qtrust_ai.graph.temporal_gnn import TemporalGNN, GraphSnapshot  # type: ignore
    HAS_TEMPORAL = True
except Exception:  # pragma: no cover
    TemporalGNN = None  # type: ignore
    GraphSnapshot = None  # type: ignore
    HAS_TEMPORAL = False


# Heuristic purpose map used when AlgorithmPurposeClassifier is unavailable.
_SIGNATURE_ALGOS = {"RSA", "RSA-PSS", "ECDSA", "ED25519", "ED448", "DSA", "ML-DSA", "SLH-DSA"}
_KEM_ALGOS = {"ECDH", "X25519", "X448", "DH", "ML-KEM", "HQC", "KYBER"}
_SYMMETRIC_ALGOS = {"AES", "AES-128", "AES-192", "AES-256", "CHACHA20", "CHACHA20-POLY1305", "3DES", "DES"}
_HASH_ALGOS = {"SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "MD5", "BLAKE2", "HMAC"}


# Family → purpose defaults (dual-use algorithms get their modern primary
# purpose; matches the recommender's ``_CLASSICAL_PURPOSE_PRIORS`` so that
# e.g. RSA-2048 → ML-DSA, ECDH → ML-KEM, AES → AES-256).
_PURPOSE_DEFAULTS: List[tuple] = [
    ("RSA", "signature"), ("DSA", "signature"), ("ECDSA", "signature"),
    ("ED25519", "signature"), ("ED448", "signature"),
    ("ML-DSA", "signature"), ("SLH-DSA", "signature"), ("FALCON", "signature"), ("FN-DSA", "signature"),
    ("ECDH", "key-establishment"), ("X25519", "key-establishment"), ("X448", "key-establishment"),
    ("DH", "key-establishment"), ("ML-KEM", "key-establishment"), ("HQC", "key-establishment"), ("KYBER", "key-establishment"),
    ("AES", "encryption"), ("CHACHA20", "encryption"), ("3DES", "encryption"), ("DES", "encryption"),
    ("SHA", "hashing"), ("SHA3", "hashing"), ("HMAC", "hashing"), ("MD5", "hashing"), ("BLAKE2", "hashing"),
]


def infer_purpose(algorithm: str, context: str = "") -> str:
    """Deterministic purpose inference (signature / key-establishment / ...).

    When *context* is provided the :class:`AlgorithmPurposeClassifier` is
    consulted first; otherwise (or on failure) a deterministic family→purpose
    map is used so dual-use algorithms (RSA, ECDH) get their modern primary
    purpose rather than an arbitrary classifier default.
    """
    if context.strip() and HAS_PURPOSE and AlgorithmPurposeClassifier is not None:
        try:
            res = AlgorithmPurposeClassifier(seed=42).predict(algorithm, context=context)  # type: ignore
            return res.purpose.value
        except Exception:
            pass
    algo_up = str(algorithm).upper()
    for fam, purpose in _PURPOSE_DEFAULTS:
        if algo_up.startswith(fam):
            return purpose
    if "RANDOM" in algo_up or "DRBG" in algo_up:
        return "randomness"
    if "CERT" in algo_up:
        return "certificate-handling"
    return "unknown"


# ---------------------------------------------------------------------------
# Evidence dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AssetEvidence:
    """Structured, trusted evidence for one asset (spec §21, §26 q1-q5)."""

    asset_id: str
    asset_name: str
    algorithm: str = "unknown"
    purpose: str = "unknown"
    criticality: str = "medium"
    risk_score: float = 0.0
    risk_level: str = "unknown"
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)  # [{factor, contribution}]
    blast_radius_score: float = 0.0
    blast_radius_level: str = "unknown"
    direct_dependencies: int = 0
    indirect_dependencies: int = 0
    critical_services: int = 0
    sensitive_datasets: List[str] = field(default_factory=list)
    dependency_count: int = 0
    recommended_pqc: str = ""
    hybrid: bool = False
    recommendation_rationale: str = ""
    engineering_hours: float = 0.0
    testing_hours: float = 0.0
    duration_days: int = 0
    total_cost_usd: float = 0.0
    failure_probability: float = 0.0
    failure_reasons: List[Dict[str, float]] = field(default_factory=list)
    interop_compatibility: float = 0.0
    interop_latency_increase: float = 0.0
    policy_violations: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OrgEvidence:
    """Enterprise-wide evidence snapshot — answers q1 (WHAT do I have?)."""

    org_name: str
    asset_count: int = 0
    algorithm_counts: Dict[str, int] = field(default_factory=dict)
    purpose_counts: Dict[str, int] = field(default_factory=dict)
    critical_asset_count: int = 0
    pqc_asset_count: int = 0
    total_risk: float = 0.0
    risk_by_level: Dict[str, int] = field(default_factory=dict)
    top_risky_assets: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# EvidenceExtractor
# ---------------------------------------------------------------------------

class EvidenceExtractor:
    """Gather deterministic evidence from the intelligence stack.

    All models are instantiated lazily and reused; every model call is guarded
    so extraction never raises when a backend is missing.

    Example:
        >>> from qtrust_ai.graph.dependency_graph import DependencyGraph
        >>> g = DependencyGraph()
        >>> g.build_from_findings([{"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical"}], app_name="payment-api", app_criticality="critical")
        >>> ex = EvidenceExtractor(seed=0)
        >>> ev = ex.asset_evidence("payment-api")
        >>> ev.dependency_count >= 1
        True
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._graph: Any = None
        # Lazy model cache
        self._blast: Any = None
        self._exposure: Any = None
        self._recommender: Any = None
        self._cost: Any = None
        self._failure: Any = None
        self._interop: Any = None
        self._gnn: Any = None

    # -- graph wiring ------------------------------------------------------

    def set_graph(self, graph: Any) -> "EvidenceExtractor":
        """Attach a crypto dependency graph (``DependencyGraph`` or compatible)."""
        self._graph = graph
        self._blast = None  # rebuilt against new graph
        return self

    # -- lazy model factories ----------------------------------------------

    def _ensure_models(self) -> None:
        if self._blast is None and self._graph is not None and HAS_BLAST_RADIUS and BlastRadius is not None:
            try:
                self._blast = BlastRadius(self._graph)  # type: ignore
            except Exception:
                self._blast = False  # type: ignore
        if self._exposure is None and HAS_QUANTUM_EXPOSURE and QuantumExposureModel is not None:
            try:
                self._exposure = QuantumExposureModel()  # type: ignore
            except Exception:
                self._exposure = False  # type: ignore
        if self._recommender is None and HAS_RECOMMENDER and PQCRecommender is not None:
            try:
                self._recommender = PQCRecommender(seed=self.seed)  # type: ignore
            except Exception:
                self._recommender = False  # type: ignore
        if self._cost is None and HAS_COST and MigrationCostPredictor is not None:
            try:
                self._cost = MigrationCostPredictor(seed=self.seed)  # type: ignore
            except Exception:
                self._cost = False  # type: ignore
        if self._failure is None and HAS_FAILURE and MigrationFailurePredictor is not None:
            try:
                self._failure = MigrationFailurePredictor(seed=self.seed)  # type: ignore
            except Exception:
                self._failure = False  # type: ignore
        if self._interop is None and HAS_INTEROP and InteroperabilityPredictor is not None:
            try:
                self._interop = InteroperabilityPredictor(seed=self.seed)  # type: ignore
            except Exception:
                self._interop = False  # type: ignore
        if self._gnn is None and HAS_TEMPORAL and TemporalGNN is not None:
            try:
                self._gnn = TemporalGNN(seed=self.seed)  # type: ignore
            except Exception:
                self._gnn = False  # type: ignore

    # -- graph helpers -----------------------------------------------------

    def _resolve_node(self, ref: str) -> Optional[Any]:
        """Resolve *ref* (node id or name) to a graph node, if graph attached.

        Match priority: exact id → exact name (case-insensitive) → crypto
        primitive by algorithm → substring (skipping DATA nodes) → any
        substring. Preferring primitives keeps algorithm references like
        ``"rsa-2048"`` from resolving to the synthetic ``data:rsa-2048`` node.
        """
        if self._graph is None:
            return None
        nodes = getattr(self._graph, "nodes", {})
        if not nodes:
            return None
        if ref in nodes:
            return nodes[ref]
        ref_l = ref.lower()
        # Exact name (case-insensitive)
        for nid, node in nodes.items():
            if str(getattr(node, "name", "")).lower() == ref_l:
                return node
        # Crypto primitive by algorithm
        for nid, node in nodes.items():
            if str(getattr(node, "algorithm", "") or "").lower() == ref_l:
                return node
        # Substring, skipping DATA placeholders (avoid data:rsa-2048 shadows)
        for nid, node in nodes.items():
            ntype = str(getattr(node, "type", "")).lower()
            if "data" in ntype:
                continue
            if ref_l in str(nid).lower() or ref_l in str(getattr(node, "name", "")).lower():
                return node
        # Any substring as last resort
        for nid, node in nodes.items():
            if ref_l in str(nid).lower() or ref_l in str(getattr(node, "name", "")).lower():
                return node
        return None

    def _dataset_names(self, affected_nodes: List[str]) -> List[str]:
        """Resolve DATA node names inside the blast zone (for evidence display)."""
        names: List[str] = []
        graph = self._graph
        if graph is None:
            return names
        nodes = getattr(graph, "nodes", {}) or {}
        for nid in affected_nodes:
            node = nodes.get(nid)
            if node is None:
                continue
            ntype = str(getattr(node, "type", "")).lower()
            if "data" in ntype or "dataset" in ntype:
                names.append(str(getattr(node, "name", nid)))
        return names[:5]

    def _node_primitives(self, node_id: str) -> List[str]:
        """Crypto primitives downstream of *node_id*, deterministically ordered.

        Ordering prefers the most security-relevant primitive first (Shor-broken
        asymmetric → weakened → symmetric/hash → PQC) so the copilot surfaces
        the dangerous algorithm, not an arbitrary one (dict/set order is not
        stable).
        """
        prims: List[str] = []
        graph = self._graph
        if graph is None:
            return prims
        try:
            down = set(graph.downstream(node_id, max_hops=6))
        except Exception:
            down = set()
        down.add(node_id)
        for nid in down:
            node = graph.nodes.get(nid)  # type: ignore
            ntype = str(getattr(node, "type", "")).lower()
            if "crypto_primitive" in ntype or "primitive" in ntype:
                algo = getattr(node, "algorithm", None) or getattr(node, "name", "")
                if algo and algo not in prims:
                    prims.append(algo)
        return sorted(prims, key=lambda a: (_prim_rank(a), a))

    def _node_criticality(self, node: Any) -> str:
        crit = str(getattr(node, "criticality", "medium") or "medium").lower()
        return crit if crit in ("low", "medium", "high", "critical") else "medium"

    # -- per-asset extraction ----------------------------------------------

    def asset_evidence(self, asset_ref: str, context: str = "") -> AssetEvidence:
        """Extract full evidence for one asset (id or name).

        Combines: blast radius, quantum exposure (risk + factors), PQC
        recommendation, cost, failure, and interop predictions.
        """
        self._ensure_models()
        node = self._resolve_node(asset_ref)
        name = getattr(node, "name", None) or asset_ref
        node_id = getattr(node, "id", None) or asset_ref
        criticality = self._node_criticality(node) if node is not None else "medium"
        sources: List[str] = ["dependency-graph"]

        prims = self._node_primitives(node_id) if node is not None else [asset_ref]
        prim = prims[0] if prims else (getattr(node, "algorithm", None) or "unknown")
        purpose = infer_purpose(prim, context=context)

        ev = AssetEvidence(
            asset_id=str(node_id),
            asset_name=str(name),
            algorithm=str(prim),
            purpose=purpose,
            criticality=criticality,
        )

        # Blast radius
        if self._blast:
            try:
                br = self._blast.compute(prim)  # type: ignore
                counts = getattr(br, "counts", {}) or {}
                ev.blast_radius_score = round(float(br.score), 1)
                ev.blast_radius_level = str(br.level)
                ev.direct_dependencies = int(counts.get("direct", 0) or 0)
                ev.indirect_dependencies = int(counts.get("indirect", 0) or 0)
                ev.critical_services = int(counts.get("critical", 0) or 0)
                ev.sensitive_datasets = self._dataset_names(getattr(br, "affected_nodes", []) or [])
                ev.dependency_count = ev.direct_dependencies + ev.indirect_dependencies
                sources.append("blast-radius")
            except Exception:
                pass

        # Quantum exposure risk + contributing factors
        if self._exposure and ExposureFactors is not None:
            try:
                sensitivity = _sensitivity_for(prim, node)
                factors = ExposureFactors(  # type: ignore
                    algorithm=prim,
                    sensitivity=sensitivity,
                    lifetime_years=5,
                    exposure_years=3.0,
                    attractiveness=_attractiveness(criticality),
                    lead_time_years=2,
                )
                res = self._exposure.predict(factors)  # type: ignore
                ev.risk_score = round(float(res.score), 1)
                ev.risk_level = str(res.level)
                ev.risk_factors = _top_factors(res, prim, criticality, ev.dependency_count)
                sources.append("quantum-exposure")
            except Exception:
                pass

        # PQC replacement recommendation (purpose-aware)
        if self._recommender:
            try:
                rec = self._recommender.recommend(prim, purpose=purpose, context=context)  # type: ignore
                ev.recommended_pqc = str(rec.primary_pqc)
                ev.hybrid = bool(getattr(rec, "hybrid", False))
                ev.recommendation_rationale = str(getattr(rec, "rationale", "") or getattr(rec, "explanation", ""))
                sources.append("pqc-recommender")
            except Exception:
                pass

        # Cost prediction
        if self._cost and MigrationCostFeatures is not None:
            try:
                kwargs = dict(
                    app_type=_app_type_for(name),
                    protocol=_protocol_for(prim),
                    library="openssl",
                    library_version="3.0.8",
                    hardware="x86",
                    legacy=criticality in ("high", "critical"),
                    target_pqc="hybrid",
                    dependency_count=max(1, ev.dependency_count),
                )
                feats = MigrationCostFeatures(**{k: v for k, v in kwargs.items() if k in MigrationCostFeatures.__dataclass_fields__})  # type: ignore
                pred = self._cost.predict(feats)  # type: ignore
                ev.engineering_hours = round(float(pred.engineering_hours), 1)
                ev.testing_hours = round(float(pred.testing_hours), 1)
                ev.duration_days = int(pred.duration_days)
                ev.total_cost_usd = round(float(pred.total_cost_usd), 2)
                sources.append("cost-predictor")
            except Exception:
                pass

        # Failure prediction
        if self._failure:
            try:
                ffeats = dict(
                    app_type=_app_type_for(name),
                    protocol=_protocol_for(prim),
                    library="openssl",
                    library_version="3.0.8",
                    hardware="x86",
                    dependency_count=max(1, ev.dependency_count),
                    pqc_impl=ev.recommended_pqc or "ML-KEM-768",
                )
                fres = self._failure.predict(**_failure_kwargs(ffeats))  # type: ignore
                ev.failure_probability = round(float(getattr(fres, "failure_prob", 0.0) or 0.0), 4)
                reasons = list(getattr(fres, "top_reasons", None) or [])
                ev.failure_reasons = [_reason_entry(r) for r in reasons]
                sources.append("failure-predictor")
            except Exception:
                pass

        # Interop (only meaningful when the target is an asymmetric PQC)
        _pqc_target = ev.recommended_pqc.upper()
        _interop_relevant = any(x in _pqc_target for x in ("ML-KEM", "ML-DSA", "SLH", "HQC", "FALCON", "HYBRID", "X25519"))
        if self._interop and _interop_relevant:
            try:
                ikwargs = dict(
                    client_library="openssl", client_version="3.0.8",
                    server_library="openssl", server_version="3.0.8",
                    client_hardware="x86", server_hardware="x86",
                    protocol=_protocol_for(prim), pqc_alg=ev.recommended_pqc,
                    baseline_latency_ms=30.0,
                )
                ires = self._interop.predict(**_interop_kwargs(ikwargs))  # type: ignore
                ev.interop_compatibility = round(float(getattr(ires, "compatibility_prob", 0.0) or 0.0), 4)
                ev.interop_latency_increase = round(float(getattr(ires, "latency_delta_percent", 0.0) or 0.0), 3)
                sources.append("interop-predictor")
            except Exception:
                pass

        ev.sources = sources
        return ev

    # -- org-wide extraction ------------------------------------------------

    def org_evidence(self, org_name: str = "enterprise", top_k: int = 10) -> OrgEvidence:
        """Aggregate evidence across the attached graph (q1 + q2)."""
        graph = self._graph
        org = OrgEvidence(org_name=org_name)
        if graph is None:
            return org
        nodes = getattr(graph, "nodes", {}) or {}
        if not nodes:
            return org

        # Algorithm / purpose census across ALL crypto primitives in the graph
        for node in nodes.values():
            ntype = str(getattr(node, "type", "")).lower()
            if "crypto_primitive" not in ntype and "primitive" not in ntype:
                continue
            algo = getattr(node, "algorithm", None) or getattr(node, "name", "")
            if not algo or algo in ("UNKNOWN", "WRAPPER", "OBFUSCATED"):
                continue
            org.algorithm_counts[algo] = org.algorithm_counts.get(algo, 0) + 1
            purpose = infer_purpose(str(algo))
            org.purpose_counts[purpose] = org.purpose_counts.get(purpose, 0) + 1
            if "ML-" in algo or "SLH" in algo or "HQC" in algo:
                org.pqc_asset_count += 1

        # Per-asset scan: application nodes (or all nodes when no apps exist)
        apps = [n for n in nodes.values() if "application" in str(getattr(n, "type", "")).lower()]
        scan_nodes = apps or list(nodes.values())

        per_asset: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for node in scan_nodes[:200]:  # cap for CPU-friendliness
            ref = getattr(node, "name", None) or getattr(node, "id", "")
            if not ref or ref in seen:
                continue
            seen.add(ref)
            ev = self.asset_evidence(str(ref))
            if ev.algorithm in ("unknown", ""):
                continue
            org.asset_count += 1
            if ev.criticality in ("high", "critical"):
                org.critical_asset_count += 1
            org.total_risk += ev.risk_score
            level = ev.risk_level if ev.risk_level in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL") else "UNKNOWN"
            org.risk_by_level[level] = org.risk_by_level.get(level, 0) + 1
            per_asset.append({"asset": ev.asset_name, "risk": ev.risk_score, "level": ev.risk_level,
                              "algorithm": ev.algorithm, "pqc_target": ev.recommended_pqc})

        per_asset.sort(key=lambda d: d["risk"], reverse=True)
        org.top_risky_assets = per_asset[:top_k]
        return org

    def temporal_evidence(self, horizon_days: Optional[List[int]] = None) -> Dict[str, Any]:
        """Forecast risk evolution from the graph (q6 — WHAT will happen?)."""
        self._ensure_models()
        if not self._gnn or GraphSnapshot is None:
            return {}
        try:
            snap = GraphSnapshot.from_graph(self._graph, t=0, day=0)  # type: ignore
            traj = self._gnn.predict_trajectory([snap], horizon_days=horizon_days or [30, 90, 180])  # type: ignore
            return {
                "current_risk": traj.current_risk,
                "risks": traj.risks,
                "horizon_days": traj.horizon_days,
                "confidence": traj.confidence,
                "intervals": traj.intervals,
                "explanation": traj.explanation,
            }
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------

def _prim_rank(algo: str) -> int:
    """Security-relevance rank for deterministic primitive ordering.

    RSA/DSA/DH first (the canonical 'payment API → RSA-2048' case), then
    ECC/Edwards, then Grover-weakened, symmetric/hash, and finally PQC.
    """
    up = algo.upper()
    if up.startswith(("RSA", "DSA", "DH", "RSA-PSS")):
        return 0
    if up.startswith(("ECDSA", "ECDH", "X25519", "X448", "ED25519", "ED448")):
        return 1
    if "DES" in up or up.startswith("AES-128"):
        return 2  # weakened by Grover
    if up.startswith(("AES", "CHACHA20", "SHA", "HMAC", "MD5", "BLAKE2")):
        return 3
    if up.startswith(("ML-KEM", "ML-DSA", "SLH", "HQC", "FALCON", "KYBER")):
        return 4  # already PQC
    return 5


def _sensitivity_for(algorithm: str, node: Any) -> int:
    sens = getattr(node, "sensitivity", None)
    if isinstance(sens, (int, float)) and 1 <= sens <= 5:
        return int(sens)
    algo_up = algorithm.upper()
    if any(x in algo_up for x in ("RSA", "ECDSA", "ECDH")):
        return 4
    if "AES" in algo_up:
        return 3
    return 2


def _attractiveness(criticality: str) -> int:
    return {"low": 2, "medium": 3, "high": 4, "critical": 5}.get(criticality, 3)


def _top_factors(res: Any, algorithm: str, criticality: str, deps: int) -> List[Dict[str, Any]]:
    """Deterministic top contributing factors (spec §15: +32 quantum vuln, ...)."""
    factors: List[Dict[str, Any]] = []
    vuln_map = {
        "RSA": 32, "RSA-2048": 32, "RSA-4096": 22, "ECDSA": 26, "ECDSA-P256": 26,
        "ECDH": 26, "X25519": 26, "DSA": 35, "DES": 30, "3DES": 30,
    }
    vuln = vuln_map.get(algorithm.upper(), 8 if ("ML-" in algorithm or "SLH" in algorithm or "HQC" in algorithm) else 20)
    factors.append({"factor": "quantum vulnerability", "contribution": vuln})
    factors.append({"factor": "business criticality", "contribution": {"low": 6, "medium": 12, "high": 19, "critical": 24}.get(criticality, 12)})
    lifetime = float(getattr(res, "hndl_risk", 0.0) or 0.0)
    factors.append({"factor": "HNDL exposure", "contribution": round(min(18, lifetime), 1)})
    factors.append({"factor": "dependency blast radius", "contribution": round(min(11, deps * 0.6), 1)})
    factors.append({"factor": "compliance urgency", "contribution": 6 if criticality in ("high", "critical") else 3})
    factors.sort(key=lambda f: f["contribution"], reverse=True)
    return factors


def _app_type_for(name: str) -> str:
    n = str(name).lower()
    if "payment" in n or "banking" in n:
        return "banking-api"
    if "auth" in n or "token" in n:
        return "auth-service"
    if "gateway" in n or "tls" in n or "proxy" in n:
        return "tls-gateway"
    if "iot" in n or "firmware" in n or "device" in n:
        return "iot-firmware"
    if "mobile" in n or "app" in n:
        return "mobile"
    if "hsm" in n or "vault" in n:
        return "hsm"
    return "web"


def _protocol_for(algorithm: str) -> str:
    algo_up = algorithm.upper()
    if any(x in algo_up for x in ("ML-KEM", "ML-DSA", "SLH", "HQC")):
        return "TLS1.3"
    if "ED" in algo_up:
        return "SSH"
    return "TLS1.3"


def _failure_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build ``predict(features=...)`` kwargs from a plain dict."""
    try:
        from qtrust_ai.migration.failure_predictor import FailureFeatures  # type: ignore
        feats = FailureFeatures(**{k: v for k, v in kwargs.items() if k in FailureFeatures.__dataclass_fields__})  # type: ignore
        return {"features": feats}
    except Exception:
        return kwargs


def _interop_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build ``predict(features=...)`` kwargs for the interop predictor."""
    try:
        from qtrust_ai.migration.interoperability import InteropFeatures  # type: ignore
        feats = InteropFeatures(**{k: v for k, v in kwargs.items() if k in InteropFeatures.__dataclass_fields__})  # type: ignore
        return {"features": feats}
    except Exception:
        return kwargs


def _reason_entry(r: Any) -> Dict[str, float]:
    """Normalise a failure reason (tuple ``(label, share)`` or dict) to dict."""
    if isinstance(r, dict):
        return {"reason": str(r.get("reason", r.get("label", ""))), "weight": float(r.get("weight", r.get("probability", 0.0)) or 0.0)}
    if isinstance(r, (tuple, list)) and len(r) >= 2:
        return {"reason": str(r[0]), "weight": float(r[1] or 0.0)}
    return {"reason": str(r), "weight": 0.0}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== EvidenceExtractor demo — 'why is our payment API critical?' ===\n")
    from qtrust_ai.graph.dependency_graph import DependencyGraph

    g = DependencyGraph()
    g.build_from_findings(
        [
            {"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical", "key_size": 2048},
            {"algorithm": "AES-256", "file": "services/payment/crypto.py", "criticality": "critical"},
            {"algorithm": "ECDSA-P256", "file": "services/auth/tls.go", "criticality": "high"},
            {"algorithm": "ML-KEM-768", "file": "services/ingress/pqc.rs", "criticality": "medium"},
        ],
        app_name="payment-api", app_criticality="critical",
    )
    ex = EvidenceExtractor(seed=42)
    ex.set_graph(g)
    ev = ex.asset_evidence("payment-api")
    print(f"asset        : {ev.asset_name}")
    print(f"algorithm    : {ev.algorithm} (purpose={ev.purpose})")
    print(f"risk         : {ev.risk_score} [{ev.risk_level}]")
    print("top factors  : " + ", ".join(f"+{f['contribution']} {f['factor']}" for f in ev.risk_factors))
    print(f"blast radius : {ev.blast_radius_score} ({ev.blast_radius_level}) direct={ev.direct_dependencies} indirect={ev.indirect_dependencies} critical={ev.critical_services}")
    print(f"recommended  : {ev.recommended_pqc} (hybrid={ev.hybrid})")
    print(f"cost         : {ev.engineering_hours}h eng, {ev.testing_hours}h test, {ev.duration_days}d, ${ev.total_cost_usd:,.0f}")
    print(f"failure      : {ev.failure_probability:.1%} {ev.failure_reasons}")
    print(f"sources      : {ev.sources}")

    org = ex.org_evidence(org_name="demo-bank")
    print(f"\norg          : {org.asset_count} assets, {org.critical_asset_count} critical, {org.pqc_asset_count} already PQC")
    print(f"algorithms   : {org.algorithm_counts}")
    print(f"top risky    : {org.top_risky_assets[:3]}")
