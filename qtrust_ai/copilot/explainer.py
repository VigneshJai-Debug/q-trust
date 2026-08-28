"""
Security Copilot — evidence-backed, explainable answers (spec §20-21).

Architecture reference: ``qtrust_ai/README.md`` § Copilot.

Sits **after** the deterministic scanners + ML models (never before):

    deterministic scanners + ML models
                    │
                    ▼
            EvidenceExtractor   (qtrust_ai.copilot.evidence)
                    │
                    ▼
              SecurityCopilot  ← this module  (intent routing + explanation)
                    │
              ┌─────┴────────┐
              ▼              ▼
      deterministic    optional LLM polish
      explanation      (qtrust_ai.copilot.llm)

The copilot answers the seven questions of §26:

    q1 WHAT do I have?            → org inventory
    q2 WHAT is dangerous?         → risky assets + levels
    q3 WHY is it dangerous?       → top contributing factors
    q4 WHAT should replace it?    → purpose-aware PQC recommendation
    q5 HOW to migrate safely?     → constrained schedule + cost + failure
    q6 WHAT will happen?          → temporal risk trajectory
    q7 DID migration improve?     → regression / anomaly verdict

Intent detection is keyword-based and deterministic; explanations are built
from structured evidence with the optional LLM as a *polish layer* only.

Canonical example (spec §21):

    "Why is our payment API critical?"
      → Payment API → RSA-2048 → customer financial data → 17 dependencies
        → CNSA policy violation
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from qtrust_ai.copilot.evidence import AssetEvidence, EvidenceExtractor, OrgEvidence
from qtrust_ai.copilot.llm import LLMProvider, build_llm_provider

try:
    from qtrust_ai.migration.constrained_optimizer import (  # type: ignore
        ConstrainedOptimizer,
        MigrationAsset,
        OptimizerConfig,
    )
    HAS_OPTIMIZER = True
except Exception:  # pragma: no cover
    ConstrainedOptimizer = None  # type: ignore
    MigrationAsset = None  # type: ignore
    OptimizerConfig = None  # type: ignore
    HAS_OPTIMIZER = False


# Intent keywords (deterministic routing, spec §26 question types)
_INTENT_KEYWORDS: Dict[str, List[str]] = {
    "inventory": ["what do i have", "inventory", "how many", "list assets", "what assets", "what is in"],
    "danger": ["danger", "risky", "at risk", "exposed", "vulnerable", "high risk", "what is unsafe"],
    "why": ["why", "because", "reason", "explain why", "contribution", "factors"],
    "replace": ["replace", "migrate to", "what should", "recommend", "pqc target", "which algorithm", "ml-kem", "ml-dsa"],
    "how": ["how do", "how to", "schedule", "plan", "roadmap", "cost", "hours", "downtime", "when"],
    "whatif": ["what if", "what will happen", "project", "forecast", "180 day", "90 day", "30 day", "future", "trajectory"],
    "verify": ["did it", "improve", "regression", "worse", "verify", "confirm", "monitor", "drift"],
}


@dataclass
class CopilotAnswer:
    """One copilot response — evidence-backed, optionally LLM-polished."""

    question: str
    intent: str
    answer: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    confidence: float = 1.0
    llm_polished: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        return self.answer


@dataclass
class CopilotConfig:
    seed: int = 42
    use_llm: bool = True          # polish only — conclusions stay deterministic
    llm_provider: Optional[LLMProvider] = None
    top_k: int = 10


# Specific phrases that keyword matching would misroute
_PHRASE_INTENTS: List[tuple] = [
    ("what should we migrate", "danger"),   # ranked roadmap, not a single replacement
    ("what to migrate", "danger"),
    ("what should be migrated", "danger"),
    ("what should we replace", "replace"),
    ("what should replace", "replace"),
    ("what to replace", "replace"),
]


def detect_intent(question: str) -> str:
    """Keyword-based intent routing over the 7 question types."""
    q = question.lower().strip()
    if not q:
        return "inventory"
    for phrase, intent in _PHRASE_INTENTS:
        if phrase in q:
            return intent
    # 'why' must be checked before 'what should' (avoid wrong routing)
    if any(k in q for k in _INTENT_KEYWORDS["why"]):
        return "why"
    for intent, kws in _INTENT_KEYWORDS.items():
        if intent == "why":
            continue
        if any(k in q for k in kws):
            return intent
    return "general"


class SecurityCopilot:
    """Q-Trust Security Copilot — answers with evidence, not vibes.

    Attributes:
        config: :class:`CopilotConfig`.
        extractor: :class:`EvidenceExtractor` wired to the crypto graph.
        provider: The LLM provider (polish layer) in use.

    Example:
        >>> from qtrust_ai.graph.dependency_graph import DependencyGraph
        >>> g = DependencyGraph()
        >>> g.build_from_findings([{"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical"}], app_name="payment-api", app_criticality="critical")
        >>> copilot = SecurityCopilot(seed=0)
        >>> copilot.attach_graph(g)
        >>> ans = copilot.answer("Why is our payment API critical?")
        >>> "RSA-2048" in ans.answer
        True
    """

    def __init__(self, config: Optional[CopilotConfig] = None, seed: int = 42) -> None:
        self.config = config or CopilotConfig(seed=seed)
        self.config.seed = seed
        self.extractor = EvidenceExtractor(seed=seed)
        self.provider: LLMProvider = self.config.llm_provider or build_llm_provider()
        self._optimizer: Any = None
        self.is_trained = False

    # -- wiring ------------------------------------------------------------

    def attach_graph(self, graph: Any) -> "SecurityCopilot":
        """Attach the crypto dependency graph to the evidence extractor."""
        self.extractor.set_graph(graph)
        return self

    def _ensure_optimizer(self) -> Any:
        if self._optimizer is None and HAS_OPTIMIZER and ConstrainedOptimizer is not None:
            try:
                self._optimizer = ConstrainedOptimizer(seed=self.config.seed)  # type: ignore
            except Exception:
                self._optimizer = False  # type: ignore
        return self._optimizer

    # -- LLM polish --------------------------------------------------------

    def _polish(self, answer_text: str, question: str) -> str:
        """Optionally rephrase evidence-backed answer via LLM (polish only)."""
        if not self.config.use_llm:
            return answer_text
        system = (
            "You are Q-Trust Copilot, a CISO-facing assistant. Security conclusions "
            "are ALREADY computed and factual — do not invent new findings, numbers, "
            "or recommendations. Rewrite the provided evidence into concise, "
            "professional prose (2-5 sentences). Keep every number and fact intact."
        )
        user = f"Question: {question}\n\nEvidence-backed answer to rephrase:\n{answer_text}"
        out = self.provider.generate(system, user)
        if not out or out == answer_text:
            return answer_text
        return out

    # -- explanation builders (deterministic) ------------------------------

    def _explain_why(self, ev: AssetEvidence) -> str:
        factors = " ".join(f"+{f['contribution']} {f['factor']}" for f in ev.risk_factors)
        lines = [
            f"{ev.asset_name} is {ev.risk_level.lower()} (risk {ev.risk_score:.0f}) because:",
            f"  • {ev.algorithm} is quantum-vulnerable (purpose: {ev.purpose})",
            f"  • blast radius {ev.blast_radius_score:.0f}/100 — {ev.direct_dependencies} direct + "
            f"{ev.indirect_dependencies} indirect dependents, {ev.critical_services} critical services, "
            f"{len(ev.sensitive_datasets)} sensitive datasets",
        ]
        if ev.risk_factors:
            lines.append(f"  • top contributing factors: {factors}")
        if ev.recommended_pqc:
            lines.append(f"  • recommended replacement: {ev.recommended_pqc} (hybrid={ev.hybrid})")
        if ev.policy_violations:
            lines.append("  • policy violations: " + "; ".join(ev.policy_violations))
        return "\n".join(lines)

    def _explain_how(self, ev: AssetEvidence) -> str:
        if ev.recommended_pqc:
            target = f" → {ev.recommended_pqc}" + (" (hybrid)" if ev.hybrid else "")
        else:
            target = ""
        lines = [
            f"Migration plan for {ev.asset_name}: {ev.algorithm}{target}",
            f"  • cost: {ev.engineering_hours:.0f}h engineering, {ev.testing_hours:.0f}h testing, "
            f"${ev.total_cost_usd:,.0f} total, {ev.duration_days}d duration",
        ]
        if ev.failure_probability > 0:
            lines.append(f"  • failure risk: {ev.failure_probability:.1%}")
            for r in ev.failure_reasons[:3]:
                lines.append(f"      - {r['reason']} ({r['weight']:.0%})")
        if ev.interop_compatibility > 0:
            lines.append(f"  • interop: {ev.interop_compatibility:.1%} compatible, latency +{ev.interop_latency_increase:.1%}")
        if ev.policy_violations:
            lines.append("  • blocks policy: " + "; ".join(ev.policy_violations))
        return "\n".join(lines)

    def _explain_inventory(self, org: OrgEvidence) -> str:
        top = ", ".join(f"{a['asset']} ({a['risk']:.0f})" for a in org.top_risky_assets[:5]) or "none"
        lines = [
            f"Enterprise crypto inventory ({org.org_name}):",
            f"  • {org.asset_count} assets, {org.critical_asset_count} critical/high, {org.pqc_asset_count} already PQC",
            f"  • algorithms: {json.dumps(org.algorithm_counts)}",
            f"  • risk by level: {json.dumps(org.risk_by_level)}",
            f"  • top risky: {top}",
        ]
        return "\n".join(lines)

    def _explain_danger(self, org: OrgEvidence) -> str:
        lines = [f"Highest-risk assets ({org.org_name}):"]
        if not org.top_risky_assets:
            return lines[0] + "\n  • none found"
        for a in org.top_risky_assets[:self.config.top_k]:
            lines.append(f"  • {a['asset']}: {a['algorithm']} risk {a['risk']:.0f} [{a['level']}] → {a['pqc_target'] or 'unknown'}")
        return "\n".join(lines)

    def _explain_whatif(self, temporal: Dict[str, Any]) -> str:
        if not temporal:
            return "Temporal forecast unavailable (no graph attached)."
        risks = " → ".join(f"{r:.0f} ({d}d)" for r, d in zip(temporal["risks"], temporal["horizon_days"]))
        return (
            f"Projected quantum exposure: now {temporal['current_risk']:.0f} → {risks}.\n"
            f"  • confidence: {temporal['confidence']}\n"
            f"  • explanation: {temporal['explanation']}"
        )

    # -- answer API --------------------------------------------------------

    def answer(self, question: str, asset_ref: Optional[str] = None, context: str = "") -> CopilotAnswer:
        """Answer any of the 7 questions with evidence-backed explanation.

        Args:
            question: Natural-language question.
            asset_ref: Optional asset id/name to scope the answer.
            context: Optional code context for purpose inference.
        """
        intent = detect_intent(question)

        # q1/q2 — org-wide
        if intent in ("inventory", "danger", "general"):
            org = self.extractor.org_evidence(top_k=self.config.top_k)
            if intent == "danger":
                text = self._explain_danger(org)
                sources = ["dependency-graph", "quantum-exposure", "blast-radius"]
            else:
                text = self._explain_inventory(org)
                sources = ["dependency-graph"]
            answer = CopilotAnswer(question=question, intent=intent, answer=text, evidence=org.to_dict(), sources=sources)
            return self._finalize(answer, question)

        # Per-asset evidence for the rest
        ref = asset_ref or self._extract_asset_ref(question)
        ev = self.extractor.asset_evidence(ref, context=context) if ref else AssetEvidence(asset_id="", asset_name="")

        if intent == "why":
            text = self._explain_why(ev)
        elif intent == "replace":
            text = (f"{ev.asset_name}: {ev.algorithm} (purpose={ev.purpose}) → {ev.recommended_pqc or 'no recommendation'} "
                    f"(hybrid={ev.hybrid}). {ev.recommendation_rationale}".strip())
        elif intent == "how":
            text = self._explain_how(ev)
        elif intent == "whatif":
            temporal = self.extractor.temporal_evidence()
            text = self._explain_whatif(temporal)
            answer = CopilotAnswer(question=question, intent=intent, answer=text,
                                   evidence={"temporal": temporal}, sources=["temporal-gnn"])
            return self._finalize(answer, question)
        elif intent == "verify":
            text = ("Continuous monitoring: attach CryptoRegressionDetector + CryptoAnomalyDetector "
                    "snapshots to verify post-migration drift (q7). Evidence: " + ", ".join(ev.sources))
        else:
            text = self._explain_why(ev)

        answer = CopilotAnswer(
            question=question, intent=intent, answer=text,
            evidence=ev.to_dict(), sources=ev.sources,
        )
        return self._finalize(answer, question)

    def _finalize(self, answer: CopilotAnswer, question: str) -> CopilotAnswer:
        """Apply optional LLM polish; mark whether it was used."""
        if answer.intent not in ("inventory", "danger", "general"):
            # LLM polish only for focused answers (safer for org-wide lists)
            polished = self._polish(answer.answer, question)
            answer.llm_polished = polished != answer.answer and not polished.startswith("  •")
            if answer.llm_polished:
                answer.answer = polished
        return answer

    _ASSET_STOPWORDS = frozenset({
        "the", "our", "is", "why", "what", "how", "should", "we", "to",
        "a", "an", "this", "that", "critical", "risky", "dangerous",
        "it", "in", "of", "for", "with", "migrate", "migration",
        "replace", "replacement", "about", "tell", "me", "do", "does",
    })
    _QUESTION_PREFIXES = (
        "what should we replace", "what should replace", "what to replace",
        "how do we migrate", "how to migrate", "what should we migrate",
        "what to migrate", "should we migrate", "why is our", "why is the",
        "why is", "why", "how do we", "how do", "tell me about", "explain",
        "migrate", "replace",
    )

    def _extract_asset_ref(self, question: str) -> Optional[str]:
        """Best-effort asset / algorithm extraction from the question.

        Strips question templates, then prefers a token that actually matches a
        node name / algorithm in the attached graph (so question words like
        "replace" / "do" never become asset names).
        """
        q = question.lower().replace("?", "").strip()
        for prefix in self._QUESTION_PREFIXES:
            if q.startswith(prefix):
                q = q[len(prefix):].strip()
                break
        tokens = [t for t in q.split() if t not in self._ASSET_STOPWORDS and len(t) > 2]
        if not tokens:
            return None
        graph = self.extractor._graph  # noqa: SLF001 — internal wiring access
        if graph is not None:
            nodes = getattr(graph, "nodes", {}) or {}
            for tok in tokens:
                for nid, node in nodes.items():
                    name = str(getattr(node, "name", "")).lower()
                    algo = str(getattr(node, "algorithm", "") or "").lower()
                    if tok == name or tok == algo or tok in name or tok in algo or tok in str(nid).lower():
                        return tok
        return tokens[0]

    # -- convenience wrappers (spec §21 examples) --------------------------

    def why_critical(self, asset_ref: str) -> CopilotAnswer:
        """'Why is <asset> critical?' — the canonical copilot query."""
        return self.answer(f"Why is {asset_ref} critical?", asset_ref=asset_ref)

    def what_to_migrate(self, top_k: int = 10) -> CopilotAnswer:
        """'What should we migrate this quarter?' — ranked evidence-backed list."""
        org = self.extractor.org_evidence(top_k=top_k)
        text = self._explain_danger(org)
        text += "\n\nSchedule: see ConstrainedOptimizer (Sat 02-04 window, payment ≤5m downtime) via migration/constrained_optimizer.py"
        answer = CopilotAnswer(
            question="What should we migrate this quarter?",
            intent="danger",
            answer=text,
            evidence=org.to_dict(),
            sources=["dependency-graph", "quantum-exposure", "blast-radius", "pqc-recommender"],
        )
        return self._finalize(answer, "What should we migrate this quarter?")

    # -- API-consistency stubs (train/evaluate) ----------------------------

    def train(self, dataset: Optional[List[Dict[str, Any]]] = None, epochs: int = 3) -> Dict[str, Any]:
        """Fit nothing — the copilot is deterministic. Kept for API parity.

        ``train()`` validates the wiring: it runs the extractor against the
        attached graph (if any) and reports how many models resolved.
        """
        self.is_trained = True
        org = self.extractor.org_evidence(top_k=self.config.top_k)
        return {
            "mode": "deterministic",
            "assets_scanned": org.asset_count,
            "models_resolved": self._resolved_models(),
            "llm_provider": self.provider.name,
            "llm_configured": bool(getattr(self.provider, "configured", True)),
        }

    def _resolved_models(self) -> Dict[str, bool]:
        return {
            "dependency_graph": self.extractor._graph is not None,  # noqa: SLF001
            "blast_radius": self.extractor._blast not in (None, False),  # noqa: SLF001
            "quantum_exposure": self.extractor._exposure not in (None, False),  # noqa: SLF001
            "recommender": self.extractor._recommender not in (None, False),  # noqa: SLF001
            "cost": self.extractor._cost not in (None, False),  # noqa: SLF001
            "failure": self.extractor._failure not in (None, False),  # noqa: SLF001
            "interop": self.extractor._interop not in (None, False),  # noqa: SLF001
            "temporal": self.extractor._gnn not in (None, False),  # noqa: SLF001
        }

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate answer quality on a small question→expected-substring set.

        Args:
            dataset: List of ``{"question": str, "expect": str}``. If ``None`` a
                built-in anchor set (spec examples) is used.

        Returns:
            Dict with ``passed``, ``total``, ``accuracy``, ``intent_map``.
        """
        if dataset is None:
            dataset = [
                {"question": "Why is our payment API critical?", "expect": "RSA-2048"},
                {"question": "What should we migrate this quarter?", "expect": "risk"},
                {"question": "What do we have?", "expect": "assets"},
            ]
        passed = 0
        intent_map: Dict[str, int] = {}
        for ex in dataset:
            q = ex["question"]
            ans = self.answer(q)
            intent_map[ans.intent] = intent_map.get(ans.intent, 0) + 1
            if ex.get("expect", "").lower() in ans.answer.lower():
                passed += 1
        total = len(dataset)
        return {
            "passed": passed,
            "total": total,
            "accuracy": round(passed / total, 3) if total else 0.0,
            "intent_map": intent_map,
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== SecurityCopilot demo — evidence-backed, LLM explains not decides ===\n")
    from qtrust_ai.graph.dependency_graph import DependencyGraph

    g = DependencyGraph()
    g.build_from_findings(
        [
            {"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical", "key_size": 2048},
            {"algorithm": "AES-256", "file": "services/payment/crypto.py", "criticality": "critical"},
            {"algorithm": "ECDSA-P256", "file": "services/auth/tls.go", "criticality": "high"},
            {"algorithm": "SHA-256", "file": "services/common/hash.py", "criticality": "medium"},
            {"algorithm": "ML-KEM-768", "file": "services/ingress/pqc.rs", "criticality": "medium"},
        ],
        app_name="payment-api", app_criticality="critical",
    )
    copilot = SecurityCopilot(seed=42)
    copilot.attach_graph(g)
    print(f"[train] {json.dumps(copilot.train(), indent=2)}\n")

    queries = [
        "Why is our payment API critical?",
        "What do I have?",
        "What is dangerous?",
        "What should replace RSA-2048?",
        "How do we migrate payment-api?",
        "What will happen in 180 days?",
    ]
    for q in queries:
        ans = copilot.answer(q)
        print(f"Q: {q}  [intent={ans.intent}]")
        print(f"A: {ans.answer}\n")

    print("--- q7: did migration improve? ---")
    from qtrust_ai.monitoring.regression import CryptoRegressionDetector
    reg = CryptoRegressionDetector()
    verdict = reg.check_ci_gate(
        {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]},
        {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]},
    )
    print(f"blocked={verdict.blocked} severity={verdict.severity} findings={len(verdict.findings)}")

    eval_res = copilot.evaluate()
    print(f"\n[evaluate] {json.dumps(eval_res, indent=2)}")
    assert eval_res["passed"] >= 2, "anchor evaluation failed"
    print("✓ copilot anchor evaluation passed")
