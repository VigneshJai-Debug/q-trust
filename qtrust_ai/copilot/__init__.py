"""
qtrust_ai.copilot — Security Copilot package (Phase 5 Interface).

Per ``qtrust_ai/README.md`` § Copilot (spec §20-21):

* :mod:`qtrust_ai.copilot.evidence` — deterministic evidence extraction from
  the intelligence stack (crypto graph, blast radius, quantum exposure,
  PQC recommender, cost / failure / interop). ``EvidenceExtractor`` answers
  q1-q5 with *trusted structured results*.
* :mod:`qtrust_ai.copilot.llm` — optional LLM hook (``LLM explains, never
  decides``). Deterministic passthrough by default; OpenAI-compatible provider
  when ``QTRUST_LLM_API_KEY`` is set. Never required for correctness.
* :mod:`qtrust_ai.copilot.explainer` — ``SecurityCopilot``: intent routing
  over the 7 questions of §26 + human-readable explanation, with optional LLM
  polish. "Why is our payment API critical?" → ``Payment API → RSA-2048 →
  customer financial data → 17 dependencies → CNSA policy violation``.

Pipeline (spec §20):

    deterministic scanners + ML models → EvidenceExtractor → SecurityCopilot
        → (optional) LLM polish → human-readable answer

Usage::

    from qtrust_ai.copilot.explainer import SecurityCopilot

    copilot = SecurityCopilot(seed=42)
    copilot.attach_graph(dependency_graph)
    answer = copilot.answer("Why is our payment API critical?")

All evidence is deterministic and CPU-friendly; every downstream model is
optional (guarded), so the copilot degrades gracefully without torch/sklearn.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .evidence import EvidenceExtractor, AssetEvidence, OrgEvidence
except ImportError:  # pragma: no cover
    EvidenceExtractor = None  # type: ignore
    AssetEvidence = None  # type: ignore
    OrgEvidence = None  # type: ignore

try:
    from .llm import LLMProvider, DeterministicProvider, OpenAICompatibleProvider, build_llm_provider
except ImportError:  # pragma: no cover
    LLMProvider = None  # type: ignore
    DeterministicProvider = None  # type: ignore
    OpenAICompatibleProvider = None  # type: ignore
    build_llm_provider = None  # type: ignore

try:
    from .explainer import SecurityCopilot, CopilotAnswer, CopilotConfig, detect_intent
except ImportError:  # pragma: no cover
    SecurityCopilot = None  # type: ignore
    CopilotAnswer = None  # type: ignore
    CopilotConfig = None  # type: ignore
    detect_intent = None  # type: ignore

__all__ = [
    "EvidenceExtractor",
    "AssetEvidence",
    "OrgEvidence",
    "LLMProvider",
    "DeterministicProvider",
    "OpenAICompatibleProvider",
    "build_llm_provider",
    "SecurityCopilot",
    "CopilotAnswer",
    "CopilotConfig",
    "detect_intent",
]

__version__: str = "5.0.0-copilot"
COPILOT_MODULES: List[str] = [
    "qtrust_ai.copilot.evidence",
    "qtrust_ai.copilot.llm",
    "qtrust_ai.copilot.explainer",
]

# The 7 questions the copilot answers (spec §26)
QUESTIONS: List[str] = [
    "WHAT do I have?",
    "WHAT is dangerous?",
    "WHY is it dangerous?",
    "WHAT should replace it?",
    "HOW to migrate without breaking prod?",
    "WHAT will happen if I migrate it?",
    "DID the migration actually improve security?",
]


def get_copilot_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.copilot",
        "version": __version__,
        "phase": "5 Interface",
        "modules": COPILOT_MODULES,
        "questions": QUESTIONS,
        "architecture_doc": "qtrust_ai/README.md",
        "llm_policy": "LLM explains, never decides — deterministic evidence first",
        "has_explainer": SecurityCopilot is not None,
        "has_extractor": EvidenceExtractor is not None,
        "has_llm_hook": build_llm_provider is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.copilot package demo ===")
    print(json.dumps(get_copilot_info(), indent=2))
    if SecurityCopilot is not None and EvidenceExtractor is not None:
        from qtrust_ai.graph.dependency_graph import DependencyGraph

        g = DependencyGraph()
        g.build_from_findings(
            [
                {"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical"},
                {"algorithm": "ECDSA-P256", "file": "services/auth/tls.go", "criticality": "high"},
            ],
            app_name="payment-api", app_criticality="critical",
        )
        copilot = SecurityCopilot(seed=42)  # type: ignore
        copilot.attach_graph(g)
        ans = copilot.answer("Why is our payment API critical?")  # type: ignore
        print(f"\nQ: Why is our payment API critical?  [intent={ans.intent}]")
        print(f"A:\n{ans.answer}")
        print(f"\nsources={ans.sources} llm_polished={ans.llm_polished}")
    else:
        print("copilot not importable (missing dependencies)")
