"""
Q-Trust ML Factory — world's best labeled dataset for cryptographic migration decisions.

Architecture (see user strategy §1):

                         Q-TRUST ML
                             │
        ┌────────────────────┼─────────────────────┐
        │                    │                     │
        ▼                    ▼                     ▼
   DISCOVERY ML          RISK ML              GRAPH ML
        │                    │                     │
        └─ crypto detection  ├─ exposure          ├─ blast radius
                             ├─ HNDL              ├─ dependency
                             ├─ business impact   └─ prioritization
                             └─ migration risk

                 ┌─────────────────────────┐
                 │ MIGRATION INTELLIGENCE   │
                 │ cost / failure / interop │
                 └────────────┬────────────┘
                              ▼
                       PLANNING ENGINE
                        CP-SAT + RL → DIGITAL TWIN

Anti-circular: labels NEVER come from heuristic being evaluated.
Expert pairwise preferences, CodeQL/Semgrep/AST + human gold, git-history mining,
and temporal splits ensure honest benchmarks (see docs/STRATEGIC_ANALYSIS.md).
"""

__version__ = "3.0.0-factory"
__all__ = ["__version__"]
