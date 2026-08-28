"""Q-Trust AI Intelligence Layer — beating competitors not with a GNN but with a migration system.

Architecture from user spec §25 (final AI architecture):

                     Q-TRUST AI
                         │
          ┌──────────────┴──────────────┐
          │                             │
    DISCOVERY AI                  INTELLIGENCE AI
          │                             │
   Crypto Detector                Risk Model
   Code Model                     HNDL Model
   Binary Model                   Vendor Model
   Protocol Model                 Supply Chain Model
          │                             │
          └──────────────┬──────────────┘
                         │
                   CRYPTO GRAPH
                         │
                         ▼
                 Temporal GNN
                         │
              ┌──────────┴──────────┐
              │                     │
        Risk Prediction       Blast Radius
              │                     │
              └──────────┬──────────┘
                         │
                         ▼
               MIGRATION ENGINE
                         │
             ┌───────────┴───────────┐
             │                       │
      PQC Recommender          Cost Predictor
             │                       │
             └───────────┬───────────┘
                         │
                         ▼
                Constrained Optimizer
                         │
                         ▼
                  RL Planner
                         │
                         ▼
                Migration Roadmap
                         │
                         ▼
                  DIGITAL TWIN
                         │
                         ▼
                 SAFE SIMULATION
                         │
                         ▼
                    EXECUTION
                         │
                         ▼
                CONTINUOUS MONITOR
                         │
                         ▼
                  REGRESSION AI

Answers 7 questions (§26):
1. WHAT do I have? 2. WHAT is dangerous? 3. WHY? 4. WHAT should replace it?
5. HOW to migrate without breaking prod? 6. WHAT will happen? 7. DID it improve?

See qtrust_ai/README.md for 32-point transformation plan.
"""
__version__ = "1.0.0-intelligence-layer"
__all__ = []
