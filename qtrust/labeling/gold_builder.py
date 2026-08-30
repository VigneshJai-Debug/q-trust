"""
Gold Crypto Dataset — §5.

Each candidate annotated with 7 dimensions:
algorithm, primitive, role, location, reachability, data sensitivity, business criticality.
This becomes the proprietary QTrust-RiskBench.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional


@dataclass
class GoldSample:
    repo: str
    commit: str
    file: str
    language: str
    code_span: str
    algorithm: str
    operation: str  # signature | encryption | kem | hashing | mac
    key_size: Optional[int]
    crypto_role: str  # authentication | confidentiality | integrity | key_establishment
    library: str
    runtime_reachable: bool
    quantum_vulnerable: bool
    confidence: float
    location: str  # code | config | cert | network | hardware
    data_sensitivity: str  # public | internal | confidential | regulated
    data_lifetime: str  # days | months | years
    business_criticality: int  # 1-5


def validate_gold(sample: GoldSample) -> List[str]:
    errors: List[str] = []
    if sample.business_criticality not in range(1, 6):
        errors.append("business_criticality must be 1-5")
    if sample.operation not in ("signature", "encryption", "kem", "hashing", "mac", "key_establishment"):
        errors.append(f"invalid operation {sample.operation}")
    return errors


def write_gold_dataset(samples: List[GoldSample], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(s) for s in samples]
    out_path.write_text(json.dumps(payload, indent=2))
    # Write manifest for lineage (§49)
    manifest = {
        "n": len(samples),
        "created_at": datetime.now().isoformat(),
        "languages": sorted({s.language for s in samples}),
        "algorithms": sorted({s.algorithm for s in samples}),
    }
    (out_path.parent / "manifest.json").write_text(json.dumps(manifest, indent=2))


def load_gold(path: Path) -> List[GoldSample]:
    data = json.loads(path.read_text())
    return [GoldSample(**d) for d in data]
