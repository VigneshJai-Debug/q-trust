"""
qtrust_ai.benchmark — Q-Trust PQC-Migration Benchmark package (Phase 5).

Per ``qtrust_ai/README.md`` §28-29 (Benchmark + Adversarial):

* :mod:`qtrust_ai.benchmark.dataset` — ``QTrustBenchmark``: generates
  organizations × applications × crypto usages × dependency edges with the
  full §28 attribute set (asset, algorithm, protocol, purpose, dependency
  graph, criticality, data sensitivity/lifetime, vendor, hardware, PQC
  compatibility, migration cost/result, failure mode). Org-level splits
  (train/val/test/enterprise-holdout/adversarial-holdout) with **no leakage**:
  the same organization never appears in train and test.
* :mod:`qtrust_ai.benchmark.adversarial` — ``AdversarialCaseGenerator``:
  the 11 §29 hard cases (obfuscated crypto, renamed functions, custom
  wrappers, dead code, generated code, mixed algorithms, false positives,
  hidden dependencies, unknown vendors, incomplete inventories, conflicting
  evidence) so evaluation can answer "can Q-Trust still discover crypto when
  the obvious patterns disappear?".

Target scale (config): 10k orgs × 100k apps × 1M usages × 10M edges — default
is CPU-friendly (small) for tests and demos.

Usage::

    from qtrust_ai.benchmark.dataset import QTrustBenchmark, BenchmarkConfig

    bench = QTrustBenchmark(BenchmarkConfig(n_orgs=200, seed=42))
    bench.generate()
    splits = bench.splits()          # train / val / test / holdouts
    records = bench.to_records()     # one row per §28 sample
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .dataset import (
        QTrustBenchmark,
        BenchmarkConfig,
        BenchmarkOrg,
        BenchmarkApp,
        BenchmarkUsage,
    )
except ImportError:  # pragma: no cover
    QTrustBenchmark = None  # type: ignore
    BenchmarkConfig = None  # type: ignore
    BenchmarkOrg = None  # type: ignore
    BenchmarkApp = None  # type: ignore
    BenchmarkUsage = None  # type: ignore

try:
    from .adversarial import AdversarialCaseGenerator, AdversarialCase, ADVERSARIAL_TYPES
except ImportError:  # pragma: no cover
    AdversarialCaseGenerator = None  # type: ignore
    AdversarialCase = None  # type: ignore
    ADVERSARIAL_TYPES = []  # type: ignore

__all__ = [
    "QTrustBenchmark",
    "BenchmarkConfig",
    "BenchmarkOrg",
    "BenchmarkApp",
    "BenchmarkUsage",
    "AdversarialCaseGenerator",
    "AdversarialCase",
    "ADVERSARIAL_TYPES",
]

__version__: str = "5.0.0-benchmark"
BENCHMARK_MODULES: List[str] = [
    "qtrust_ai.benchmark.dataset",
    "qtrust_ai.benchmark.adversarial",
]

# §28 sample fields (each usage record must carry all of these)
SAMPLE_FIELDS: List[str] = [
    "asset", "algorithm", "protocol", "purpose", "business_criticality",
    "data_sensitivity", "data_lifetime_years", "vendor", "hardware",
    "pqc_compatible", "migration_cost_hours", "migration_result", "failure_mode",
]

SPLIT_NAMES: List[str] = ["train", "val", "test", "enterprise_holdout", "adversarial_holdout"]


def get_benchmark_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.benchmark",
        "version": __version__,
        "phase": "5 Interface",
        "modules": BENCHMARK_MODULES,
        "target_scale": "10k orgs × 100k apps × 1M usages × 10M edges",
        "split_discipline": "org-level splits — same org never in train+test",
        "sample_fields": SAMPLE_FIELDS,
        "adversarial_categories": ADVERSARIAL_TYPES,
        "architecture_doc": "qtrust_ai/README.md",
        "has_dataset": QTrustBenchmark is not None,
        "has_adversarial": AdversarialCaseGenerator is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.benchmark package demo ===")
    print(json.dumps(get_benchmark_info(), indent=2))
    if QTrustBenchmark is not None and BenchmarkConfig is not None:
        bench = QTrustBenchmark(BenchmarkConfig(n_orgs=30, seed=42))  # type: ignore
        bench.generate()
        sp = bench.splits()  # type: ignore
        print(f"\norgs={len(bench.orgs)} usages={bench.usage_count()} edges={bench.edge_count()}")
        print(f"split records: { {k: len(v['records']) for k, v in sp.items()} }")
        leak = sum(len(set(sp[a]['org_ids']) & set(sp[b]['org_ids'])) for i, a in enumerate(SPLIT_NAMES) for b in SPLIT_NAMES[i + 1:])  # type: ignore
        print(f"cross-split org leakage: {leak}")
        if AdversarialCaseGenerator is not None:
            gen = AdversarialCaseGenerator(seed=42)  # type: ignore
            cases = gen.generate(n=22)  # type: ignore
            print(f"adversarial cases: {len(cases)} across {len({c.adversarial_type for c in cases})} categories")
        assert leak == 0
        print("\n✓ benchmark package demo passed (no leakage)")
    else:
        print("benchmark not importable (missing dependencies)")
