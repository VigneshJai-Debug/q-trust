from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


@dataclass
class BenchmarkReport:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    per_fixture: list[dict[str, Any]]

    def passed(self, recall_min: float, precision_min: float) -> bool:
        return self.recall >= recall_min and self.precision >= precision_min


def _family(algorithm: str) -> str:
    algo = algorithm.upper().replace("_", "-")
    ordered_prefixes = (
        "SHA3",
        "SHA-1",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHAKE",
        "RSA",
        "ECDSA",
        "ECDH",
        "ED25519",
        "ED448",
        "X25519",
        "X448",
        "MD5",
        "AES",
        "DES",
        "DSA",
        "DH",
        "HMAC",
        "CHACHA20",
    )
    for prefix in ordered_prefixes:
        if algo == prefix or algo.startswith(prefix + "-"):
            aliases = {"EC": "ECDSA"}
            return aliases.get(prefix, prefix)
    return algo


NOISE_FAMILIES: set[str] = set()
_SPEC = json.loads((CORPUS_DIR / "ground_truth.json").read_text())
NOISE_FAMILIES.update(_SPEC.get("matching_rules", {}).get("ignored_families", []))


def _load_expected() -> dict[str, list[str]]:
    spec = json.loads((CORPUS_DIR / "ground_truth.json").read_text())
    out: dict[str, list[str]] = {}
    for fixture in spec["fixtures"]:
        labels = []
        for item in fixture["expected"]:
            label = _family(item["algorithm"])
            if label not in labels:
                labels.append(label)
        out[fixture["file"]] = labels
    return out


def run_benchmark() -> BenchmarkReport:
    from qtrust_inspector.ast_scanner import (
        DETECTOR_CAPABILITIES,
        scan_source_directory_ast,
    )
    from qtrust_inspector.source_scanner import scan_source_directory

    ast_findings = scan_source_directory_ast(str(CORPUS_DIR), use_tree_sitter=True)
    regex_findings = scan_source_directory(str(CORPUS_DIR))

    expected = _load_expected()
    detected_by_file: dict[str, set[str]] = {name: set() for name in expected}
    all_files = set(expected.keys())

    tp = fp = fn = 0
    per_fixture: list[dict[str, Any]] = []

    for finding in (*ast_findings, *regex_findings):
        host = getattr(finding, "host", "") or ""
        name = Path(host).name
        if name not in all_files:
            continue
        algorithm = getattr(finding, "algorithm", None) or ""
        family = _family(algorithm)
        if family in NOISE_FAMILIES:
            continue
        detected_by_file.setdefault(name, set())
        detected_by_file[name].add(family)

    for fname, wanted_list in expected.items():
        wanted = set(wanted_list)
        got = detected_by_file.get(fname, set())
        matched = wanted & got
        missed = sorted(wanted - got)
        unexpected = [g for g in sorted(got) if g not in wanted]
        tp += len(matched)
        fn += len(missed)
        fp += len(unexpected)
        per_fixture.append(
            {
                "fixture": fname,
                "expected": wanted,
                "detected": sorted(got),
                "matched": sorted(matched),
                "missed": missed,
                "unexpected": unexpected,
                "detector_capabilities": DETECTOR_CAPABILITIES,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return BenchmarkReport(tp, fp, fn, precision, recall, f1, per_fixture)


if __name__ == "__main__":
    import sys

    report = run_benchmark()
    thresholds = json.loads((CORPUS_DIR / "ground_truth.json").read_text())["thresholds"]
    print(f"TP={report.true_positives} FP={report.false_positives} FN={report.false_negatives}")
    print(f"precision={report.precision:.3f} recall={report.recall:.3f} f1={report.f1:.3f}")
    for row in report.per_fixture:
        status = "OK" if not row["missed"] and not row["unexpected"] else "GAP"
        print(f"  [{status}] {row['fixture']}: missed={row['missed']} unexpected={row['unexpected']}")
    ok = report.passed(thresholds["recall_min"], thresholds["precision_min"])
    sys.exit(0 if ok else 1)
