"""Benchmark-corpus gate: precision/recall must meet ground_truth thresholds."""
from __future__ import annotations

import json


from benchmarks.score import CORPUS_DIR, run_benchmark

_SPEC = json.loads((CORPUS_DIR / "ground_truth.json").read_text())
_THRESHOLDS = _SPEC["thresholds"]


def test_corpus_files_exist():
    for fixture in _SPEC["fixtures"]:
        assert (CORPUS_DIR / fixture["file"]).exists(), f"missing corpus file {fixture['file']}"


def test_clean_fixture_has_no_expected_findings():
    clean = [f for f in _SPEC["fixtures"] if "clean" in f["file"]]
    assert clean and all(f["expected"] == [] for f in clean)


def test_benchmark_meets_recall_threshold():
    report = run_benchmark()
    assert report.recall >= _THRESHOLDS["recall_min"], (
        f"recall {report.recall:.3f} < {_THRESHOLDS['recall_min']}; "
        f"missed: {[(r['fixture'], r['missed']) for r in report.per_fixture if r['missed']]}"
    )


def test_benchmark_meets_precision_threshold():
    report = run_benchmark()
    assert report.precision >= _THRESHOLDS["precision_min"], (
        f"precision {report.precision:.3f} < {_THRESHOLDS['precision_min']}; "
        f"unexpected: {[(r['fixture'], r['unexpected']) for r in report.per_fixture if r['unexpected']]}"
    )


def test_report_is_deterministic():
    a, b = run_benchmark(), run_benchmark()
    assert (a.true_positives, a.false_positives, a.false_negatives) == (
        b.true_positives,
        b.false_positives,
        b.false_negatives,
    )
