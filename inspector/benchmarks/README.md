# Q-Trust Scanner Benchmark Corpus

Labeled ground-truth fixtures with precision/recall gating in CI — the only
published evaluation harness in the PQC-scanning space as of August 2026.

## Layout

- `corpus/` — fixture files + `ground_truth.json` (expected algorithm labels
  per fixture, matching rules, thresholds)
- `score.py` — runs the scanner stack over the corpus, computes
  TP/FP/FN/precision/recall/F1, exits non-zero below threshold
- `tests/test_benchmark.py` — pytest gate enforcing thresholds

## Methodology

1. Fixtures are small, deterministic source files. `*_vulnerable.*` files
   contain known cryptographic APIs; `*_clean.py` files contain
   lookalike-but-safe constructs (`RSA_MAX_KEY_SIZE_RECOMMENDED`, string
   literals mentioning sha256, variable names containing algorithm words)
   that must produce **zero** findings.
2. Expected labels are algorithm families (`RSA`, `MD5`, `SHA-1`, ...),
   not line numbers — detectors may locate them anywhere in the file.
3. Import/library-level informational labels (`HAZMAT`, `NODE-CRYPTO`, ...)
   are excluded from algorithm-precision scoring via
   `matching_rules.ignored_families` — transparently declared in data,
   not hidden in scorer code.
4. Thresholds start at recall ≥ 0.90, precision ≥ 0.80 and ratchet upward
   as the corpus grows.

## Growing the corpus

Add a fixture + its expected labels to `ground_truth.json`. Any regression
in detection shows up as a CI failure naming the missed family. Target:
50+ labeled fixtures across all supported languages before v2.
