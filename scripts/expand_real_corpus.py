#!/usr/bin/env python3
"""Expand the real code corpus with real blockchain/smart-contract code.

Adds real-world Solidity + JS/TS/Python code from the shipped
``Q-Trust_Dataset_Collection`` (SolidiFI benchmark contracts, SmartBugs-curated
vulnerable contracts, EIP asset contracts, W3C WebAuthn test vectors) to the
existing real code corpus. Every file is labeled by the trusted deterministic
scanner (``CryptoCodeDetector.scan_file``), so the labels are produced by the
same deterministic layer the rest of the corpus uses.

Invariants preserved:
  * source-disjoint splits — each added file carries a ``source`` equal to its
    collection root, so repo-disjoint train/eval splits never share a repo.
  * no duplicate content — files are deduped by SHA-256 of normalized text.
  * the corpus schema is unchanged (code / language / label / is_crypto /
    source / path), so downstream training scripts need no changes.

Usage:
    python scripts/expand_real_corpus.py                     # default paths
    python scripts/expand_real_corpus.py --in corpus.json --out corpus.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "inspector"))

DEFAULT_COLLECTION = REPO_ROOT / "Q-Trust_Dataset_Collection"
DEFAULT_CORPUS = REPO_ROOT / "qtrust_ai" / "artifacts" / "real_datasets" / "code_corpus.json"

# (collection subdir, source label) — order matters, first match wins.
SOURCES: list[tuple[str, str]] = [
    ("SolidiFI-benchmark-master", "solidifi-benchmark"),
    ("smartbugs-curated-main", "smartbugs-curated"),
    ("EIPs-master", "eips-assets"),
    ("webauthn-main", "w3c-webauthn"),
]

_SUPPORTED_EXT = {".sol": "solidity", ".js": "javascript", ".ts": "typescript",
                  ".py": "python", ".rs": "rust", ".go": "go", ".c": "c",
                  ".h": "c", ".cpp": "cpp", ".java": "java", ".cs": "csharp",
                  ".php": "php", ".swift": "swift", ".sh": "shell", ".kt": "kotlin"}


def _norm(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.splitlines()).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection", type=Path, default=DEFAULT_COLLECTION)
    parser.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--max-per-source", type=int, default=1500)
    args = parser.parse_args()

    from qtrust_ai.discovery.code_detector import CryptoCodeDetector  # noqa: PLC0415

    det = CryptoCodeDetector(seed=42)  # deterministic scanner layer

    corpus = json.loads(args.in_path.read_text())
    existing = corpus.get("corpus", [])
    seen = set()
    for rec in existing:
        seen.add(hashlib.sha256(_norm(rec.get("code", "")).encode()).hexdigest())

    added: list[dict] = []
    per_source: dict[str, list[str]] = {}
    for subdir, label in SOURCES:
        root = args.collection / subdir
        if not root.is_dir():
            print(f"  ! missing {subdir} — skipping")
            continue
        count = 0
        for p in sorted(root.rglob("*")):
            if count >= args.max_per_source:
                break
            if not p.is_file() or p.suffix.lower() not in _SUPPORTED_EXT:
                continue
            rel = p.relative_to(root).as_posix().lower()
            if any(part in rel for part in ("/test", "/tests", "/node_modules",
                                            "/build", "/.git", "/docs", "/examples")):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(text) < 80 or len(text) > 200_000:
                continue
            digest = hashlib.sha256(_norm(text).encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            try:
                findings = det.scan_file(p)
            except Exception:
                findings = det._static_layer(text, _SUPPORTED_EXT[p.suffix.lower()])  # type: ignore[attr-defined]  # noqa: SLF001
            is_crypto = bool(findings)
            lbl = findings[0].algorithm if is_crypto else "NONE"
            added.append({
                "code": text,
                "language": _SUPPORTED_EXT[p.suffix.lower()],
                "label": lbl,
                "is_crypto": is_crypto,
                "source": label,
                "path": p.name,
            })
            per_source.setdefault(label, []).append(lbl)
            count += 1
        crypto_n = sum(1 for lbl2 in per_source.get(label, []) if lbl2 != "NONE")
        print(f"  {subdir}: +{count} files (crypto={crypto_n})")

    if not added:
        print("No new files — corpus already contains everything.")
        return

    # Extend stats counters.
    stats = corpus.setdefault("stats", {})
    crypto_counter = dict(stats.get("crypto", {}))
    non_crypto_counter = dict(stats.get("non_crypto", {}))
    for rec in added:
        bucket = crypto_counter if rec["is_crypto"] else non_crypto_counter
        bucket[rec["language"]] = bucket.get(rec["language"], 0) + 1
    stats["crypto"], stats["non_crypto"] = crypto_counter, non_crypto_counter

    corpus["corpus"] = existing + added
    out = args.out or args.in_path
    out.write_text(json.dumps(corpus, indent=2))
    n_crypto = sum(1 for r in corpus["corpus"] if r["is_crypto"])
    print(f"\nCorpus now {len(corpus['corpus'])} files ({n_crypto} crypto) -> {out}")
    print("  added:", {k: len(v) for k, v in per_source.items()})


if __name__ == "__main__":
    main()
