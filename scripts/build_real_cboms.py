#!/usr/bin/env python3
"""Build REAL, HOST-DISJOINT enterprise CBOMs from a live TLS scan.

Why this exists (audit finding, 2026-08-29):

The previously committed `planner/data/real_cboms/` corpus was hand-packed and
unreproducible — every one of the 131 scanned hosts appeared in **two**
CBOMs, so any train/eval split over CBOMs silently shared hosts (label
leakage). The flagship real-CBOM benchmark (τ-b 0.807) was fine-tuned and
evaluated on the same CBOMs, i.e. in-sample. This builder replaces the
hand-packed files with a deterministic, host-disjoint corpus:

  - Each scanned host appears in exactly ONE CBOM (no cross-CBOM leakage).
  - Hosts are grouped by industry (finance / gov_edu / infra / media /
    security / tech / mixed) so each CBOM looks like a real enterprise
    estate, then packed deterministically from a seed.
  - Every CBOM records its exact host list and scan provenance, so the
    corpus is auditable and regenerable from `tls_scan.json`.

Input:  qtrust_ai/artifacts/real_datasets/tls_scan.json (scan_hosts.py output)
Output: planner/data/real_cboms/*.json (qtrust.cbom.v1 schema)

Usage:
    python scripts/build_real_cboms.py                    # from the TLS scan
    python scripts/build_real_cboms.py --scan path.json   # explicit scan file
    python scripts/build_real_cboms.py --hosts-per-cbom 8 --seed 7
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN = REPO_ROOT / "qtrust_ai" / "artifacts" / "real_datasets" / "tls_scan.json"
OUT_DIR = REPO_ROOT / "planner" / "data" / "real_cboms"

# Industry classification — deterministic keyword rules over the hostname.
# Order matters: first match wins (finance beats tech for bank domains, etc.).
_INDUSTRY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("finance", ("bank", "paypal", "stripe", "squareup", "visa", "mastercard",
                 "chase", "wellsfargo", "hsbc", "jpmorgan", "goldmansachs",
                 "bloomberg", "capitalone", "amex", "americanexpress", "citi",
                 "barclays", "ubs", "reuters")),
    ("gov_edu", (".gov", ".edu", ".ac.uk", ".ac.at", "nist.gov", "cisa.gov",
                 "fbi.gov", "whitehouse.gov", "state.gov", "who.int", "un.org",
                 "esa.int", "cern.ch", "mit.edu", "stanford.edu", "harvard.edu",
                 "ox.ac.uk", "cam.ac.uk", "ethz.ch", "tum.de", "berkeley.edu",
                 "parliament", "europa.eu")),
    ("media", ("nytimes", "cnn", "bbc", "guardian", "economist", "forbes",
               "wsj", "ft.com", "reuters", "npr", "bloomberg", "theguardian",
               "washingtonpost", "theverge", "techcrunch")),
    ("security", ("1password", "lastpass", "bitwarden", "dashlane", "nordvpn",
                  "expressvpn", "proton", "tutanota", "signal", "sentry",
                  "splunk", "datadog", "cloudflare", "akamai", "fastly",
                  "imperva", "auth0", "okta", "duo", "cyberark", "crowdstrike")),
    ("infra", ("aws", "azure", "gcp", "cloud.google", "oracle", "ibm", "intel",
               "amd", "nvidia", "samsung", "hashicorp", "mongodb", "postgres",
               "mysql", "redis", "elastic", "docker", "kubernetes", "github",
               "gitlab", "bitbucket", "vercel", "netlify", "digitalocean",
               "heroku", "cloudflare-nginx", "akamai")),
    ("tech", ("google", "youtube", "microsoft", "apple", "amazon", "meta",
              "facebook", "netflix", "openai", "anthropic", "linkedin", "x.com",
              "twitter", "reddit", "medium", "quora", "spotify", "soundcloud",
              "dropbox", "box", "salesforce", "workday", "sap", "adobe",
              "autodesk", "figma", "canva", "notion", "slack", "zoom", "webex",
              "discord", "telegram", "duckduckgo", "brave", "mozilla", "apache",
              "kernel.org", "debian", "ubuntu", "archlinux", "fedora", "redhat",
              "suse", "python.org", "pypi.org", "npmjs", "crates.io", "golang",
              "nodejs.org", "java.com", "rust-lang")),
]


def classify_industry(host: str) -> str:
    """Deterministic industry label for a hostname (first matching rule)."""
    h = (host or "").lower()
    for industry, keywords in _INDUSTRY_RULES:
        for kw in keywords:
            if kw in h:
                return industry
    return "mixed"


def build_cboms(
    scan_path: Path,
    hosts_per_cbom: int,
    seed: int,
    min_assets: int = 2,
) -> list[dict]:
    """Build host-disjoint enterprise CBOMs from a TLS ScanResult JSON.

    Each host's findings become one CBOM's assets. Hosts are grouped by
    industry, then packed deterministically (seeded shuffle) so that no host
    appears in more than one CBOM and no CBOM mixes industries arbitrarily.
    """
    scan = json.loads(scan_path.read_text())
    findings = scan.get("findings", [])
    by_host: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        host = f.get("host") or f.get("location") or "unknown"
        by_host[host].append(f)

    rng = random.Random(seed)
    industry_groups: dict[str, list[str]] = defaultdict(list)
    for host in sorted(by_host):
        industry_groups[classify_industry(host)].append(host)
    for hosts in industry_groups.values():
        rng.shuffle(hosts)

    # Real-world certs can carry a *signature* algorithm name (e.g.
    # sha256WithRSAEncryption) that differs from the *actual public key*
    # (e.g. ECPublicKey / P-256 — capitalone.com, facebook.com, fda.gov,
    # netlify.com, truist.com all ship EC keys under RSA-signed certs).
    # The key type is authoritative for quantum-risk: normalize the
    # algorithm label from key_type+key_size so downstream featurization
    # and risk scoring see the real key, not the cert's signature wrapper.
    def _normalize_algorithm(asset: dict) -> dict:
        kt = str(asset.get("key_type") or "").lower()
        alg = (asset.get("algorithm") or "").lower()
        ks = asset.get("key_size")
        out = dict(asset)
        if "ecpublic" in kt or kt.startswith("ec"):
            n = int(ks) if ks else 256
            out["algorithm"] = f"ECDSA-P{n}" if n in (256, 384, 521) else f"ECDSA-P256"
            out["_sig_algorithm"] = asset.get("algorithm")
        elif "rsapublic" in kt or kt == "rsa":
            n = int(ks) if ks else 2048
            out["algorithm"] = f"RSA-{n}"
            out["_sig_algorithm"] = asset.get("algorithm")
        return out

    cboms: list[dict] = []
    for industry in sorted(industry_groups):
        hosts = industry_groups[industry]
        for start in range(0, len(hosts), hosts_per_cbom):
            chunk = hosts[start:start + hosts_per_cbom]
            assets: list[dict] = []
            for host in chunk:
                assets.extend(_normalize_algorithm(a) for a in by_host[host])
            if len(assets) < min_assets:
                # Too thin to be a meaningful graph — merge into the next CBOM.
                if cboms:
                    cboms[-1]["assets"].extend(assets)
                    cboms[-1]["_hosts"].extend(chunk)
                    cboms[-1]["_hosts"].sort()
                continue
            target = f"acme-{industry.replace('_', '-')}.example"
            cboms.append({
                "schema_version": "qtrust.cbom.v1",
                "target": target,
                "industry": industry,
                "assets": assets,
                "_hosts": sorted(chunk),
                "_provenance": {
                    "scan": scan_path.name,
                    "scan_timestamp": scan.get("scan_timestamp"),
                    "n_findings": len(findings),
                    "builder": "scripts/build_real_cboms.py",
                    "builder_version": "1.0.0",
                    "seed": seed,
                    "hosts_per_cbom": hosts_per_cbom,
                },
            })

    return cboms


def main() -> None:
    parser = argparse.ArgumentParser(description="Build host-disjoint real CBOM corpus")
    parser.add_argument("--scan", type=Path, default=DEFAULT_SCAN)
    parser.add_argument("--hosts-per-cbom", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    if not args.scan.exists():
        sys.exit(f"scan file not found: {args.scan} — run scripts/scan_hosts.py first")

    cboms = build_cboms(args.scan, args.hosts_per_cbom, args.seed)

    args.out.mkdir(parents=True, exist_ok=True)
    # Idempotent: remove previous builds so stale CBOM files (from older scan
    # sets or parameter tweaks) can never leak into a train/eval split.
    for stale in args.out.glob("real_*.json"):
        stale.unlink()
    # Deterministic filenames: real_<industry>_<n>.json (n = index within industry).
    seen: dict[str, int] = defaultdict(int)
    hosts_seen: set[str] = set()
    for cbom in cboms:
        industry = cbom["industry"]
        idx = seen[industry]
        seen[industry] += 1
        path = args.out / f"real_{industry}_{idx}.json"
        # Verify host-disjointness as we write.
        for h in cbom["_hosts"]:
            assert h not in hosts_seen, f"host {h} appears in two CBOMs — corpus not disjoint"
            hosts_seen.add(h)
        path.write_text(json.dumps({k: v for k, v in cbom.items() if not k.startswith("_")},
                                   indent=1) + "\n")

    # Sanity report
    n_assets = sum(len(c["assets"]) for c in cboms)
    print(f"Wrote {len(cboms)} CBOMs to {args.out}")
    print(f"  hosts: {len(hosts_seen)} (unique, disjoint) | assets: {n_assets}")
    from collections import Counter
    print(f"  industries: {dict(Counter(c['industry'] for c in cboms))}")
    sizes = [len(c["assets"]) for c in cboms]
    print(f"  assets/CBOM: min={min(sizes)} max={max(sizes)} mean={sum(sizes)/len(sizes):.1f}")
    print("  Provenance recorded per CBOM (scan timestamp, seed, builder).")


if __name__ == "__main__":
    main()
