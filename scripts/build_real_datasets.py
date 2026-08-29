"""Build REAL datasets for the qtrust_ai intelligence layer from public sources.

Data sources (all public; cached under ``qtrust_ai/artifacts/real_datasets/``):

1. **Real code corpus** (discovery) — open-source repos with real crypto usage
   (pyca/cryptography, cloudflare/circl [PQC], rustls, libsodium, SJCL, plus
   the vendored OpenZeppelin contracts in this repo) and repos with no crypto
   (pallets/click, pallets/jinja, serde-rs/serde, golang/example). Each source
   file is labeled by the project's *trusted deterministic scanner*
   (``CryptoCodeDetector.scan_file`` — static rules + AST, the deterministic
   layer of the architecture). The ML code model then learns distributional
   patterns from REAL code with those labels, which is the §20 pipeline
   ("deterministic scanners + ML code model").

2. **Real TLS inventory** (risk / anomaly / regression) — live scan of a
   curated list of real public hosts (port 443) with ``scripts/scan_hosts.py``
   → real certificate algorithms / key sizes (RSA-2048, ECDSA-P256, ...).
   Converts to per-host CBOMs → anomaly snapshots, regression pairs, and
   risk-labeled samples (labels from the deterministic quantum-exposure
   reference scoring).

3. **Real vendor data** (supply-chain / readiness) — NVD CVE API (v2.0) for
   crypto libraries (openssl, mbedtls, wolfssl, libsodium, bouncy-castle,
   python-cryptography, boringssl). Vendor readiness labels combine real CVE
   counts with the deterministic PQC-support knowledge base.

Models whose labels are inherently proprietary (migration cost, failure,
interoperability, RL trajectories, temporal risk) have NO public dataset —
``train_qtrust_all.py --real`` keeps those on synthetic data and says so.

Usage:
    python scripts/build_real_datasets.py --parts code,tls,nvd [--hosts 80]
    python scripts/build_real_datasets.py --parts code          # repos only
    python scripts/build_real_datasets.py --parts tls           # scan only
    python scripts/build_real_datasets.py --parts nvd           # NVD only
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import time
import subprocess
import sys
import tarfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = REPO_ROOT / "qtrust_ai" / "artifacts" / "real_datasets"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "inspector"))

CACHE = ARTIFACTS / "cache"
ARTIFACTS.mkdir(parents=True, exist_ok=True)
CACHE.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Real code corpus
# ---------------------------------------------------------------------------

# (owner/repo, tag or "HEAD") — real crypto usage across many languages
CRYPTO_REPOS: List[Dict[str, str]] = [
    {"repo": "pyca/cryptography", "ref": "HEAD"},
    {"repo": "cloudflare/circl", "ref": "HEAD"},          # Go PQC (ML-KEM, X25519)
    {"repo": "rustls/rustls", "ref": "HEAD"},
    {"repo": "jedisct1/libsodium", "ref": "HEAD"},
    {"repo": "bitwiseshiftleft/sjcl", "ref": "HEAD"},     # JS crypto
    {"repo": "bcgit/bc-java", "ref": "HEAD"},             # Java crypto
    {"repo": "bcgit/bc-csharp", "ref": "HEAD"},            # C# crypto
    {"repo": "krzyzanowskim/CryptoSwift", "ref": "HEAD"},  # Swift crypto
    {"repo": "phpseclib/phpseclib", "ref": "HEAD"},        # PHP crypto
    {"repo": "open-quantum-safe/liboqs", "ref": "HEAD"},   # C PQC implementations
    # --- production-grade crypto libraries (real-world TLS/SSH/PKI) --------
    {"repo": "openssl/openssl", "ref": "HEAD"},             # C — de-facto TLS standard
    {"repo": "google/boringssl", "ref": "HEAD"},           # C — Chrome's TLS stack
    {"repo": "aws/aws-lc", "ref": "HEAD"},                 # C — AWS libcrypto
    {"repo": "mbedtls/mbedtls", "ref": "HEAD"},            # C — embedded TLS
    {"repo": "wolfSSL/wolfssl", "ref": "HEAD"},            # C — embedded TLS/DTLS
    {"repo": "gpg/libgcrypt", "ref": "HEAD"},              # C — GnuPG crypto engine
    {"repo": "randombit/botan", "ref": "HEAD"},            # C++ — crypto toolkit
    {"repo": "PyCryptoDome/pycryptodome", "ref": "HEAD"},  # Python crypto
    {"repo": "paramiko/paramiko", "ref": "HEAD"},           # Python SSH
    {"repo": "nodejs/node", "ref": "HEAD"},                # Node.js (crypto/tls core)
    {"repo": "golang/go", "ref": "HEAD"},                   # Go stdlib (crypto/x509, tls)
]
NON_CRYPTO_REPOS: List[Dict[str, str]] = [
    {"repo": "pallets/click", "ref": "HEAD"},             # Python CLI — no crypto
    {"repo": "pallets/jinja", "ref": "HEAD"},             # templating — no crypto
    {"repo": "serde-rs/serde", "ref": "HEAD"},            # Rust serialization
    {"repo": "golang/example", "ref": "HEAD"},
    {"repo": "psf/requests", "ref": "HEAD"},              # Python HTTP — no crypto
    {"repo": "google/gson", "ref": "HEAD"},               # Java JSON — no crypto
    {"repo": "expressjs/express", "ref": "HEAD"},         # JS web framework
    {"repo": "tokio-rs/tokio", "ref": "HEAD"},            # Rust async runtime
    # --- large pure non-crypto codebases for balance -----------------------
    {"repo": "numpy/numpy", "ref": "HEAD"},                 # Python numerics
    {"repo": "pandas-dev/pandas", "ref": "HEAD"},           # Python data
    {"repo": "facebook/react", "ref": "HEAD"},             # JS UI — no crypto
    {"repo": "sveltejs/svelte", "ref": "HEAD"},            # JS UI — no crypto
    {"repo": "apache/commons-lang", "ref": "HEAD"},        # Java utils
]

# Additional real crypto sources already in this repo (no download needed)
LOCAL_CRYPTO_DIRS: List[str] = [
    "contracts/lib/openzeppelin-contracts/contracts",     # Solidity
    "contracts/src",                                      # this project's Solidity
]

_SUPPORTED_EXT: Dict[str, str] = {
    ".py": "python", ".go": "go", ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".js": "javascript", ".ts": "typescript", ".java": "java",
    ".cs": "csharp", ".sol": "solidity", ".sh": "shell",
    ".kt": "kotlin", ".swift": "swift", ".php": "php",
}

_SKIP_DIR_PARTS = ("test", "tests", "fixture", "examples", "bench", "build",
                   "node_modules", ".git", "vendor", "third_party", "target",
                   ".github", "docs", "doc", "misc", "utils", "fuzz", "wasm")


def _download_tarball(owner_repo: str, ref: str) -> Optional[Path]:
    """Download a GitHub repo tarball to cache; return extracted dir or None."""
    org, name = owner_repo.split("/")
    safe = f"{org}__{name}__{ref.replace('/', '-')}"
    extract_dir = CACHE / safe
    if extract_dir.exists():
        return extract_dir
    url = f"https://codeload.github.com/{org}/{name}/tar.gz/{ref}"
    tarball = CACHE / f"{safe}.tar.gz"
    try:
        print(f"  downloading {owner_repo}@{ref} ...")
        urllib.request.urlretrieve(url, tarball)  # noqa: S310 — public github
    except Exception as exc:
        print(f"  ! failed to download {owner_repo}: {exc}")
        return None
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(extract_dir, filter="data")  # type: ignore[attr-defined]
    # codeload extracts into <name>-<ref>/ — flatten one level
    subs = [p for p in extract_dir.iterdir() if p.is_dir()]
    if len(subs) == 1:
        inner = subs[0]
        for child in inner.iterdir():
            shutil.move(str(child), str(extract_dir / child.name))
        inner.rmdir()
    return extract_dir


def _iter_code_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _SUPPORTED_EXT:
            continue
        rel = p.relative_to(root).as_posix().lower()
        if any(part in rel for part in _SKIP_DIR_PARTS):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if len(text) < 80 or len(text) > 200_000:
            continue
        yield p, _SUPPORTED_EXT[p.suffix.lower()], text


def build_code_corpus(max_files_per_repo: int = 600) -> Dict[str, Any]:
    """Label real code files with the trusted deterministic scanner."""
    from qtrust_ai.discovery.code_detector import CryptoCodeDetector

    det = CryptoCodeDetector(seed=42)  # deterministic scanner layer
    corpus: List[Dict[str, Any]] = []
    stats: Dict[str, Counter] = {"crypto": Counter(), "non_crypto": Counter()}

    def _label_files(root: Path, source: str) -> None:
        count = 0
        for p, language, text in _iter_code_files(root):
            if count >= max_files_per_repo:
                break
            try:
                findings = det.scan_file(p) if language in ("python",) else _rules_findings(text, language)
            except Exception:
                findings = _rules_findings(text, language)
            is_crypto = bool(findings)
            label = findings[0].algorithm if is_crypto else "NONE"
            corpus.append({
                "code": text, "language": language, "label": label, "is_crypto": is_crypto,
                "source": source, "path": p.name,
            })
            stats["crypto" if is_crypto else "non_crypto"][language] += 1
            count += 1

    for spec in CRYPTO_REPOS:
        d = _download_tarball(spec["repo"], spec["ref"])
        if d:
            _label_files(d, spec["repo"])
    for spec in NON_CRYPTO_REPOS:
        d = _download_tarball(spec["repo"], spec["ref"])
        if d:
            _label_files(d, spec["repo"])
    for local in LOCAL_CRYPTO_DIRS:
        p = REPO_ROOT / local
        if p.exists():
            _label_files(p, local)

    print(f"  code corpus: {len(corpus)} files | "
          f"crypto={dict(stats['crypto'])} non_crypto={dict(stats['non_crypto'])}")
    return {"type": "code", "corpus": corpus, "stats": {k: dict(v) for k, v in stats.items()}}


_RULES = [
    (re.compile(r"\b(rsa|ecdsa|ecdh|ed25519|x25519|dsa)\b", re.I), "RSA/ECC"),
    (re.compile(r"\b(aes|des|chacha20|twofish|blowfish)\b", re.I), "AES"),
    (re.compile(r"\b(sha(?:1|256|384|512|3)?|md5|hmac|pbkdf2|scrypt|bcrypt|argon2|ripemd(?:160)?|keccak256)\b", re.I), "HASH"),
    (re.compile(r"\b(ml-kem|mlkem|ml-dsa|dilithium|sphincs|slh-dsa|falcon|kyber|hqc)\b", re.I), "PQC"),
    (re.compile(r"\b(openssl|boringssl|libsodium|bouncycastle|mbedtls|wolfssl|cryptography|pycryptodome|sjcl)\b", re.I), "LIB"),
    (re.compile(r"\b(certificate|x509|pkcs|cipher|signature)\b", re.I), "CERT"),
    (re.compile(r"\b(gcm|ccm|ocb|salsa20|poly1305)\b", re.I), "MODE"),
    (re.compile(r"\bcrypto_[a-z0-9_]+\b", re.I), "LIBSODIUM"),
    (re.compile(r"\bcrypto/[a-z0-9_]+\b", re.I), "CRYPTOLIB"),
]


def _rules_findings(text: str, language: str) -> List[Any]:
    """Minimal deterministic rule scan (label source for non-Python files)."""
    class _F:
        algorithm = ""

    findings = []
    lower = text.lower()
    for pattern, label in _RULES:
        if pattern.search(lower):
            f = _F()
            f.algorithm = label
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# 2. Real TLS inventory
# ---------------------------------------------------------------------------

CURATED_HOSTS: List[str] = [
    "example.com", "cloudflare.com", "github.com", "nist.gov", "rust-lang.org",
    "google.com", "youtube.com", "wikipedia.org", "amazon.com", "netflix.com",
    "microsoft.com", "apple.com", "linkedin.com", "facebook.com", "x.com",
    "openai.com", "anthropic.com", "cloud.google.com", "aws.amazon.com",
    "azure.microsoft.com", "stackoverflow.com", "gitlab.com", "bitbucket.org",
    "docker.com", "kubernetes.io", "python.org", "pypi.org", "npmjs.com",
    "crates.io", "golang.org", "nodejs.org", "java.com", "oracle.com",
    "ibm.com", "intel.com", "amd.com", "nvidia.com", "samsung.com",
    "sony.com", "paypal.com", "stripe.com", "squareup.com", "visa.com",
    "mastercard.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "hsbc.com", "jpmorganchase.com", "goldmansachs.com", "bloomberg.com",
    "reuters.com", "nytimes.com", "wsj.com", "ft.com", "cnn.com",
    "bbc.co.uk", "guardian.co.uk", "economist.com", "forbes.com",
    "reddit.com", "medium.com", "quora.com", "twitch.tv", "spotify.com",
    "soundcloud.com", "dropbox.com", "box.com", "salesforce.com",
    "workday.com", "sap.com", "adobe.com", "autodesk.com", "figma.com",
    "canva.com", "notion.so", "slack.com", "zoom.us", "webex.com",
    "discord.com", "telegram.org", "signal.org", "proton.me",
    "tutanota.com", "duckduckgo.com", "brave.com", "mozilla.org",
    "apache.org", "kernel.org", "debian.org", "ubuntu.com", "archlinux.org",
    "fedora.org", "redhat.com", "suse.com", "hashicorp.com", "mongodb.com",
    "postgresql.org", "mysql.com", "redis.io", "elastic.co", "datadoghq.com",
    "newrelic.com", "splunk.com", "sentry.io", "vercel.com", "netlify.com",
    "cloudflare-nginx.com", "fastly.com", "akamai.com", "imperva.com",
    "nordvpn.com", "expressvpn.com", "1password.com", "lastpass.com",
    "dashlane.com", "bitwarden.com", "auth0.com", "okta.com", "duo.com",
    "cisa.gov", "fbi.gov", "whitehouse.gov", "state.gov", "who.int",
    "un.org", "esa.int", "cern.ch", "mit.edu", "stanford.edu", "harvard.edu",
    "ox.ac.uk", "cam.ac.uk", "ethz.ch", "tum.de", "berkeley.edu",
]


def scan_real_hosts(max_hosts: int = 60) -> Dict[str, Any]:
    """Scan real hosts with scripts/scan_hosts.py → per-host CBOMs."""
    hosts = CURATED_HOSTS[:max_hosts]
    hosts_file = ARTIFACTS / "hosts.txt"
    hosts_file.write_text("\n".join(hosts) + "\n")
    out_file = ARTIFACTS / "tls_scan.json"
    # scan_hosts.py writes tls_scan.summary.json alongside out_file itself
    cmd = [sys.executable, str(REPO_ROOT / "scripts" / "scan_hosts.py"),
           "--hosts", str(hosts_file), "-o", str(out_file),
           "--workers", "24"]
    print(f"  scanning {len(hosts)} real hosts (port 443) ...")
    subprocess.run(cmd, check=False, timeout=600)  # noqa: S603

    if not out_file.exists():
        return {"type": "tls", "error": "scan failed", "n_hosts": 0, "n_findings": 0}

    data = json.loads(out_file.read_text())
    findings = data.get("findings", [])
    by_alg: Counter = Counter((f.get("algorithm") or "unknown") for f in findings)
    per_host: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        host = f.get("host") or f.get("location") or "unknown"
        per_host.setdefault(host, []).append(f)

    cboms: List[Dict[str, Any]] = []
    for host, fs in sorted(per_host.items()):
        cboms.append({"schema_version": "qtrust.cbom.v1", "target": host, "assets": fs})

    print(f"  TLS scan: {len(hosts)} hosts, {len(findings)} findings, "
          f"{len(cboms)} per-host CBOMs; algs={dict(by_alg)}")
    return {
        "type": "tls", "n_hosts": len(hosts), "n_findings": len(findings),
        "by_algorithm": dict(by_alg), "cboms": cboms,
    }


# ---------------------------------------------------------------------------
# 3. Real NVD vendor data
# ---------------------------------------------------------------------------

_NVD_LIB_KEYWORDS = {
    "openssl": ["openssl"], "mbedtls": ["mbedtls"], "wolfssl": ["wolfssl"],
    "libsodium": ["libsodium"], "bouncy-castle": ["bouncy castle", "bouncycastle"],
    "python-cryptography": ["python cryptography"], "boringssl": ["boringssl"],
    "aws-lc": ["aws-lc", "aws libcrypto"], "botan": ["botan"],
    "libgcrypt": ["libgcrypt"], "cryptopp": ["crypto++", "cryptopp"],
    "gnupg": ["gnupg"], "libressl": ["libressl"], "nettle": ["nettle"],
    "gnutls": ["gnutls"], "nss": ["network security services"],
}


def fetch_nvd_cves(keywords: Dict[str, List[str]], max_per_lib: int = 40) -> Dict[str, Any]:
    """Pull CVEs mentioning each crypto library from the NVD API 2.0."""
    results: Dict[str, List[Dict[str, Any]]] = {}
    for lib, kws in keywords.items():
        found: List[Dict[str, Any]] = []
        for kw in kws:
            time.sleep(1.5)  # NVD API 2.0 rate limit (no API key)
            url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                   f"?keywordSearch={urllib.request.quote(kw)}&resultsPerPage=40")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "qtrust-ai/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — public NVD API
                    body = json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                print(f"  ! NVD query failed for {lib}: {exc}")
                continue
            for vuln in body.get("vulnerabilities", [])[:max_per_lib]:
                c = vuln.get("cve", {})
                cve_id = c.get("id", "")
                if cve_id in {x["id"] for x in found}:
                    continue
                metrics = c.get("metrics", {})
                base_score = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        try:
                            base_score = float(metrics[key][0]["cvssData"]["baseScore"])
                        except Exception:
                            pass
                        break
                year = int(cve_id.split("-")[1]) if len(cve_id.split("-")) > 1 else 0
                found.append({"id": cve_id, "year": year, "base_score": base_score,
                              "description": (c.get("descriptions") or [{}])[0].get("value", "")[:200]})
        results[lib] = found[:max_per_lib]
        print(f"  NVD {lib}: {len(results[lib])} CVEs")
    return results


def build_vendor_dataset(nvd: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Vendor objects from real NVD CVEs + deterministic PQC-support KB."""
    from qtrust_ai.migration.interoperability import _LIB_PQC_SUPPORT  # noqa: PLC2701 — reuse KB

    records: List[Dict[str, Any]] = []
    for lib, cves in nvd.items():
        info = _LIB_PQC_SUPPORT.get(lib.lower().replace("-", "-").replace("_", "-"), {})
        has_pqc = bool(info.get("supports"))
        min_ver = info.get("min_pqc")
        n_high = sum(1 for c in cves if c["base_score"] >= 7.0)
        n_med = sum(1 for c in cves if 4.0 <= c["base_score"] < 7.0)
        recent = sum(1 for c in cves if c["year"] >= 2023)
        total = len(cves)
        # Readiness label: PQC support dominates; CVE load penalises.
        score = 40.0
        if has_pqc:
            score += 45.0
        if min_ver is not None:
            score += 10.0
        score -= min(35.0, n_high * 6.0 + n_med * 2.0)
        score -= min(15.0, recent * 2.5)
        score = max(5.0, min(95.0, round(score, 1)))
        vendor_name = lib.replace("-", " ").title()
        records.append({
            "vendor": {
                "name": vendor_name,
                "products": [{
                    "name": lib,
                    "libraries": [{
                        "name": lib, "version": min_ver or "n/a",
                        "crypto_algorithms": info.get("supports", []),
                        "pqc_support": has_pqc,
                        "cve_count": total, "cve_high": n_high, "cve_recent": recent,
                    }],
                }],
            },
            "score": score,
            "_nvd": cves,
        })
    print(f"  vendor dataset: {len(records)} libraries with real CVE data")
    return {"type": "vendor", "records": records}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build real datasets for qtrust_ai")
    parser.add_argument("--parts", default="code,tls,nvd",
                        help="comma list: code,tls,nvd")
    parser.add_argument("--hosts", type=int, default=120, help="max hosts to scan")
    parser.add_argument("--max-files-per-repo", type=int, default=600)
    args = parser.parse_args()

    parts = [p.strip() for p in args.parts.split(",") if p.strip()]
    manifest: Dict[str, Any] = {}

    if "code" in parts:
        print("=== Real code corpus ===")
        manifest["code"] = build_code_corpus(max_files_per_repo=args.max_files_per_repo)
        (ARTIFACTS / "code_corpus.json").write_text(json.dumps(manifest["code"], indent=2))

    if "tls" in parts:
        print("=== Real TLS inventory ===")
        manifest["tls"] = scan_real_hosts(max_hosts=args.hosts)
        (ARTIFACTS / "tls_inventory.json").write_text(json.dumps(manifest["tls"], indent=2))

    if "nvd" in parts:
        print("=== Real NVD vendor data ===")
        nvd = fetch_nvd_cves(_NVD_LIB_KEYWORDS)
        manifest["nvd"] = nvd
        (ARTIFACTS / "nvd_cves.json").write_text(json.dumps(nvd, indent=2))
        vendor = build_vendor_dataset(nvd)
        manifest["vendor"] = vendor
        (ARTIFACTS / "vendor_dataset.json").write_text(json.dumps(vendor, indent=2))

    manifest_path = ARTIFACTS / "manifest.json"
    manifest_path.write_text(json.dumps(
        {k: v for k, v in manifest.items() if k not in ("code",)},
        indent=2, default=str))
    print(f"\nDatasets written to {ARTIFACTS}")
    print("  code_corpus.json    (code discovery corpus)")
    print("  tls_inventory.json  (real TLS CBOMs)")
    print("  nvd_cves.json       (real vendor CVEs)")
    print("  vendor_dataset.json (vendor readiness records)")


if __name__ == "__main__":
    main()
