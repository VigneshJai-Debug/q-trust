"""
GitHub/GitLab ingestion — §2/§25/§60 Phase 1.

Fetches real repositories, extracts build/dependency metadata, AST-ready file tree.
Uses GitHub tarball API (no token needed for public repos; rate-limited).
"""
from __future__ import annotations

import shutil
import tarfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional


CACHE = Path("qtrust/data/raw/cache")
CACHE.mkdir(parents=True, exist_ok=True)


def download_repo(owner_repo: str, ref: str = "HEAD") -> Optional[Path]:
    org, name = owner_repo.split("/")
    safe = f"{org}__{name}__{ref.replace('/', '-')}"
    extract_dir = CACHE / safe
    if extract_dir.exists():
        return extract_dir
    url = f"https://codeload.github.com/{org}/{name}/tar.gz/{ref}"
    tarball = CACHE / f"{safe}.tar.gz"
    try:
        urllib.request.urlretrieve(url, tarball)
    except Exception as exc:
        print(f"! download failed {owner_repo}: {exc}")
        return None
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(extract_dir, filter="data")
    subs = [p for p in extract_dir.iterdir() if p.is_dir()]
    if len(subs) == 1:
        inner = subs[0]
        for child in inner.iterdir():
            shutil.move(str(child), str(extract_dir / child.name))
        inner.rmdir()
    return extract_dir


CRYPTO_REPOS: List[Dict[str, str]] = [
    {"repo": "pyca/cryptography", "org": "pyca"},
    {"repo": "cloudflare/circl", "org": "cloudflare"},
    {"repo": "openssl/openssl", "org": "openssl"},
    {"repo": "google/boringssl", "org": "google"},
    {"repo": "aws/aws-lc", "org": "aws"},
    {"repo": "mbedtls/mbedtls", "org": "mbedtls"},
    {"repo": "wolfSSL/wolfssl", "org": "wolfssl"},
    {"repo": "rustls/rustls", "org": "rustls"},
    {"repo": "jedisct1/libsodium", "org": "jedisct1"},
]
