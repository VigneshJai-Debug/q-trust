from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key

from .models import AssetFinding


def scan_pem_files(directory: str) -> Iterator[AssetFinding]:
    """Scan a directory for PEM files (certificates and keys)."""
    path_obj = Path(directory)
    if not path_obj.exists():
        return

    patterns = ["**/*.pem", "**/*.crt", "**/*.key", "**/*.cert"]
    for pattern in patterns:
        for path in path_obj.glob(pattern):
            try:
                content = path.read_bytes()
                # Try Certificate
                try:
                    cert = x509.load_der_x509_certificate(content)
                    yield AssetFinding(
                        asset_type="tls_certificate",
                        host=str(path),
                        algorithm="unknown", # Need more info from cert
                        criticality="medium",
                        metadata={"serial": str(cert.serial_number)}
                    )
                    continue
                except Exception:
                    pass

                # Try Private Key
                try:
                    load_pem_private_key(content, password=None)
                    yield AssetFinding(
                        asset_type="private_key",
                        host=str(path),
                        criticality="high"
                    )
                    continue
                except Exception:
                    pass

            except Exception:
                continue

def scan_ssh_directory(ssh_dir: str = "~/.ssh") -> Iterator[AssetFinding]:
    """Scan ~/.ssh for public keys."""
    ssh_path = Path(ssh_dir).expanduser()
    if not ssh_path.exists():
        return
    for key_file in ssh_path.glob("*.pub"):
        try:
            content = key_file.read_bytes()
            load_ssh_public_key(content)
            yield AssetFinding(
                asset_type="ssh_key",
                host=str(key_file),
                criticality="medium"
            )
        except Exception:
            continue
