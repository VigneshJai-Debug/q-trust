"""Click-based CLI for the cryptography-inspector scanner.

Commands:
    scan <host>             Scan a single host, print the CBOM as JSON.
    scan-network <cidr>     Scan a network range and print a combined CBOM.
    register <cbom_file>    Register a CBOM on-chain via the Q-Trust SDK.
    verify <asset_id>       Verify an on-chain asset via the Q-Trust SDK.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import click

from qtrust_inspector.scanner import CryptoScanner


def _print_cbom(cbom: dict[str, Any]) -> None:
    """Pretty-print a CBOM to stdout."""
    click.echo(json.dumps(cbom, indent=2, sort_keys=True))


def _load_qtrust_client() -> Any:
    """Import and instantiate the Q-Trust client from the SDK.

    Raises click.ClickException if the SDK or environment is not configured.
    """
    try:
        # Allow importing qtrust.sdk if installed in editable mode
        from qtrust import QTrustClient
    except ImportError as exc:
        raise click.ClickException(
            "qtrust-sdk is not installed. Install with: pip install -e ./sdk"
        ) from exc
    try:
        return QTrustClient()
    except KeyError as exc:
        raise click.ClickException(
            f"Missing environment variable: {exc}. "
            "Set QTRUST_DEPLOYER_PRIVATE_KEY, QTRUST_BASE_SEPOLIA_RPC, "
            "QTRUST_REGISTRY_ADDRESS, QTRUST_PINATA_API_KEY, "
            "QTRUST_PINATA_API_SECRET."
        ) from exc


@click.group()
@click.version_option(package_name="cryptography-inspector")
def app() -> None:
    """cryptography-inspector — discover cryptographic assets and produce CBOMs."""


@app.command()
@click.argument("host")
@click.option("--timeout", default=5, show_default=True, help="Socket timeout (seconds).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write CBOM to file instead of stdout.")
def scan(host: str, timeout: int, output: str | None) -> None:
    """Scan a single host and print its CBOM as JSON."""
    scanner = CryptoScanner(timeout=timeout)
    click.echo(f"Scanning {host}..." , err=True)
    findings = scanner.scan_host(host)
    cbom = scanner.generate_cbom(findings)

    if output:
        scanner.save_cbom(cbom, output)
        click.echo(f"CBOM written to {output}", err=True)
        click.echo(f"CBOM hash: {scanner.hash_cbom(cbom)}", err=True)
    else:
        _print_cbom(cbom)


@app.command(name="scan-network")
@click.argument("cidr")
@click.option("--timeout", default=5, show_default=True, help="Socket timeout (seconds).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write CBOM to file instead of stdout.")
def scan_network(cidr: str, timeout: int, output: str | None) -> None:
    """Scan a network range (CIDR) and print a combined CBOM."""
    scanner = CryptoScanner(timeout=timeout)
    click.echo(f"Discovering hosts in {cidr}...", err=True)
    findings = scanner.scan_network(cidr)
    cbom = scanner.generate_cbom(findings)

    if output:
        scanner.save_cbom(cbom, output)
        click.echo(f"CBOM written to {output}", err=True)
    else:
        _print_cbom(cbom)


@app.command()
@click.argument("cbom_file", type=click.Path(exists=True))
def register(cbom_file: str) -> None:
    """Register a CBOM JSON file on-chain via the Q-Trust SDK."""
    with open(cbom_file, "r", encoding="utf-8") as f:
        cbom = json.load(f)

    scanner = CryptoScanner()
    cbom_hash = scanner.hash_cbom(cbom)
    asset_count = cbom.get("asset_count", len(cbom.get("assets", [])))

    # Build an algorithm summary
    algorithms: dict[str, int] = {}
    for asset in cbom.get("assets", []):
        alg = asset.get("algorithm", "unknown")
        algorithms[alg] = algorithms.get(alg, 0) + 1

    client = _load_qtrust_client()
    click.echo(f"Registering CBOM with hash {cbom_hash}...", err=True)
    click.echo(f"Asset count: {asset_count}", err=True)
    click.echo(f"Algorithms: {algorithms}", err=True)

    asset_id = client.register_cbom_hash(cbom_hash=cbom_hash)
    click.echo(f"Registered! Asset ID: {asset_id}")


@app.command()
@click.argument("asset_id")
def verify(asset_id: str) -> None:
    """Verify an on-chain asset via the Q-Trust SDK."""
    client = _load_qtrust_client()

    if not asset_id.startswith("0x"):
        click.echo("Asset ID must be a 0x-prefixed hex string", err=True)
        sys.exit(1)

    try:
        exists, active, org_did = client.verify_asset(asset_id)
    except Exception as exc:
        raise click.ClickException(f"Verification failed: {exc}") from exc

    click.echo(json.dumps({
        "asset_id": asset_id,
        "exists": exists,
        "active": active,
        "org_did": org_did,
    }, indent=2))


@app.command()
@click.argument("cbom_file", type=click.Path(exists=True))
@click.option("--asset-id", required=True, help="The asset ID returned by `register`.")
def plan(cbom_file: str, asset_id: str) -> None:
    """Run the GNN migration planner over a CBOM. (Convenience wrapper.)

    This invokes the gnn.predict.predict_migration_order function if available.
    """
    try:
        # Allow importing the GNN package from a sibling directory
        gnn_root = Path(cbom_file).resolve().parent.parent / "gnn"
        if gnn_root.exists():
            sys.path.insert(0, str(gnn_root))
        from predict import predict_migration_order
    except ImportError as exc:
        raise click.ClickException(
            "GNN module not found. Run from the qtrust/ root or install the gnn package."
        ) from exc

    order = predict_migration_order(cbom_file)
    click.echo(json.dumps({
        "asset_id": asset_id,
        "cbom_file": cbom_file,
        "recommended_migration_order": order,
    }, indent=2))


if __name__ == "__main__":
    app()
