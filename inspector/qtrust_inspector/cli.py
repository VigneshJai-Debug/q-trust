from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .models import ScanResult
from .scanner import scan_directory, scan_host, scan_network

app = typer.Typer(name="qtrust-scan", help="Cryptographic asset scanner for Q-Trust",
                  no_args_is_help=True, rich_markup_mode="rich")
console = Console()

try:
    from qtrust import QTrustClient
    from qtrust.schema import CBOM
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


def _get_client() -> "QTrustClient":
    """Build an SDK client from env config, with a helpful error if unavailable."""
    if not SDK_AVAILABLE:
        console.print(
            "[red]qtrust-sdk is not installed.[/red] Install it with:\n"
            "  pip install -e sdk/\n"
            "or set PYTHONPATH=sdk/"
        )
        raise typer.Exit(1)
    try:
        return QTrustClient()
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        console.print("Set QTRUST_DEPLOYER_PRIVATE_KEY (writes) or leave unset (reads).")
        raise typer.Exit(1)


@app.command()
def host(
    hostname: str = typer.Argument(..., help="Hostname to scan"),
    ports: str = typer.Option("443,8443,22", "--ports", "-p"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    register: bool = typer.Option(False, "--register"),
):
    """Scan a single host."""
    try:
        port_list = [int(p.strip()) for p in ports.split(",")]
    except ValueError as e:
        console.print(f"[red]Invalid port format: {e}[/red]")
        raise typer.Exit(1)
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
    ) as progress:
        progress.add_task(description=f"Scanning {hostname}...", total=None)
        result = scan_host(hostname, port_list)

    _display(result)
    if output:
        output.write_text(result.model_dump_json(indent=2))
        console.print(f"\n[green]Saved to {output}[/green]")
    if register:
        _register_onchain(result)


@app.command()
def directory(
    path: Path = typer.Argument(..., help="Directory to scan"),
    output: Path | None = typer.Option(None, "--output", "-o"),
):
    """Scan a directory."""
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
    ) as progress:
        progress.add_task(description=f"Scanning {path}...", total=None)
        result = scan_directory(str(path))

    _display(result)
    if output:
        output.write_text(result.model_dump_json(indent=2))
        console.print(f"\n[green]Saved to {output}[/green]")


@app.command()
def network(
    hosts_file: Path = typer.Argument(..., help="File containing list of hosts"),
    ports: str = typer.Option("443,22", "--ports", "-p"),
):
    """Scan multiple hosts from a file."""
    if not hosts_file.exists():
        console.print(f"[red]File not found: {hosts_file}[/red]")
        raise typer.Exit(1)
    hosts = [
        host.strip()
        for host in hosts_file.read_text().splitlines()
        if host.strip() and not host.startswith("#")
    ]
    try:
        port_list = [int(p.strip()) for p in ports.split(",")]
    except ValueError as e:
        console.print(f"[red]Invalid port format: {e}[/red]")
        raise typer.Exit(1)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
    ) as progress:
        progress.add_task(description=f"Scanning network from {hosts_file}...", total=None)
        results = scan_network(hosts, port_list)

    total = sum(r.finding_count for r in results)
    console.print(
        f"\n[bold green]Scan complete:[/bold green] {len(results)} hosts, {total} findings"
    )
    for r in results:
        _display(r)


@app.command()
def register_cbom(
    cbom_path: Path = typer.Argument(..., help="Path to a CBOM JSON file"),
    metadata_uri: str = typer.Option("", "--metadata-uri", "-m",
                                     help="IPFS URI for the full CBOM (optional)"),
):
    """Register a CBOM JSON file on-chain. Returns the asset ID."""
    if not cbom_path.exists():
        console.print(f"[red]File not found: {cbom_path}[/red]")
        raise typer.Exit(1)

    try:
        cbom_dict = json.loads(cbom_path.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON in CBOM file: {e}[/red]")
        raise typer.Exit(1)
    if SDK_AVAILABLE:
        try:
            cbom = CBOM.model_validate(cbom_dict)
        except Exception as e:
            console.print(f"[red]Invalid CBOM: {e}[/red]")
            raise typer.Exit(1)
        client = _get_client()
        asset_id = client.register_cbom_hash(client.hash_cbom(cbom), metadata_uri)
        console.print(f"\n[bold green]CBOM registered[/bold green]")
        console.print(f"  asset_id : {asset_id}")
        console.print(f"  cbom_hash: {client.hash_cbom(cbom)}")
        console.print(f"  verify   : qtrust-scan verify {asset_id}")
        return asset_id

    # Fallback: register just the hash (no schema validation).
    client = _get_client()
    cbom_hash = client.hash_string(cbom_path.read_text())
    asset_id = client.register_cbom_hash(cbom_hash, metadata_uri)
    console.print(f"\n[bold green]CBOM registered (raw-hash mode)[/bold green]")
    console.print(f"  asset_id: {asset_id}")
    return asset_id


@app.command()
def attest_product(
    product_id: str = typer.Argument(..., help="Product ID, e.g. DigiCert-TLS"),
    version: str = typer.Argument(..., help="Product version, e.g. 5.2.1"),
    algorithm: str = typer.Argument(..., help="Algorithm, e.g. ML-DSA-441"),
    supported: bool = typer.Option(True, "--supported/--not-supported",
                                   help="Whether the product supports the algorithm"),
    evidence_uri: str = typer.Option("", "--evidence-uri", "-e",
                                     help="IPFS URI for test evidence"),
):
    """Post a vendor PQC attestation on-chain (vendor key via env)."""
    client = _get_client()
    attestation_id = client.attest_product(product_id, version, algorithm, supported, evidence_uri)
    console.print(f"\n[bold green]Attestation posted[/bold green]")
    console.print(f"  attestation_id: {attestation_id}")
    console.print(f"  {product_id} v{version} {algorithm} supported={supported}")
    return attestation_id


@app.command()
def verify(asset_id: str = typer.Argument(..., help="On-chain asset ID (0x-prefixed bytes32)")):
    """Verify an on-chain CBOM registration (read-only, no key needed)."""
    client = _get_client()
    exists, active, org_did = client.verify_asset(asset_id)
    if not exists:
        console.print(f"[red]Asset not found on-chain: {asset_id}[/red]")
        raise typer.Exit(1)
    record = client.get_asset(asset_id)
    status = "VALID" if active else "REVOKED"
    console.print(f"\n[bold green]{status}[/bold green] — asset {asset_id}")
    console.print(f"  org_did     : {org_did}")
    console.print(f"  cbom_hash   : {record.cbom_hash}")
    console.print(f"  metadata_uri: {record.metadata_uri or '(none)'}")
    console.print(f"  registered  : {record.registered_at} (unix)")
    console.print(f"  last updated: {record.last_updated} (unix)")


@app.command()
def retire(asset_id: str = typer.Argument(..., help="On-chain asset ID to retire")):
    """Retire a CBOM registration (owner or admin key via env)."""
    client = _get_client()
    tx_hash = client.retire_asset(asset_id)
    console.print(f"[bold green]Asset retired[/bold green] tx={tx_hash}")


def _display(result: ScanResult):
    console.print(f"\n[bold cyan]Scan result: {result.target}[/bold cyan]")
    console.print(f"  Findings: {result.finding_count}")
    console.print(f"  By algorithm: {result.by_algorithm}")
    console.print(f"  By type: {result.by_type}")
    if result.findings:
        table = Table(title=f"Findings for {result.target}")
        table.add_column("Type", style="cyan")
        table.add_column("Algorithm", style="yellow")
        table.add_column("Location", style="green")
        table.add_column("Vendor", style="magenta")
        table.add_column("Criticality", style="red")
        for f in result.findings:
            table.add_row(f.asset_type, f.algorithm, f.location, f.vendor or "-", f.criticality)
        console.print(table)


def _register_onchain(scan_result: ScanResult):
    """Register a scan result as a CBOM on-chain."""
    cbom_dict = scan_result.to_cbom()
    if SDK_AVAILABLE:
        try:
            cbom = CBOM.model_validate(cbom_dict)
        except Exception:
            cbom = None
        client = _get_client()
        if cbom is not None:
            asset_id = client.register_cbom_hash(client.hash_cbom(cbom))
        else:
            asset_id = client.register_cbom_hash(
                client.hash_string(json.dumps(cbom_dict, sort_keys=True))
            )
        console.print(f"\n[bold green]CBOM registered on-chain[/bold green]")
        console.print(f"  asset_id: {asset_id}")
        console.print(f"  verify  : qtrust-scan verify {asset_id}")
        return asset_id
    console.print("[yellow]qtrust-sdk not installed — skipping on-chain registration[/yellow]")
    return None


if __name__ == "__main__":
    app()