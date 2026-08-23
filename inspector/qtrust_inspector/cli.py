from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .models import ScanResult
from .scanner import scan_directory, scan_host, scan_network

app = typer.Typer(
    name="crypto-inspector",
    help="Enterprise PQC migration scanner -- discover, score, comply, plan.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

try:
    from qtrust import QTrustClient
    from qtrust.schema import CBOM
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


def _get_client():
    if not SDK_AVAILABLE:
        console.print(
            "[red]qtrust-sdk is not installed.[/red] Install with:\n"
            "  pip install -e sdk/\n"
        )
        raise typer.Exit(1)
    try:
        return QTrustClient()
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@app.command()
def host(
    hostname: str = typer.Argument(..., help="Hostname to scan"),
    ports: str = typer.Option("443,8443,22", "--ports", "-p"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    risk: bool = typer.Option(True, "--risk/--no-risk", help="Include risk scoring"),
    compliance: Optional[str] = typer.Option(None, "--compliance", "-c", help="Comma-separated frameworks: nist,cnsa,fips,nis2,fisma,fedramp,cmmc"),
    cyclonedx: Optional[Path] = typer.Option(None, "--cyclonedx", help="Export CycloneDX 1.7 CBOM"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="Export SARIF 2.1 for GitHub"),
    register: bool = typer.Option(False, "--register"),
):
    """Scan a single host for cryptographic assets."""
    try:
        port_list = [int(p.strip()) for p in ports.split(",")]
    except ValueError as e:
        console.print(f"[red]Invalid port format: {e}[/red]")
        raise typer.Exit(1)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description=f"Scanning {hostname}...", total=None)
        result = scan_host(hostname, port_list)
    _display(result)
    _apply_outputs(result, output, risk, compliance, cyclonedx, sarif_out, register)


@app.command()
def directory(
    path: Path = typer.Argument(..., help="Directory to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    source: bool = typer.Option(True, "--source/--no-source", help="Scan source code for crypto APIs"),
    manifests: bool = typer.Option(True, "--manifests/--no-manifests", help="Scan package manifests"),
    risk: bool = typer.Option(True, "--risk/--no-risk", help="Include risk scoring"),
    compliance: Optional[str] = typer.Option(None, "--compliance", "-c"),
    cyclonedx: Optional[Path] = typer.Option(None, "--cyclonedx", help="Export CycloneDX 1.7 CBOM"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="Export SARIF 2.1 for GitHub"),
):
    """Scan a directory for cryptographic assets (certs, keys, source, manifests)."""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description=f"Scanning {path}...", total=None)
        result = scan_directory(str(path))
        if source:
            from .source_scanner import scan_source_directory
            for finding in scan_source_directory(str(path)):
                result.findings.append(finding)
        if manifests:
            from .manifest_scanner import scan_manifest
            for finding in scan_manifest(str(path)):
                result.findings.append(finding)
    _display(result)
    _apply_outputs(result, output, risk, compliance, cyclonedx, sarif_out, False)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: hostname, directory path, or CIDR range"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    source: bool = typer.Option(True, "--source/--no-source"),
    manifests: bool = typer.Option(True, "--manifests/--no-manifests"),
    risk: bool = typer.Option(True, "--risk/--no-risk"),
    compliance: Optional[str] = typer.Option(None, "--compliance", "-c"),
    cyclonedx: Optional[Path] = typer.Option(None, "--cyclonedx"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif"),
    evidence: Optional[Path] = typer.Option(None, "--evidence", help="Hash-chained evidence ledger path"),
    roadmap_out: Optional[Path] = typer.Option(None, "--roadmap", help="Migration roadmap output"),
    daily_rate: float = typer.Option(1500.0, "--daily-rate", help="Daily rate for cost estimation"),
):
    """Universal scan command -- auto-detects target type and runs all scanners."""
    results: list[ScanResult] = []
    if Path(target).is_dir():
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description=f"Scanning directory {target}...", total=None)
            result = scan_directory(target)
            if source:
                from .source_scanner import scan_source_directory
                for finding in scan_source_directory(target):
                    result.findings.append(finding)
            if manifests:
                from .manifest_scanner import scan_manifest
                for finding in scan_manifest(target):
                    result.findings.append(finding)
            results.append(result)
    elif _is_cidr(target):
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description=f"Scanning network {target}...", total=None)
            results = scan_network([target])
    else:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description=f"Scanning host {target}...", total=None)
            result = scan_host(target)
            results.append(result)

    combined = _merge_results(results)
    _display(combined)

    if evidence:
        _write_evidence(combined, evidence)
    if roadmap_out:
        _write_roadmap(combined, roadmap_out, daily_rate)
    _apply_outputs(combined, output, risk, compliance, cyclonedx, sarif_out, False)


@app.command()
def risk_score(
    scan_file: Path = typer.Argument(..., help="Path to a scan result JSON file"),
):
    """Calculate risk scores for a scan result."""
    data = json.loads(scan_file.read_text())
    findings = data.get("findings", [])
    from .risk_engine import calculate_risk_score
    from .models import AssetFinding
    table = Table(title="Risk Scores")
    table.add_column("Type", style="cyan")
    table.add_column("Algorithm", style="yellow")
    table.add_column("Location", style="green")
    table.add_column("Quantum", style="red")
    table.add_column("NIST", style="magenta")
    table.add_column("HNDL", style="blue")
    table.add_column("Risk", style="bold red")
    table.add_column("Action", style="white")
    for f_data in findings:
        finding = AssetFinding(**f_data)
        rs = calculate_risk_score(finding)
        nist = "YES" if rs.nist_800_131a_compliant else "NO"
        table.add_row(
            finding.asset_type,
            finding.algorithm or "-",
            finding.location,
            rs.quantum_vulnerability,
            nist,
            f"{rs.hndl_exposure_score:.0f}",
            rs.risk_level,
            rs.recommended_action[:50],
        )
    console.print(table)


@app.command()
def compliance_check(
    scan_file: Path = typer.Argument(..., help="Path to a scan result JSON file"),
    framework: str = typer.Option("nist,cnsa,fips", "--framework", "-f", help="Comma-separated frameworks"),
):
    """Evaluate compliance against PQC frameworks."""
    from .compliance import ComplianceEngine, ComplianceFramework
    from .models import AssetFinding
    engine = ComplianceEngine()
    fw_map = {
        "nist": ComplianceFramework.NIST_SP_800_131A,
        "cnsa": ComplianceFramework.CNSA_2_0,
        "fips": ComplianceFramework.FIPS_140_3,
        "nis2": ComplianceFramework.EU_NIS2,
        "fisma": ComplianceFramework.FISMA,
        "fedramp": ComplianceFramework.FEDRAMP,
        "cmmc": ComplianceFramework.CMMC,
    }
    frameworks = [fw_map[f.strip()] for f in framework.split(",") if f.strip() in fw_map]
    data = json.loads(scan_file.read_text())
    findings = data.get("findings", [])
    for fw in frameworks:
        total = compliant = non_compliant = partial = 0
        for f_data in findings:
            finding = AssetFinding(**f_data)
            result = engine.evaluate(finding, fw)
            total += result.total_rules
            compliant += result.compliant_count
            non_compliant += result.non_compliant_count
            partial += result.partial_count
        score = (compliant / total * 100) if total > 0 else 0
        console.print(f"\n[bold cyan]{fw.value}[/bold cyan]")
        console.print(f"  Score: {score:.0f}%  ({compliant}/{total} rules compliant)")
        console.print(f"  Non-compliant: {non_compliant}  Partial: {partial}")


@app.command()
def evidence_verify(
    ledger_path: Path = typer.Argument(..., help="Path to evidence ledger JSON"),
):
    """Verify the integrity of a hash-chained evidence ledger."""
    from .evidence import EvidenceLedger
    ledger = EvidenceLedger.load(str(ledger_path))
    valid, msg = ledger.verify()
    if valid:
        console.print(f"[bold green]LEDGER VALID[/bold green] -- {ledger.entry_count} entries")
    else:
        console.print(f"[bold red]LEDGER INVALID[/bold red] -- {msg}")
        raise typer.Exit(1)


@app.command()
def export(
    scan_file: Path = typer.Argument(..., help="Path to a scan result JSON file"),
    cyclonedx: Optional[Path] = typer.Option(None, "--cyclonedx", help="CycloneDX 1.7 output"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="SARIF 2.1 output"),
    evidence_out: Optional[Path] = typer.Option(None, "--evidence", help="Evidence ledger output"),
    roadmap_out: Optional[Path] = typer.Option(None, "--roadmap", help="Migration roadmap"),
    daily_rate: float = typer.Option(1500.0, "--daily-rate"),
):
    """Export scan results in various formats."""
    from .models import ScanResult as SR
    data = json.loads(scan_file.read_text())
    result = SR(**data)
    if cyclonedx:
        from .cyclonedx import generate_cyclonedx, save_cyclonedx
        cdx = generate_cyclonedx(result)
        save_cyclonedx(cdx, str(cyclonedx))
        console.print(f"[green]CycloneDX 1.7 saved to {cyclonedx}[/green]")
    if sarif_out:
        from .sarif import generate_sarif, save_sarif
        sarif = generate_sarif([result])
        save_sarif(sarif, str(sarif_out))
        console.print(f"[green]SARIF 2.1 saved to {sarif_out}[/green]")
    if evidence_out:
        _write_evidence(result, evidence_out)
    if roadmap_out:
        _write_roadmap(result, roadmap_out, daily_rate)


@app.command()
def register_cbom(
    cbom_path: Path = typer.Argument(..., help="Path to a CBOM JSON file"),
    metadata_uri: str = typer.Option("", "--metadata-uri", "-m"),
):
    """Register a CBOM JSON file on-chain. Returns the asset ID."""
    if not cbom_path.exists():
        console.print(f"[red]File not found: {cbom_path}[/red]")
        raise typer.Exit(1)
    cbom_dict = json.loads(cbom_path.read_text())
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
        return asset_id
    client = _get_client()
    cbom_hash = client.hash_string(cbom_path.read_text())
    asset_id = client.register_cbom_hash(cbom_hash, metadata_uri)
    console.print(f"\n[bold green]CBOM registered[/bold green]  asset_id: {asset_id}")
    return asset_id


@app.command()
def attest_product(
    product_id: str = typer.Argument(...),
    version: str = typer.Argument(...),
    algorithm: str = typer.Argument(...),
    supported: bool = typer.Option(True, "--supported/--not-supported"),
    evidence_uri: str = typer.Option("", "--evidence-uri", "-e"),
):
    """Post a vendor PQC attestation on-chain."""
    client = _get_client()
    attestation_id = client.attest_product(product_id, version, algorithm, supported, evidence_uri)
    console.print(f"\n[bold green]Attestation posted[/bold green]  id: {attestation_id}")
    return attestation_id


@app.command()
def verify(asset_id: str = typer.Argument(...)):
    """Verify an on-chain CBOM registration."""
    client = _get_client()
    exists, active, org_did = client.verify_asset(asset_id)
    if not exists:
        console.print(f"[red]Asset not found: {asset_id}[/red]")
        raise typer.Exit(1)
    record = client.get_asset(asset_id)
    status = "VALID" if active else "REVOKED"
    console.print(f"\n[bold green]{status}[/bold green] -- asset {asset_id}")
    console.print(f"  org_did : {org_did}")
    console.print(f"  cbom_hash: {record.cbom_hash}")


@app.command()
def retire(asset_id: str = typer.Argument(...)):
    """Retire a CBOM registration."""
    client = _get_client()
    tx_hash = client.retire_asset(asset_id)
    console.print(f"[bold green]Asset retired[/bold green] tx={tx_hash}")


def _is_cidr(target: str) -> bool:
    import re
    return bool(re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", target))


def _merge_results(results: list[ScanResult]) -> ScanResult:
    if not results:
        return ScanResult(target="empty")
    merged = ScanResult(
        target=results[0].target,
        findings=[],
    )
    for r in results:
        merged.findings.extend(r.findings)
    return merged


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
            table.add_row(f.asset_type, f.algorithm or "-", f.location, f.vendor or "-", f.criticality)
        console.print(table)


def _apply_outputs(result, output, risk, compliance, cyclonedx, sarif_out, register):
    if output:
        output.write_text(result.model_dump_json(indent=2))
        console.print(f"\n[green]Saved to {output}[/green]")
    if risk:
        from .risk_engine import calculate_risk_score
        console.print("\n[bold cyan]Risk Assessment:[/bold cyan]")
        for f in result.findings:
            rs = calculate_risk_score(f)
            console.print(f"  {f.location}: {rs.risk_level} (quantum={rs.quantum_vulnerability}, score={rs.overall_risk_score:.0f})")
    if compliance:
        from .compliance import ComplianceEngine, ComplianceFramework
        engine = ComplianceEngine()
        fw_map = {
            "nist": ComplianceFramework.NIST_SP_800_131A,
            "cnsa": ComplianceFramework.CNSA_2_0,
            "fips": ComplianceFramework.FIPS_140_3,
            "nis2": ComplianceFramework.EU_NIS2,
            "fisma": ComplianceFramework.FISMA,
            "fedramp": ComplianceFramework.FEDRAMP,
            "cmmc": ComplianceFramework.CMMC,
        }
        console.print("\n[bold cyan]Compliance:[/bold cyan]")
        for f_name in compliance.split(","):
            fw = fw_map.get(f_name.strip())
            if fw:
                for f in result.findings:
                    cr = engine.evaluate(f, fw)
                    if cr.non_compliant_count > 0:
                        console.print(f"  {f.location} [{fw.value}]: {cr.non_compliant_count} non-compliant rules (score: {cr.score:.0f}%)")
    if cyclonedx:
        from .cyclonedx import generate_cyclonedx, save_cyclonedx
        cdx = generate_cyclonedx(result)
        save_cyclonedx(cdx, str(cyclonedx))
        console.print(f"\n[green]CycloneDX 1.7 CBOM saved to {cyclonedx}[/green]")
    if sarif_out:
        from .sarif import generate_sarif, save_sarif
        sarif = generate_sarif([result])
        save_sarif(sarif, str(sarif_out))
        console.print(f"\n[green]SARIF 2.1 saved to {sarif_out}[/green]")
    if register:
        _register_onchain(result)


def _write_evidence(result: ScanResult, evidence_path: Path):
    from .evidence import EvidenceLedger
    import hashlib
    cbom = result.to_cbom()
    cbom_hash = "0x" + hashlib.sha256(json.dumps(cbom, sort_keys=True).encode()).hexdigest()
    batch_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    ledger = EvidenceLedger(batch_id)
    risk_summary = {}
    for f in result.findings:
        from .risk_engine import calculate_risk_score
        rs = calculate_risk_score(f)
        risk_summary[f.location] = rs.risk_level
    ledger.append(
        scan_result_hash=cbom_hash,
        scan_target=result.target,
        findings_count=result.finding_count,
        risk_summary=risk_summary,
    )
    ledger.save(str(evidence_path))
    console.print(f"\n[green]Evidence ledger saved to {evidence_path}[/green]")


def _write_roadmap(result: ScanResult, roadmap_path: Path, daily_rate: float):
    from .roadmap import generate_roadmap
    roadmap = generate_roadmap(
        [f.model_dump() for f in result.findings],
        daily_rate_usd=daily_rate,
    )
    roadmap_path.write_text(json.dumps(roadmap.model_dump(), indent=2))
    console.print(f"\n[green]Migration roadmap saved to {roadmap_path}[/green]")
    console.print(f"  Total effort: {roadmap.total_effort_days:.1f} days")
    console.print(f"  Estimated cost: ${roadmap.total_cost_usd:,.0f}")
    console.print(f"  Timeline: {roadmap.timeline_months:.1f} months")


def _register_onchain(scan_result: ScanResult):
    cbom_dict = scan_result.to_cbom()
    if SDK_AVAILABLE:
        client = _get_client()
        asset_id = client.register_cbom_hash(
            client.hash_string(json.dumps(cbom_dict, sort_keys=True))
        )
        console.print(f"\n[bold green]CBOM registered on-chain[/bold green]  asset_id: {asset_id}")
        return asset_id
    console.print("[yellow]qtrust-sdk not installed -- skipping on-chain registration[/yellow]")
    return None


if __name__ == "__main__":
    app()
