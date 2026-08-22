#!/usr/bin/env python3
"""Q-Trust Phase 8 — First National Bank PQC migration pilot (end-to-end).

Runs the full demo:
  1. Scan a target for cryptographic assets (TLS/SSH) -> CBOM
  2. Register the CBOM on-chain (Base Sepolia, or local anvil by default)
  3. Quantum threat analysis (Shor's algorithm resource estimate)
  4. GNN migration planner (ranks assets by priority/risk)
  5. Vendor attestation + migration record + audit, all on-chain
  6. Verify every on-chain record and print demo URLs

Environment (all optional — sensible local defaults):
  QTRUST_BASE_SEPOLIA_RPC         default http://127.0.0.1:8545
  QTRUST_DEPLOYER_PRIVATE_KEY     default anvil dev key
  QTRUST_ASSET_REGISTRY_ADDRESS   etc. — required unless using defaults below
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk"))
sys.path.insert(0, str(REPO / "inspector"))
sys.path.insert(0, str(REPO / "planner"))

from qtrust import QTrustClient  # noqa: E402
from qtrust.schema import CBOM, CBOMEntry  # noqa: E402
from qtrust_inspector.scanner import scan_host  # noqa: E402

# Local anvil defaults (see contracts/ + sdk/tests/run_e2e.sh)
DEFAULT_ADDRS = {
    "QTRUST_ASSET_REGISTRY_ADDRESS": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
    "QTRUST_VENDOR_REGISTRY_ADDRESS": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
    "QTRUST_MIGRATION_REGISTRY_ADDRESS": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
    "QTRUST_AUDIT_REGISTRY_ADDRESS": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
}
for k, v in DEFAULT_ADDRS.items():
    os.environ.setdefault(k, v)
os.environ.setdefault("QTRUST_DEPLOYER_PRIVATE_KEY",
                      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
os.environ.setdefault("QTRUST_BASE_SEPOLIA_RPC", "http://127.0.0.1:8545")

BANNER = "=" * 70


def step1_scan(target: str = "example.com") -> dict:
    print(f"\n{BANNER}\nSTEP 1: Scan {target} for cryptographic assets\n{BANNER}")
    result = scan_host(target, ports=[443, 22])
    print(f"Findings: {result.finding_count} | by_algorithm: {result.by_algorithm} | by_type: {result.by_type}")
    for f in result.findings:
        print(f"  - [{f.asset_type}] {f.algorithm} at {f.location} (vendor: {f.vendor or 'unknown'})")
    if result.finding_count == 0:
        print("No findings from network scan — using synthetic bank CBOM for the demo.")
        cbom = CBOM(
            org_did=f"did:ethr:{QTrustClient().account.address}",
            generated_at=int(time.time()),
            scanner_version="qtrust-inspector 0.1.0 (synthetic)",
            assets=[
                CBOMEntry(asset_type="tls_cert", algorithm="RSA-2048",
                          location="bank.example.com:443", vendor="DigiCert",
                          criticality="critical"),
                CBOMEntry(asset_type="ssh_key", algorithm="RSA-2048",
                          location="bank.example.com:22", criticality="high"),
                CBOMEntry(asset_type="tls_cert", algorithm="ECC-P256",
                          location="api.bank.example.com:443", vendor="Let's Encrypt",
                          criticality="medium"),
                CBOMEntry(asset_type="code_signing", algorithm="RSA-4096",
                          location="signing.hsm.bank.example.com", vendor="Thales",
                          criticality="high"),
                CBOMEntry(asset_type="jwt", algorithm="HS256",
                          location="auth.bank.example.com", criticality="medium"),
            ],
            summary={"total_assets": 5, "by_algorithm": {"RSA-2048": 2, "ECC-P256": 1, "RSA-4096": 1, "HS256": 1}},
        )
        return {"cbom": cbom, "synthetic": True}
    cbom_json = result.to_cbom()
    cbom = CBOM(
        org_did=f"did:ethr:{QTrustClient().account.address}",
        generated_at=int(time.time()),
        scanner_version=cbom_json.get("scanner_version", "qtrust-inspector 0.1.0"),
        assets=[
            CBOMEntry(
                asset_type=f.asset_type,
                algorithm=f.algorithm,
                location=f.location,
                vendor=f.vendor,
                criticality=f.criticality,
            )
            for f in result.findings
        ],
    )
    cbom.summary = {
        "total_assets": len(cbom.assets),
        "by_algorithm": result.by_algorithm,
        "by_type": result.by_type,
    }
    return {"cbom": cbom, "synthetic": False}


def step2_register(cbom: CBOM) -> str:
    print(f"\n{BANNER}\nSTEP 2: Register CBOM on-chain\n{BANNER}")
    client = QTrustClient()
    asset_id, ipfs_cid = client.register_cbom(cbom, pin_to_ipfs=False)
    print(f"Asset ID:   {asset_id}")
    print(f"CBOM hash:  {client.hash_cbom(cbom)}")
    print(f"Metadata:   ipfs://{ipfs_cid}" if ipfs_cid else "Metadata:   (no IPFS configured — hash-only)")
    return asset_id


def step3_quantum() -> None:
    print(f"\n{BANNER}\nSTEP 3: Quantum threat analysis (Shor's algorithm)\n{BANNER}")
    roadmap = [(2024, 1121), (2025, 4158), (2026, 10000), (2027, 20000),
               (2028, 50000), (2029, 100000), (2030, 200000), (2031, 500000),
               (2032, 1000000), (2033, 2000000)]

    def physical_qubits(n_bits: int) -> int:
        return (2 * n_bits + 3) * 1000

    print(f"{'Key size':<10} {'Logical qubits':<16} {'Physical qubits':<18} {'Breakable by':<12}")
    for n in (1024, 2048, 3072, 4096):
        required = physical_qubits(n)
        year = next((y for y, q in roadmap if q >= required), "after 2033")
        print(f"RSA-{n:<6} {2 * n + 3:<16,} {required:<18,} {year}")
    print("\nFull Shor simulation: notebooks/01_quantum_threat_demo.ipynb")


def step4_plan(cbom: CBOM) -> dict:
    print(f"\n{BANNER}\nSTEP 4: GNN migration planner\n{BANNER}")
    from qtrust_planner.predict import predict_detailed
    cbom_path = REPO / "data" / "cbom_for_planner.json"
    cbom_path.write_text(cbom.model_dump_json(indent=2))
    plan = predict_detailed(str(cbom_path), model_path=str(REPO / "planner" / "model.pt"))
    print(f"Assets ranked: {plan['total_assets']} | model accuracy: {plan['model_accuracy']:.3f}")
    for entry in plan["migration_order"][:5]:
        print(f"  #{entry['rank']:<3} {entry['algorithm']:<12} crit={entry['criticality']:<9} "
              f"priority={entry['priority_score']:+.3f}  {entry['host']}")
    return plan


def step5_onchain(asset_id: str, plan: dict, cbom: CBOM) -> None:
    print(f"\n{BANNER}\nSTEP 5: Attestation, migration & audit on-chain\n{BANNER}")
    client = QTrustClient()

    # Vendor attestation: DigiCert-TLS 5.2.1 now supports the target PQC algorithm
    try:
        client.register_vendor(client.account.address, "DigiCert", "ipfs://QmDigiCert")
    except RuntimeError as e:
        if "reverted" not in str(e):
            raise
    try:
        attestation_id = client.attest_product(
            product_id="DigiCert-TLS", version="5.2.1",
            algorithm="ML-DSA-441", supported=True,
            evidence_uri="ipfs://QmMockEvidence",
        )
    except RuntimeError as e:
        if "reverted" not in str(e):
            raise
        existing = client.get_attestations_by_product("DigiCert-TLS", "5.2.1", "ML-DSA-441")
        if not existing:
            raise
        attestation_id = existing[0]
    print(f"Attestation: {attestation_id} (vendor {client.account.address[:10]}…)")

    # Migration record: highest-risk classical asset -> PQC
    top = plan["migration_order"][0]
    migration_id = "0x" + hashlib.sha256(
        f"migration-{asset_id}-{int(time.time())}".encode()).hexdigest()
    evidence_hash = "0x" + hashlib.sha256(b"mock-hsm-log-evidence").hexdigest()
    client.record_migration(
        migration_id=migration_id,
        asset_id=asset_id,
        from_algorithm=top["algorithm"],
        to_algorithm="ML-DSA-441",
        evidence_hash=evidence_hash,
        evidence_uri="ipfs://QmMockEvidence",
    )
    print(f"Migration:  {migration_id} ({top['algorithm']} -> ML-DSA-441)")

    # Independent on-chain verification of the migration
    client.verify_migration(migration_id)
    migration = client.get_migration(migration_id)
    print(f"Migration verified on-chain: {migration.verified}")

    # Auditor posts a passing audit for the org
    # (deployer pre-granted AUDITOR_ROLE via Deploy.s.sol timelock deployment)
    auditor = QTrustClient()
    role = auditor.audit_registry.functions.AUDITOR_ROLE().call()
    has_role = auditor.audit_registry.functions.hasRole(role, auditor.account.address).call()
    if not has_role:
        try:
            auditor.audit_registry.functions.grantRole(role, auditor.account.address).transact({
                "from": auditor.account.address, "gas": 150_000,
            })
        except Exception as e:
            if "reverted" not in str(e).lower():
                raise
            has_role = auditor.audit_registry.functions.hasRole(role, auditor.account.address).call()
            if not has_role:
                raise
    report_hash = "0x" + hashlib.sha256(b"mock-audit-report").hexdigest()
    audit_id = client.post_audit(
        org_did=client.account.address, result=1,
        assets_reviewed=len(cbom.assets), assets_migrated=1,
        report_hash=report_hash, report_uri="ipfs://QmMockAuditReport",
    )
    exists, result_code, ts = client.get_latest_audit(client.account.address)
    print(f"Audit:      id={audit_id[:18]}… exists={exists} result={result_code} at {ts}")


def step6_verify(asset_id: str) -> None:
    print(f"\n{BANNER}\nSTEP 6: Verify all on-chain records\n{BANNER}")
    client = QTrustClient()
    asset = client.get_asset(asset_id)
    print(f"Asset:   {asset.asset_id}")
    print(f"  Org:       {asset.org_did}")
    print(f"  CBOM hash: {asset.cbom_hash}")
    print(f"  Active:    {asset.active}")
    exists, active, org = client.verify_asset(asset_id)
    print(f"  verifyAsset -> exists={exists} active={active} org={org}")
    print(f"  Org assets: {client.get_assets_by_org(client.account.address)}")
    support = client.check_product_support("DigiCert-TLS", "5.2.1", "ML-DSA-441")
    print(f"  checkProductSupport(ML-DSA-441) -> supported={support[0]} vendor={support[1]}")
    migrations = client.get_migrations_by_org(client.account.address)
    print(f"  Org migrations: {len(migrations)}")


def main() -> None:
    print(BANNER)
    print("Q-Trust Pilot Demo — First National Bank PQC Migration")
    print(BANNER)
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"RPC:  {os.environ['QTRUST_BASE_SEPOLIA_RPC']}")

    scan = step1_scan()
    asset_id = step2_register(scan["cbom"])
    step3_quantum()
    plan = step4_plan(scan["cbom"])
    step5_onchain(asset_id, plan, scan["cbom"])
    step6_verify(asset_id)

    print(f"\n{BANNER}\nPILOT COMPLETE\n{BANNER}")
    print(f"Demo URLs:")
    print(f"  Backend:  http://localhost:3001/v1/assets/{asset_id}")
    print(f"  Frontend: http://localhost:3000/v/{asset_id}")


if __name__ == "__main__":
    main()