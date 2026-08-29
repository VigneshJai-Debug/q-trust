"""End-to-end verification of the Q-Trust SDK against a local anvil chain.

Usage:
    python sdk/tests/e2e_anvil.py

Requires anvil running at http://127.0.0.1:8545 with chain ID 84532 and the
contracts deployed (see contracts/broadcast/Deploy.s.sol/84532/run-latest.json).
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


from qtrust import QTrustClient
from qtrust.schema import CBOM, CBOMEntry

DEPLOYER = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
VENDOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
AUDITOR_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# Deployed addresses from the anvil broadcast run. Override via env vars.
ADDRESSES = {
    "asset": os.environ.get(
        "QTRUST_ASSET_REGISTRY_ADDRESS", "0x5fbdb2315678afecb367f032d93f642f64180aa3"
    ),
    "vendor": os.environ.get(
        "QTRUST_VENDOR_REGISTRY_ADDRESS", "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"
    ),
    "migration": os.environ.get(
        "QTRUST_MIGRATION_REGISTRY_ADDRESS", "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
    ),
    "audit": os.environ.get(
        "QTRUST_AUDIT_REGISTRY_ADDRESS", "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"
    ),
}

RPC = os.environ.get("QTRUST_BASE_SEPOLIA_RPC", "http://127.0.0.1:8545")


def main() -> None:
    client = QTrustClient(
        private_key=DEPLOYER,
        rpc_url=RPC,
        asset_registry_address=ADDRESSES["asset"],
        vendor_registry_address=ADDRESSES["vendor"],
        migration_registry_address=ADDRESSES["migration"],
        audit_registry_address=ADDRESSES["audit"],
        chain_id=84532,
    )
    org = client.account.address

    print("=== 1. Register CBOM ===")
    cbom = CBOM(
        org_did=org,
        generated_at=int(datetime.now(timezone.utc).timestamp()),
        scanner_version="0.1.0",
        assets=[
            CBOMEntry(
                asset_type="tls_cert", algorithm="RSA-2048", location="example.com:443",
                criticality="high",
            ),
            CBOMEntry(asset_type="ssh_key", algorithm="Ed25519", location="host:22"),
            CBOMEntry(
                asset_type="code_signing", algorithm="ECC-P256", location="signer",
                criticality="critical",
            ),
        ],
    )
    asset_id, cid = client.register_cbom(cbom, pin_to_ipfs=False)
    assert asset_id.startswith("0x") and len(asset_id) == 66, asset_id
    print(f"  asset_id={asset_id} cid={cid!r}")

    record = client.get_asset(asset_id)
    assert record.org_did.lower() == org.lower(), record
    assert record.active is True
    print(
        f"  get_asset: org={record.org_did[:8]}... cbom_hash={record.cbom_hash[:18]}..."
        f" active={record.active}"
    )

    exists, active, v_org = client.verify_asset(asset_id)
    assert exists and active and v_org.lower() == org.lower()
    print(f"  verify_asset: exists={exists} active={active} org={v_org[:8]}...")
    assert client.asset_count() >= 1
    assert asset_id in client.get_assets_by_org(org)
    print(f"  asset_count={client.asset_count()} get_assets_by_org OK")

    print("=== 2. Vendor registration + attestation ===")
    try:
        client.register_vendor(client.account.address, "DigiCert", "ipfs://QmDigiCert")
    except RuntimeError as e:
        # VendorAlreadyRegistered — fine on a warm chain.
        assert "reverted" in str(e)
    attestation_id = client.attest_product(
        "DigiCert-TLS", "5.2.1", "ML-DSA-441", True, "ipfs://QmEvidence"
    )
    assert attestation_id.startswith("0x") and len(attestation_id) == 66
    print(f"  attestation_id={attestation_id}")

    att = client.get_attestation(attestation_id)
    assert att.supported and att.algorithm == "ML-DSA-441" and not att.revoked
    print(
        f"  get_attestation: product={att.product_id} {att.version} alg={att.algorithm}"
        f" supported={att.supported}"
    )

    supported, vendor, att_id = client.check_product_support(
        "DigiCert-TLS", "5.2.1", "ML-DSA-441"
    )
    assert supported and vendor.lower() == org.lower() and att_id == attestation_id
    print(f"  check_product_support: supported={supported}")

    ids = client.get_attestations_by_product("DigiCert-TLS", "5.2.1", "ML-DSA-441")
    assert attestation_id in ids
    print(f"  get_attestations_by_product: {len(ids)} found")

    # Revocation must come from the vendor or admin.
    client.revoke_attestation(attestation_id)
    att = client.get_attestation(attestation_id)
    assert att.revoked
    print(f"  revoke_attestation: revoked={att.revoked}")

    supported, _, _ = client.check_product_support("DigiCert-TLS", "5.2.1", "ML-DSA-441")
    assert not supported
    print(f"  after revoke check_product_support: supported={supported}")

    print("=== 3. Migration recording ===")
    mig_id = client.hash_string(f"migration-{asset_id}")
    client.record_migration(
        mig_id, asset_id, "RSA-2048", "ML-DSA-441", client.hash_string("evidence-log-1")
    )
    mig = client.get_migration(mig_id)
    assert (
        mig.from_algorithm == "RSA-2048"
        and mig.to_algorithm == "ML-DSA-441"
        and not mig.verified
    )
    print(
        f"  migration recorded: {mig.from_algorithm} -> {mig.to_algorithm}"
        f" verified={mig.verified}"
    )

    client.verify_migration(mig_id)
    mig = client.get_migration(mig_id)
    assert mig.verified
    print(f"  verify_migration: verified={mig.verified}")
    assert mig_id in client.get_migrations_by_asset(asset_id)
    assert mig_id in client.get_migrations_by_org(org)
    print("  get_migrations_by_asset / by_org OK")

    print("=== 4. Audit attestation (bound to on-chain state) ===")
    auditor = QTrustClient(
        private_key=AUDITOR_KEY,
        rpc_url=RPC,
        asset_registry_address=ADDRESSES["asset"],
        vendor_registry_address=ADDRESSES["vendor"],
        migration_registry_address=ADDRESSES["migration"],
        audit_registry_address=ADDRESSES["audit"],
        chain_id=84532,
    )
    # Grant AUDITOR_ROLE to the auditor (no-op if already granted via Deploy
    # timelock or QTRUST_DEV_GRANTEE). run_e2e.sh deploys with the auditor
    # address in QTRUST_DEV_GRANTEE, so this branch is normally skipped.
    role = auditor.audit_registry.functions.AUDITOR_ROLE().call()
    has_role = auditor.audit_registry.functions.hasRole(role, auditor.account.address).call()
    if not has_role:
        auditor_tx = auditor.audit_registry.functions.grantRole(role, auditor.account.address)
        try:
            client._send_transaction(auditor_tx, gas_limit=150_000)
        except RuntimeError:
            # Admin was handed to timelock — a dev-granted account holds
            # AUDITOR_ROLE (QTRUST_DEV_GRANTEE), so fall back to the deployer
            # as auditor when it was granted the role.
            has_role = client.audit_registry.functions.hasRole(role, client.account.address).call()
            if has_role:
                auditor = client
                print("  fell back to deployer as auditor (has AUDITOR_ROLE)")
            else:
                raise RuntimeError("no address has AUDITOR_ROLE — cannot run audit tests")

    # One migration exists on-chain, so an audit may claim at most 1 migrated.
    audit_id = auditor.post_audit(org, 1, 3, 1, client.hash_string("audit-report-2026"))
    audit = auditor.get_audit(audit_id)
    assert audit["result"] == 1 and audit["assets_reviewed"] == 3
    print(f"  audit_id={audit_id} result={audit['result']} reviewed={audit['assets_reviewed']}")

    exists, result, ts = auditor.get_latest_audit(org)
    assert exists and result == 1
    print(f"  get_latest_audit: exists={exists} result={result}")

    print("=== 5. Integrity guards (Phase 0) ===")
    # 5a. Migration for a non-existent asset must revert.
    try:
        client.record_migration(
            client.hash_string("m-ghost"), client.hash_string("ghost-asset"),
            "RSA-2048", "ML-DSA-441", client.hash_string("evidence-ghost"),
        )
        raise AssertionError("record_migration on a ghost asset must revert")
    except RuntimeError as e:
        assert "reverted" in str(e)
        print("  record_migration(ghost asset) reverted as expected")

    # 5b. Same-algorithm migration must revert.
    try:
        client.record_migration(
            client.hash_string("m-same"), asset_id,
            "RSA-2048", "RSA-2048", client.hash_string("evidence-same"),
        )
        raise AssertionError("same-algorithm migration must revert")
    except RuntimeError as e:
        assert "reverted" in str(e)
        print("  record_migration(same algorithm) reverted as expected")

    # 5c. Retire the asset: verify inactive; further migrations revert.
    client.retire_asset(asset_id)
    _, active, _ = client.verify_asset(asset_id)
    assert not active
    print("  retire_asset: asset now inactive")
    try:
        client.record_migration(
            client.hash_string("m-retired"), asset_id,
            "ECC-P256", "ML-KEM-512", client.hash_string("evidence-retired"),
        )
        raise AssertionError("record_migration on retired asset must revert")
    except RuntimeError as e:
        assert "reverted" in str(e)
        print("  record_migration(retired asset) reverted as expected")

    # 5d. Deactivate the vendor: attestations must revert.
    # With timelock governance, direct deactivation is now governance-gated (2-day delay).
    # On local anvil with timelock deployment, the deployer no longer holds DEFAULT_ADMIN_ROLE,
    # so deactivate will revert — we handle both paths.
    try:
        client.deactivate_vendor(org)
        assert not client.is_vendor_active(org)
        print("  deactivate_vendor: vendor inactive")
        try:
            client.attest_product("DigiCert-TLS", "5.2.1", "ML-KEM-512", True, "ipfs://QmE")
            raise AssertionError("inactive vendor attestation must revert")
        except RuntimeError as e:
            assert "reverted" in str(e)
            print("  attest_product(inactive vendor) reverted as expected")
    except RuntimeError as e:
        if "reverted" in str(e):
            # Timelock path: deployer cannot directly deactivate; vendor remains active.
            # Verify that governance correctly blocks direct deactivation.
            assert client.is_vendor_active(org), (
                "vendor should remain active under timelock governance"
            )
            print(
                "  deactivate_vendor: blocked by timelock governance"
                " (vendor remains active — expected)"
            )
            print(
                "  (governance deactivation requires 2-day timelock;"
                " direct attest still succeeds)"
            )
        else:
            raise

    print("=== 6. Read-only client (no private key) ===")
    ro = QTrustClient(
        rpc_url=RPC,
        asset_registry_address=ADDRESSES["asset"],
        vendor_registry_address=ADDRESSES["vendor"],
        migration_registry_address=ADDRESSES["migration"],
        audit_registry_address=ADDRESSES["audit"],
        chain_id=84532,
    )
    assert ro.account is None
    exists, active, _ = ro.verify_asset(asset_id)
    assert exists and not active
    assert ro.get_asset(asset_id).asset_id == asset_id
    try:
        ro.attest_product("P", "1", "ML-KEM-512", True, "")
        raise AssertionError("read-only write must raise ValueError")
    except ValueError as e:
        assert "private key" in str(e)
    print("  read-only verify + write guard OK")

    print("=== 7. EIP-712 gasless attestation ===")
    # The deployer re-registers as a vendor (deactivation in step 5 was reverted
    # for this client by re-registering is impossible — so use a fresh vendor).
    vendor2 = QTrustClient(
        private_key=VENDOR_KEY,
        rpc_url=RPC,
        asset_registry_address=ADDRESSES["asset"],
        vendor_registry_address=ADDRESSES["vendor"],
        migration_registry_address=ADDRESSES["migration"],
        audit_registry_address=ADDRESSES["audit"],
        chain_id=84532,
    )
    v2_addr = vendor2.account.address
    try:
        client.register_vendor(v2_addr, "SignerCorp", "ipfs://QmSC")
    except RuntimeError:
        pass  # already registered on a warm chain

    nonce = vendor2.get_nonce(v2_addr)
    typed_data, signature = vendor2.sign_attestation(
        "SignerCorp-HSM", "3.0", "ML-KEM-1024", True, "ipfs://QmE712", nonce
    )
    recovered = vendor2.recover_attestation_signer(typed_data, signature)
    assert recovered.lower() == v2_addr.lower(), recovered
    print(f"  signature recovered to {recovered[:10]}... nonce={nonce}")

    # A different account (the deployer, acting as relayer) submits the signed
    # attestation — the vendor only signed off-chain. Gasless flow.
    client.attest_product_signed(
        "SignerCorp-HSM", "3.0", "ML-KEM-1024", True, "ipfs://QmE712", nonce, signature
    )
    supported, vendor, _ = ro.check_product_support("SignerCorp-HSM", "3.0", "ML-KEM-1024")
    assert supported and vendor.lower() == v2_addr.lower()
    assert vendor2.get_nonce(v2_addr) == nonce + 1
    print("  gasless attestation recorded with the SIGNER as vendor; nonce advanced")

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
