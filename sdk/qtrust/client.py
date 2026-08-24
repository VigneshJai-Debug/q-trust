# sdk/qtrust/client.py
"""Q-Trust SDK client — talks to the Q-Trust smart contracts on Base.

Relay nonce management (condensed; full guide in sdk/README.md):

- EIP-712 nonces are per-signer and per-registry; each registry increments
  its `nonces[signer]` mapping on-chain for every accepted signed submission.
- Fetch the signer's current nonce immediately before signing
  (`GET /v1/relay/cbom-nonce/:did` / `/v1/relay/nonce/:did`, or pass
  nonce=None to the sign_* helpers to fetch on-chain state).
- Concurrent submissions from the same signer race on one nonce: the second
  transaction reverts with InvalidNonce/InvalidSignature. On such a failure,
  refetch the nonce, re-sign, and resubmit — never reuse a stale signature.
"""
from __future__ import annotations

import hashlib
import json
import os

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from .contracts import (
    ASSET_REGISTRY_ABI,
    AUDIT_REGISTRY_ABI,
    MIGRATION_REGISTRY_ABI,
    VENDOR_REGISTRY_ABI,
)
from .ipfs import PinataClient
from .schema import CBOM, AssetRecord, MigrationRecord, ProductAttestation

BASE_SEPOLIA_CHAIN_ID = 84532

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000"


class QTrustClient:
    """High-level client for posting and verifying Q-Trust attestations."""

    def __init__(
        self,
        private_key: str | None = None,
        rpc_url: str | None = None,
        asset_registry_address: str | None = None,
        vendor_registry_address: str | None = None,
        migration_registry_address: str | None = None,
        audit_registry_address: str | None = None,
        governance_address: str | None = None,
        ipfs_api_key: str | None = None,
        ipfs_api_secret: str | None = None,
        chain_id: int | None = None,
    ):
        self.private_key = private_key or os.environ.get("QTRUST_DEPLOYER_PRIVATE_KEY")
        self.rpc_url = rpc_url or os.environ.get("QTRUST_BASE_SEPOLIA_RPC", "http://127.0.0.1:8545")
        self.asset_registry_address = asset_registry_address or os.environ.get(
            "QTRUST_ASSET_REGISTRY_ADDRESS", ""
        )
        self.vendor_registry_address = vendor_registry_address or os.environ.get(
            "QTRUST_VENDOR_REGISTRY_ADDRESS", ""
        )
        self.migration_registry_address = migration_registry_address or os.environ.get(
            "QTRUST_MIGRATION_REGISTRY_ADDRESS", ""
        )
        self.audit_registry_address = audit_registry_address or os.environ.get(
            "QTRUST_AUDIT_REGISTRY_ADDRESS", ""
        )
        self.governance_address = governance_address or os.environ.get(
            "QTRUST_GOVERNANCE_ADDRESS", ""
        )
        self.chain_id = chain_id or int(os.environ.get("QTRUST_CHAIN_ID", BASE_SEPOLIA_CHAIN_ID))

        # Read-only mode: no private key means verification/lookup calls only.
        self.account = Account.from_key(self.private_key) if self.private_key else None

        # Web3 setup
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {self.rpc_url}")

        chain_id = self.w3.eth.chain_id
        if chain_id != self.chain_id:
            raise ValueError(f"Expected chain ID {self.chain_id}, got {chain_id}")

        def _contract(address: str, abi) -> any:
            if not address:
                return None
            return self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)

        self.asset_registry = _contract(self.asset_registry_address, ASSET_REGISTRY_ABI)
        self.vendor_registry = _contract(self.vendor_registry_address, VENDOR_REGISTRY_ABI)
        self.migration_registry = _contract(self.migration_registry_address, MIGRATION_REGISTRY_ABI)
        self.audit_registry = _contract(self.audit_registry_address, AUDIT_REGISTRY_ABI)

        # IPFS client (optional — only used when pin_to_ipfs=True)
        self.ipfs = None
        api_key = ipfs_api_key or os.environ.get("QTRUST_PINATA_API_KEY")
        api_secret = ipfs_api_secret or os.environ.get("QTRUST_PINATA_API_SECRET")
        if api_key and api_secret:
            self.ipfs = PinataClient(api_key=api_key, api_secret=api_secret)

    # ------------------------------------------------------------------
    # Hashing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return "0x" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return "0x" + h.hexdigest()

    @staticmethod
    def hash_string(s: str) -> str:
        return "0x" + hashlib.sha256(s.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_cbom(cbom: CBOM) -> str:
        """Hash a CBOM object deterministically (canonical JSON)."""
        canonical = json.dumps(cbom.model_dump(), sort_keys=True, separators=(",", ":"))
        return "0x" + hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Transaction helpers
    # ------------------------------------------------------------------
    def _require_account(self):
        """Raise a clear error when a write method is used in read-only mode."""
        if self.account is None:
            raise ValueError(
                "This operation requires a private key. Pass private_key= or set "
                "QTRUST_DEPLOYER_PRIVATE_KEY (read-only clients can only verify)."
            )
        return self.account

    def _send_transaction(self, tx_builder, gas_limit: int = 250_000) -> dict:
        account = self._require_account()
        nonce = self.w3.eth.get_transaction_count(account.address)
        tx = tx_builder.build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": self.chain_id,
        })
        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
        return dict(receipt)

    @staticmethod
    def _event_args(receipt: dict, contract, event_name: str) -> dict | None:
        events = getattr(contract.events, event_name)().process_receipt(receipt)
        if not events:
            return None
        return dict(events[0]["args"])

    # ------------------------------------------------------------------
    # AssetRegistry
    # ------------------------------------------------------------------
    def register_cbom(self, cbom: CBOM, pin_to_ipfs: bool = True) -> tuple:
        """Register a CBOM on-chain. Returns (asset_id, ipfs_cid_or_empty)."""
        cbom_hash = self.hash_cbom(cbom)
        metadata_uri = ""
        if pin_to_ipfs and self.ipfs:
            cid = self.ipfs.pin_json(cbom.model_dump_json(indent=2), name="qtrust-cbom")
            metadata_uri = f"ipfs://{cid}"

        receipt = self._send_transaction(
            self.asset_registry.functions.registerCBOM(
                bytes.fromhex(cbom_hash[2:]),
                metadata_uri,
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.asset_registry, "CBOMRegistered")
        if args is None:
            raise RuntimeError("CBOMRegistered event not found in receipt")
        return "0x" + args["assetId"].hex(), metadata_uri.replace("ipfs://", "")

    def register_cbom_hash(self, cbom_hash: str, metadata_uri: str = "") -> str:
        """Register a pre-computed CBOM hash on-chain. Returns the asset ID."""
        receipt = self._send_transaction(
            self.asset_registry.functions.registerCBOM(
                bytes.fromhex(cbom_hash[2:]),
                metadata_uri,
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.asset_registry, "CBOMRegistered")
        if args is None:
            raise RuntimeError("CBOMRegistered event not found in receipt")
        return "0x" + args["assetId"].hex()

    # ------------------------------------------------------------------
    # EIP-712 gasless CBOM registration
    # ------------------------------------------------------------------
    def _eip712_asset_domain(self) -> dict:
        return {
            "name": "QTrustAssetRegistry",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": Web3.to_checksum_address(self.asset_registry_address),
        }

    def sign_cbom_registration(
        self, cbom_hash: str, metadata_uri: str = "", nonce: int | None = None,
    ) -> tuple[dict, str]:
        """Sign a CBOM registration as EIP-712 typed data.

        Returns (typed_data, signature). The signature authorizes any relayer
        to submit the registration on the org's behalf (gasless).
        """
        self._require_account()
        if nonce is None:
            nonce = self.asset_registry.functions.nonces(
                self.account.address
            ).call()
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "CBOMRegistration": [
                    {"name": "cbomHash", "type": "bytes32"},
                    {"name": "metadataURI", "type": "string"},
                    {"name": "nonce", "type": "uint256"},
                ],
            },
            "primaryType": "CBOMRegistration",
            "domain": self._eip712_asset_domain(),
            "message": {
                "cbomHash": bytes.fromhex(cbom_hash[2:]),
                "metadataURI": metadata_uri,
                "nonce": nonce,
            },
        }
        signed = self.account.sign_typed_data(full_message=typed_data)
        return typed_data, signed.signature.hex()

    def register_cbom_signed(
        self, cbom_hash: str, metadata_uri: str, nonce: int, signature: str,
    ) -> str:
        """Submit a signed CBOM registration (gas paid by the caller).

        The on-chain registration records the SIGNER as the org — the
        submitting account only pays gas.
        """
        receipt = self._send_transaction(
            self.asset_registry.functions.registerCBOMSigned(
                bytes.fromhex(cbom_hash[2:]),
                metadata_uri,
                nonce,
                bytes.fromhex(signature[2:] if signature.startswith("0x") else signature),
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.asset_registry, "CBOMRegistered")
        if args is None:
            raise RuntimeError("CBOMRegistered event not found in receipt")
        return "0x" + args["assetId"].hex()

    def retire_asset(self, asset_id: str) -> str:
        """Retire a CBOM registration (owner or admin). Returns the tx hash."""
        return self._send_transaction(
            self.asset_registry.functions.retireAsset(
                bytes.fromhex(asset_id[2:])
            ),
            gas_limit=150_000,
        )["transactionHash"].hex()

    def get_asset(self, asset_id: str) -> AssetRecord:
        raw = self.asset_registry.functions.getAsset(bytes.fromhex(asset_id[2:])).call()
        return AssetRecord(
            asset_id=asset_id,
            org_did=raw[0],
            cbom_hash="0x" + raw[1].hex(),
            metadata_uri=raw[2],
            registered_at=raw[3],
            last_updated=raw[4],
            active=raw[5],
        )

    def verify_asset(self, asset_id: str) -> tuple:
        """Verify an asset exists and is active. Returns (exists, active, org_did)."""
        return self.asset_registry.functions.verifyAsset(bytes.fromhex(asset_id[2:])).call()

    def get_assets_by_org(self, org_did: str) -> list:
        ids = self.asset_registry.functions.getAssetsByOrg(
            Web3.to_checksum_address(org_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    def asset_count(self) -> int:
        return self.asset_registry.functions.assetCount().call()

    # ------------------------------------------------------------------
    # VendorRegistry
    # ------------------------------------------------------------------
    def register_vendor(self, vendor_address: str, name: str, metadata_uri: str = "") -> str:
        return self._send_transaction(
            self.vendor_registry.functions.registerVendor(
                Web3.to_checksum_address(vendor_address), name, metadata_uri,
            ),
            gas_limit=200_000,
        )["transactionHash"].hex()

    def deactivate_vendor(self, vendor_address: str) -> str:
        """Deactivate a vendor (admin only). Returns the tx hash."""
        return self._send_transaction(
            self.vendor_registry.functions.deactivateVendor(
                Web3.to_checksum_address(vendor_address)
            ),
            gas_limit=150_000,
        )["transactionHash"].hex()

    def is_vendor_active(self, vendor_address: str) -> bool:
        """Check whether a vendor is currently active."""
        return self.vendor_registry.functions.isVendorActive(
            Web3.to_checksum_address(vendor_address)
        ).call()

    # ------------------------------------------------------------------
    # EIP-712 gasless attestations
    # ------------------------------------------------------------------
    def get_nonce(self, vendor_address: str) -> int:
        """Current EIP-712 nonce for a vendor."""
        return self.vendor_registry.functions.nonces(
            Web3.to_checksum_address(vendor_address)
        ).call()

    def _eip712_domain(self) -> dict:
        return {
            "name": "QTrustVendorRegistry",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": Web3.to_checksum_address(self.vendor_registry_address),
        }

    def sign_attestation(
        self,
        product_id: str,
        version: str,
        algorithm: str,
        supported: bool,
        evidence_uri: str = "",
        nonce: int | None = None,
    ) -> tuple[dict, str]:
        """Sign a product attestation as EIP-712 typed data.

        Returns (typed_data, signature). The signature authorizes any relayer
        to submit the attestation on the vendor's behalf (gasless).
        """
        self._require_account()
        if nonce is None:
            nonce = self.get_nonce(self.account.address)
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "ProductAttestation": [
                    {"name": "productId", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "algorithm", "type": "string"},
                    {"name": "supported", "type": "bool"},
                    {"name": "evidenceURI", "type": "string"},
                    {"name": "nonce", "type": "uint256"},
                ],
            },
            "primaryType": "ProductAttestation",
            "domain": self._eip712_domain(),
            "message": {
                "productId": product_id,
                "version": version,
                "algorithm": algorithm,
                "supported": supported,
                "evidenceURI": evidence_uri,
                "nonce": nonce,
            },
        }
        signed = self.account.sign_typed_data(full_message=typed_data)
        return typed_data, signed.signature.hex()

    @staticmethod
    def recover_attestation_signer(typed_data: dict, signature: str) -> str:
        """Recover the signer of an EIP-712 attestation (off-chain verification)."""
        from eth_account.messages import encode_typed_data

        encoded = encode_typed_data(full_message=typed_data)
        return Account.recover_message(encoded, signature=signature)

    def attest_product_signed(
        self,
        product_id: str,
        version: str,
        algorithm: str,
        supported: bool,
        evidence_uri: str,
        nonce: int,
        signature: str,
    ) -> str:
        """Submit a vendor-signed attestation (gas paid by the caller).

        The on-chain attestation records the SIGNER as the vendor — the
        submitting account only pays gas.
        """
        return self._send_transaction(
            self.vendor_registry.functions.attestProductSigned(
                product_id, version, algorithm, supported, evidence_uri,
                nonce, bytes.fromhex(signature[2:] if signature.startswith("0x") else signature),
            ),
            gas_limit=500_000,
        )["transactionHash"].hex()

    def attest_product(self, product_id: str, version: str, algorithm: str,
                       supported: bool, evidence_uri: str = "") -> str:
        """Post a product PQC attestation. Returns the attestation ID."""
        receipt = self._send_transaction(
            self.vendor_registry.functions.attestProduct(
                product_id, version, algorithm, supported, evidence_uri,
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.vendor_registry, "ProductAttested")
        if args is None:
            raise RuntimeError("ProductAttested event not found in receipt")
        return "0x" + args["attestationId"].hex()

    def revoke_attestation(self, attestation_id: str) -> str:
        return self._send_transaction(
            self.vendor_registry.functions.revokeAttestation(
                bytes.fromhex(attestation_id[2:])
            ),
            gas_limit=150_000,
        )["transactionHash"].hex()

    def get_attestation(self, attestation_id: str) -> ProductAttestation:
        raw = self.vendor_registry.functions.getAttestation(
            bytes.fromhex(attestation_id[2:])
        ).call()
        return ProductAttestation(
            attestation_id=attestation_id,
            vendor_did=raw[0],
            product_id=raw[1],
            version=raw[2],
            algorithm=raw[3],
            supported=raw[4],
            evidence_uri=raw[5],
            timestamp=raw[6],
            revoked=raw[7],
        )

    def get_attestations_by_vendor(self, vendor_did: str) -> list:
        ids = self.vendor_registry.functions.getAttestationsByVendor(
            Web3.to_checksum_address(vendor_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    def get_attestations_by_product(self, product_id: str, version: str, algorithm: str) -> list:
        ids = self.vendor_registry.functions.getAttestationsByProduct(
            product_id, version, algorithm
        ).call()
        return ["0x" + i.hex() for i in ids]

    def check_product_support(self, product_id: str, version: str, algorithm: str) -> tuple:
        """Check if any vendor attests support. Returns (supported, vendor_did, attestation_id)."""
        supported, vendor_did, attestation_id = self.vendor_registry.functions.checkProductSupport(
            product_id, version, algorithm
        ).call()
        if isinstance(attestation_id, bytes):
            attestation_id = "0x" + attestation_id.hex()
        return supported, vendor_did, attestation_id

    # ------------------------------------------------------------------
    # MigrationRegistry
    # ------------------------------------------------------------------
    def record_migration(self, migration_id: str, asset_id: str,
                         from_algorithm: str, to_algorithm: str,
                         evidence_hash: str, evidence_uri: str = "") -> str:
        return self._send_transaction(
            self.migration_registry.functions.recordMigration(
                bytes.fromhex(migration_id[2:]),
                bytes.fromhex(asset_id[2:]),
                from_algorithm, to_algorithm,
                bytes.fromhex(evidence_hash[2:]),
                evidence_uri,
            ),
            gas_limit=500_000,
        )["transactionHash"].hex()

    # ------------------------------------------------------------------
    # EIP-712 gasless migration recording
    # ------------------------------------------------------------------
    def _eip712_migration_domain(self) -> dict:
        return {
            "name": "QTrustMigrationRegistry",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": Web3.to_checksum_address(self.migration_registry_address),
        }

    def sign_migration(
        self,
        migration_id: str,
        asset_id: str,
        from_algorithm: str,
        to_algorithm: str,
        evidence_hash: str,
        evidence_uri: str = "",
        nonce: int | None = None,
    ) -> tuple[dict, str]:
        """Sign a migration recording as EIP-712 typed data.

        Returns (typed_data, signature). The signature authorizes any relayer
        to submit the migration on the org's behalf (gasless).
        """
        self._require_account()
        if nonce is None:
            nonce = self.migration_registry.functions.nonces(
                self.account.address
            ).call()
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "MigrationRecording": [
                    {"name": "migrationId", "type": "bytes32"},
                    {"name": "assetId", "type": "bytes32"},
                    {"name": "fromAlgorithm", "type": "string"},
                    {"name": "toAlgorithm", "type": "string"},
                    {"name": "evidenceHash", "type": "bytes32"},
                    {"name": "evidenceURI", "type": "string"},
                    {"name": "nonce", "type": "uint256"},
                ],
            },
            "primaryType": "MigrationRecording",
            "domain": self._eip712_migration_domain(),
            "message": {
                "migrationId": bytes.fromhex(migration_id[2:]),
                "assetId": bytes.fromhex(asset_id[2:]),
                "fromAlgorithm": from_algorithm,
                "toAlgorithm": to_algorithm,
                "evidenceHash": bytes.fromhex(evidence_hash[2:]),
                "evidenceURI": evidence_uri,
                "nonce": nonce,
            },
        }
        signed = self.account.sign_typed_data(full_message=typed_data)
        return typed_data, signed.signature.hex()

    def record_migration_signed(
        self,
        migration_id: str,
        asset_id: str,
        from_algorithm: str,
        to_algorithm: str,
        evidence_hash: str,
        evidence_uri: str,
        nonce: int,
        signature: str,
    ) -> str:
        """Submit a signed migration recording (gas paid by the caller).

        The on-chain migration records the SIGNER as the org — the
        submitting account only pays gas.
        """
        receipt = self._send_transaction(
            self.migration_registry.functions.recordMigrationSigned(
                bytes.fromhex(migration_id[2:]),
                bytes.fromhex(asset_id[2:]),
                from_algorithm, to_algorithm,
                bytes.fromhex(evidence_hash[2:]),
                evidence_uri,
                nonce,
                bytes.fromhex(signature[2:] if signature.startswith("0x") else signature),
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.migration_registry, "MigrationRecorded")
        if args is None:
            raise RuntimeError("MigrationRecorded event not found in receipt")
        return "0x" + args["migrationId"].hex()

    def verify_migration(self, migration_id: str) -> str:
        return self._send_transaction(
            self.migration_registry.functions.verifyMigration(
                bytes.fromhex(migration_id[2:])
            ),
            gas_limit=150_000,
        )["transactionHash"].hex()

    def get_migration(self, migration_id: str) -> MigrationRecord:
        raw = self.migration_registry.functions.getMigration(
            bytes.fromhex(migration_id[2:])
        ).call()
        return MigrationRecord(
            migration_id=migration_id,
            asset_id="0x" + raw[0].hex(),
            org_did=raw[1],
            from_algorithm=raw[2],
            to_algorithm=raw[3],
            evidence_hash="0x" + raw[4].hex(),
            evidence_uri=raw[5],
            timestamp=raw[6],
            verified=raw[7],
        )

    def get_migrations_by_asset(self, asset_id: str) -> list:
        ids = self.migration_registry.functions.getMigrationsByAsset(
            bytes.fromhex(asset_id[2:])
        ).call()
        return ["0x" + i.hex() for i in ids]

    def get_migrations_by_org(self, org_did: str) -> list:
        ids = self.migration_registry.functions.getMigrationsByOrg(
            Web3.to_checksum_address(org_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    # ------------------------------------------------------------------
    # AuditRegistry
    # ------------------------------------------------------------------
    def post_audit(self, org_did: str, result: int,
                   assets_reviewed: int, assets_migrated: int,
                   report_hash: str, report_uri: str = "") -> str:
        """Post an audit attestation. Returns the audit ID."""
        receipt = self._send_transaction(
            self.audit_registry.functions.postAudit(
                Web3.to_checksum_address(org_did),
                result, assets_reviewed, assets_migrated,
                bytes.fromhex(report_hash[2:]),
                report_uri,
            ),
            gas_limit=500_000,
        )
        args = self._event_args(receipt, self.audit_registry, "AuditPosted")
        if args is None:
            raise RuntimeError("AuditPosted event not found in receipt")
        return "0x" + args["auditId"].hex()

    def get_audit(self, audit_id: str) -> dict:
        raw = self.audit_registry.functions.getAudit(
            bytes.fromhex(audit_id[2:])
        ).call()
        return {
            "audit_id": audit_id,
            "org_did": raw[0],
            "auditor_did": raw[1],
            "result": raw[2],
            "assets_reviewed": raw[3],
            "assets_migrated": raw[4],
            "report_hash": "0x" + raw[5].hex(),
            "report_uri": raw[6],
            "timestamp": raw[7],
        }

    def get_audits_by_org(self, org_did: str) -> list:
        ids = self.audit_registry.functions.getAuditsByOrg(
            Web3.to_checksum_address(org_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    def get_audits_by_auditor(self, auditor_did: str) -> list:
        ids = self.audit_registry.functions.getAuditsByAuditor(
            Web3.to_checksum_address(auditor_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    def get_latest_audit(self, org_did: str) -> tuple:
        """Returns (exists, result, timestamp) for the org's latest audit."""
        return self.audit_registry.functions.getLatestAudit(
            Web3.to_checksum_address(org_did)
        ).call()
