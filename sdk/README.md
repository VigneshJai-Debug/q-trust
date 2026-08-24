# qtrust-sdk

Q-Trust SDK — verifiable post-quantum cryptography migration provenance on
Base L2. Register Cryptographic Bills of Materials (CBOM) on-chain, pin
evidence to IPFS, issue/verify W3C Verifiable Credentials, score quantum risk,
and evaluate compliance frameworks.

## Install

```bash
cd sdk && pip install -e ".[dev]"
```

## Quickstart

```python
from qtrust import QTrustClient, CBOM, CBOMEntry

client = QTrustClient(
    private_key="0x...",
    rpc_url="https://sepolia.base.org",
    asset_registry_address="0x...",
)

cbom = CBOM(
    org_did="did:ethr:0x...",
    generated_at=1700000000,
    scanner_version="1.1.0",
    assets=[CBOMEntry(asset_type="tls_cert", algorithm="RSA-2048", location="example.com:443")],
)
asset_id, cid = client.register_cbom(cbom)
```

## IPFS pinning

Pinning is provider-pluggable. The first configured provider is primary; its
CID is returned by `pin_json()` / `pin_file()`. Additional providers pin
best-effort concurrently (ThreadPoolExecutor); CID mismatches are logged as
warnings. If the primary fails, the first successful fallback CID is returned
with a warning; if every provider fails, the error is raised.

```python
from qtrust.ipfs import create_ipfs_client

ipfs = create_ipfs_client()          # built from environment variables
cid = ipfs.pin_json('{"cbom": true}', name="qtrust-cbom")
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `QTRUST_BASE_SEPOLIA_RPC` | RPC endpoint (default `http://127.0.0.1:8545`) |
| `QTRUST_CHAIN_ID` | Expected chain ID (default `84532`) |
| `QTRUST_DEPLOYER_PRIVATE_KEY` | Signer key (omit for read-only mode) |
| `QTRUST_ASSET_REGISTRY_ADDRESS` | Deployed AssetRegistry |
| `QTRUST_VENDOR_REGISTRY_ADDRESS` | Deployed VendorRegistry |
| `QTRUST_MIGRATION_REGISTRY_ADDRESS` | Deployed MigrationRegistry |
| `QTRUST_AUDIT_REGISTRY_ADDRESS` | Deployed AuditRegistry |
| `QTRUST_GOVERNANCE_ADDRESS` | Deployed QTrustGovernance |
| `QTRUST_PINATA_API_KEY` / `QTRUST_PINATA_API_SECRET` | Pinata credentials (provider `pinata`) |
| `QTRUST_IPFS_PROVIDERS` | Comma-separated provider list; default `pinata`. Order = priority (first is primary). Supported: `pinata`, `kubo`, `web3` |
| `QTRUST_IPFS_KUBO_API` | Kubo RPC endpoint (default `http://127.0.0.1:5001`) |
| `QTRUST_IPFS_KUBO_USER` / `QTRUST_IPFS_KUBO_PASS` | Optional basic auth for Kubo |
| `QTRUST_WEB3_STORAGE_TOKEN` | Bearer token for web3.storage (provider `web3`) |

## Relay nonce management

Gasless registrations (CBOM, vendor attestations, migrations) are authorized
with EIP-712 signatures consumed by a relayer. Nonces are **per-signer,
per-registry**: each registry (`AssetRegistry`, `VendorRegistry`,
`MigrationRegistry`) maintains its own `nonces[signer]` mapping that increments
on-chain every time a signed submission is accepted.

Operational rules:

1. **Fetch immediately before signing.** Always retrieve the signer's current
   nonce right before signing via the relay service's read endpoints
   (`GET /v1/relay/cbom-nonce/:did` for CBOM registration,
   `GET /v1/relay/nonce/:did` for vendor attestations). The SDK equivalents are
   `QTrustClient.sign_cbom_registration(...)` /
   `sign_attestation(...)` with `nonce=None`, which fetch on-chain state for you.
2. **Concurrent submissions from the same signer race.** Two signed payloads
   sharing one nonce cannot both land: whichever transaction confirms second
   reverts with the registry's `InvalidNonce(signer, provided, expected)` (or
   `InvalidSignature()` if the relayer pre-checks). This is expected replay
   protection, not a bug.
3. **Retry pattern = refetch + resign.** On a nonce/replay failure, do NOT reuse
   the old signature: refetch the current nonce, re-sign the payload with it,
   and resubmit.

## Testing

```bash
cd sdk && python -m pytest tests -q
```

Tests run offline; network-dependent tests mock HTTP or skip when no local
anvil node is available (`tests/e2e_anvil.py` covers the live path).
