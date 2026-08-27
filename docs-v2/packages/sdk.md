---
title: qtrust-sdk
outline: [2, 3]
---

# qtrust-sdk

Python SDK for the Q-Trust protocol: register CBOMs on Base L2, pin evidence
to IPFS, evaluate deterministic trust assessments, and issue/verify W3C
Verifiable Credentials.

- **PyPI:** <https://pypi.org/project/qtrust-sdk/> (v1.1.0)
- **Source:** [`sdk/`](https://github.com/humoge7502/q-trust/tree/main/sdk)
  — all examples below are mirrored from `sdk/README.md` and the package's
  docstrings.

## Install

```bash
pip install qtrust-sdk
# or, from the monorepo:
pip install -e "./sdk[dev]"
```

## Register a CBOM on-chain

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

`register_cbom` pins the CBOM JSON to IPFS and registers its SHA-256 hash on
`AssetRegistry`, returning `(asset_id, cid)`. Related read/verify helpers:
`client.verify_asset(asset_id)` → `(exists, active, org_did)`,
`client.get_asset(asset_id)`, `client.retire_asset(asset_id)`.

## IPFS pinning (multi-provider)

```python
from qtrust.ipfs import create_ipfs_client

ipfs = create_ipfs_client()          # built from environment variables
cid = ipfs.pin_json('{"cbom": true}', name="qtrust-cbom")
```

The first configured provider is primary; additional providers pin
best-effort concurrently. On primary failure the first successful fallback
CID is returned (with a warning); if all fail, the error is raised.

## Deterministic trust assessment

```python
from qtrust import TrustEvaluator

evaluator = TrustEvaluator()
assessment = evaluator.evaluate(
    subject_did="did:ethr:0x...",
    policy_id="pqc-readiness",
    policy_version="1.0",
    evidence=[
        {
            "evidence_id": "ev-001",
            "evidence_type": "cbom",
            "claims": {"no_rsa_1024": True, "tls_min_key_bits": 2048},
        }
    ],
)
print(assessment.passed, assessment.confidence, assessment.assessment_hash)
```

Same evidence + same policy + same version = same result — the assessment
hash deliberately excludes timestamps.

## Verifiable Credentials & DIDs

The SDK implements W3C VCs and `did:web` / `did:key` resolution in-house
(ADR-0005): `VCIssuer` (Ed25519-signed issuance), `VCPresenter`,
`VCVerifier` (`verify_credential` / `verify_credential_sync`),
`DIDResolver` (`resolve` / `resolve_sync`, with an SSRF allowlist), and
`DIDDocument`:

```python
from qtrust import VCIssuer, DIDResolver

resolver = DIDResolver()
issuer = VCIssuer(issuer_did="did:web:issuer.example", resolver=resolver)
vc = issuer.issue(
    subject_did="did:web:creditunion.example",
    credential_type=["PQCReadinessCredential"],
    claims={"pqc_readiness_level": "Level 2"},
)
```

## Gasless relay nonce rules

Nonces are **per-signer, per-registry**. Fetch immediately before signing
(`client.sign_cbom_registration(...)` / `sign_attestation(...)` with
`nonce=None` does this for you); on a replay failure, refetch the nonce and
re-sign — never reuse the old signature. The backend exposes
`GET /v1/relay/cbom-nonce/:did` and `GET /v1/relay/nonce/:did` for the same
purpose.

## Key environment variables

| Variable | Purpose |
| --- | --- |
| `QTRUST_BASE_SEPOLIA_RPC` | RPC endpoint (default `http://127.0.0.1:8545`) |
| `QTRUST_CHAIN_ID` | Expected chain ID (default `84532`) |
| `QTRUST_DEPLOYER_PRIVATE_KEY` | Signer key (omit for read-only mode) |
| `QTRUST_ASSET_REGISTRY_ADDRESS` | Deployed AssetRegistry |
| `QTRUST_IPFS_PROVIDERS` | Comma-separated providers: `pinata`, `kubo`, `web3` |

The full table (vendor/migration/audit/governance addresses, Pinata/Kubo/
web3.storage credentials) lives in `sdk/README.md`.

## Testing

```bash
cd sdk && python -m pytest tests -q
```

Tests run offline; network-dependent tests mock HTTP or skip without a local
anvil node (`tests/e2e_anvil.py` covers the live path).
