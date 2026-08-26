# Guide — Integrate the SDK in CI

Use the Python SDK to hash, pin, and register CBOMs without touching wallets in CI.

## Install

```bash
pip install -e ./sdk[dev]
```

## Hash and register

```python
import json
from qtrust import QTrustClient
from qtrust.schema import CBOM

client = QTrustClient()  # reads QTRUST_BASE_SEPOLIA_RPC, registry addrs
cbom = CBOM.model_validate(json.load(open("cbom.json")))
cbom_hash = QTrustClient.hash_cbom(cbom)          # deterministic SHA-256 over canonical JSON
asset_id = client.register_cbom_hash(cbom_hash, metadata_uri="ipfs://Qm...")
print(asset_id)

# Gasless (no gas needed — relayer submits):
# 1) GET /v1/relay/cbom-nonce/<yourAddr> -> nonce
# 2) client.sign_cbom_registration(cbom_hash, metadata_uri, nonce) -> EIP-712 sig
# 3) POST /v1/relay/cbom {cbomHash, metadataURI, nonce, signature}

exists, active, org_did = client.verify_asset(asset_id)
assert exists and active
```

## Verify in CI (GH Actions snippet)

```yaml
- run: pip install qtrust-sdk && crypto-inspector scan . --cyclonedx cbom.json --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
- run: python scripts/register_cbom.py  # uses QTrustClient.hash_cbom + relay
```

See `sdk/qtrust/client.py`, `docs/api.md`, `backend/openapi.yaml`.

*Last verified: 2026-08-27 · against commit f02d106 · verifier: ./scripts/verify_all.sh*
