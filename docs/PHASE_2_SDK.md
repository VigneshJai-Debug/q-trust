# Phase 2: Python SDK

## Objectives
- Create `sdk/` package
- Implement QTrustClient
- Implement Pydantic models
- Implement IPFS integration

## Status
- [x] Package structure created — sdk/pyproject.toml, sdk/qtrust/, sdk/tests/, sdk/scripts/
- [x] Client implemented — sdk/qtrust/client.py (full rewrite of stub): register/verify CBOM, vendor attest + revoke, migration record/verify, audit post/latest, product support check, hashing helpers
- [x] Schema implemented — sdk/qtrust/schema.py (CBOM, CBOMEntry, AssetRecord, ProductAttestation, MigrationRecord)
- [x] IPFS integration implemented — sdk/qtrust/ipfs.py (PinataClient, optional; hash-only mode when unconfigured)
- [x] Contract ABIs implemented — sdk/qtrust/contracts.py regenerated from forge artifacts via sdk/scripts/generate_abis.py

## Verification
- `pip install -e "sdk[dev]"` OK
- Unit tests: `pytest sdk/tests/test_client.py` — 5/5 pass
- E2E on anvil: `sdk/tests/e2e_anvil.py` — ALL E2E CHECKS PASSED (CBOM register/verify, vendor attest+revoke, migration+verify, audit post with role grant)
- `sdk/tests/run_e2e.sh` — full cycle: restart anvil → deploy → E2E

## Fixes applied
- Gas limits raised to 500k (attestProduct alone uses ~403k)
- check_product_support bytes32 → hex conversion
- ABI JSON true/false → Python True/False during generation