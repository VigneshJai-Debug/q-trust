# Phase 8: Bank Pilot

## Status: DONE

## Deliverables
- `pilot/run_pilot.py` — end-to-end pilot script
- `notebooks/08_bank_pilot.ipynb` — notebook driving the same flow step-by-step

## Scenario
First National Bank (fictional) must comply with OMB M-23-02. The CISO coordinates migration of TLS certificates and SSH keys from classical to post-quantum cryptography.

## Flow (all steps verified against local anvil)
1. **Scan** `example.com` (TLS :443 + SSH :22) → CBOM (falls back to a synthetic bank CBOM when no findings)
2. **Register CBOM on-chain** — hash-only (no IPFS pinning required)
3. **Quantum threat analysis** — Shor resource table (RSA-1024→4096 with qubits needed + breakable year)
4. **GNN migration planner** — `predict_detailed()` ranks CBOM assets (model acc 0.24)
5. **On-chain actions**:
   - Vendor attestation: DigiCert-TLS 5.2.1 supports ML-DSA-441
   - Migration record: highest-risk algorithm → ML-DSA-441, then `verifyMigration`
   - Auditor posts passing audit (AUDITOR_ROLE granted by admin first)
6. **Verification** — `verifyAsset` (exists/active), `checkProductSupport` → supported=True, org asset + migration lists

## Verification
- `python3 pilot/run_pilot.py` — PILOT COMPLETE (full run, no errors)
- `jupyter nbconvert --execute notebooks/08_bank_pilot.ipynb` — 0 errors, PILOT COMPLETE

## Demo URLs (printed at end of run)
- Backend: `http://localhost:3001/v1/assets/<asset-id>`
- Frontend: `http://localhost:3000/v/<asset-id>`

## Fixes surfaced by the pilot
- `ScanResult.to_cbom()` takes no `org_did` — build the CBOM directly from findings
- `post_audit` requires `assets_reviewed`, `assets_migrated`, `report_hash`
- `verify_migration` returns the tx hash — read `get_migration().verified` for the boolean
- `AUDITOR_ROLE` must be granted before `postAudit`