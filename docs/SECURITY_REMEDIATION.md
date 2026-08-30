# Security Remediation — QTRUST-010/011/012 (P0 Days 15-30)

## Contracts (11 UUPS) — Production Trust Gap (QTRUST-010)

**Current (honest README Reality Check):**
- No independent audit
- No Base Sepolia deployment (local anvil)
- Deployer EOA governance
- Backend-held relayer key

**Fix:**
```
Safe 2/3 → Timelock (7-day) → QTrustGovernance
Relayer → KMS/HSM (AWS KMS, GCP HSM) with spend limits, rate limits, rotation, emergency revoke
Storage-layout CI, upgrade simulation, fork tests, timelocked upgrade announcements, emergency pause without upgrade authority
```

Grouping (QTRUST-011):
```
CORE: Asset, Evidence, Migration
TRUST: Vendor, TrustAnchor, Revocation, Governance
COMPLIANCE: Audit, Compliance, Policy, Schema
```
Keep separate contracts but centralize upgrade policy.

**Next:** External audit (Trail of Bits / OpenZeppelin), Base Sepolia deploy, multisig + KMS relayer, then re-run `halmos` + `slither`.

## Indexer Reorg Handling (QTRUST-012)

**Current:** `chain → indexer → Postgres read model` — if reorg, Postgres ≠ canonical.

**Fix:** Store for every indexed event:

```ts
block_number, block_hash, parent_hash, log_index, transaction_hash
```

Logic:

```ts
newBlock: if parent_hash != last.block_hash → detect reorg → rollback affected blocks → replay canonical chain
```

Add chaos tests: RPC timeout, stale block, duplicate/missing/out-of-order events, chain restart, DB/Redis failure → eventual consistency, no duplicate/phantom evidence.

## Performance (QTRUST-013/014)

Current `147.8 req/s p95 11.27ms` is **local dev-grade tsx + local Postgres/Redis/anvil, rate-limit disabled** — not production. Add matrix: prod Docker, TLS, real RPC, network latency, 3 API replicas, real Redis/Postgres, chain delays, 100/500/1k/5k/10k VUs, p50/p95/p99, CPU/RAM/DB/Redis/RPC.

Horizontally scalable: `LB → API-1/2/3 → Redis → Postgres`, planner autoscaled independently.
