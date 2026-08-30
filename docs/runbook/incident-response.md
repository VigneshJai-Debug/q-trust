# Incident Response Runbook

Applies to the Q-Trust production deployment (Base mainnet or Base Sepolia).
Read this document **before** an incident; during one, jump to the severity
matrix and follow the linked playbook.

## Severity matrix

| Severity | Definition | Examples | Response target |
|---|---|---|---|
| **SEV1** | Contract exploit, fund/data integrity loss, active attack on-chain | Exploit draining a registry, malicious upgrade, broken signature verification, reorg deep enough to rewrite settled state | Page immediately, respond 24/7, public disclosure decision within 24h |
| **SEV2** | Core service down, writes blocked | Relayer down (`/health` reports no relayer), all RPC endpoints unhealthy, Postgres lost, API process crash-looping | Respond within 1h business hours / 4h otherwise |
| **SEV3** | Degraded but functional | Elevated 5xx ratio, p99 latency > 1s, indexer lag > 50 blocks, relay rate-limit surges | Next business day |

Escalation: see [Escalation contacts](#escalation-contacts).

---

## SEV1 — Suspected contract exploit

### 1. Pause the affected registry

All registries are `Pausable` and `pause()`/`unpause()` require
`DEFAULT_ADMIN_ROLE`. After `Deploy.s.sol` completes, that role lives on the
`TimelockController`, so pausing is a two-step governance action
(schedule → wait delay → execute). `QTrustGovernance.schedulePause(registryIndex, salt)`
targets: `0` AssetRegistry, `1` VendorRegistry, `2` MigrationRegistry,
`3` AuditRegistry.

```bash
# 1) Schedule pause of AssetRegistry through governance (7-day default delay)
cast send $QTRUST_GOVERNANCE_ADDRESS \
  "schedulePause(uint256,bytes32)(bytes32)" \
  0 $(cast keccak "pause-$(date +%s)") \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY --rpc-url $QTRUST_BASE_SEPOLIA_RPC

# 2) After TimelockController.getMinDelay() has elapsed, execute it
cast send $QTRUST_GOVERNANCE_ADDRESS \
  "execute(address,bytes,bytes32)" \
  $QTRUST_ASSET_REGISTRY_ADDRESS \
  $(cast calldata "pause()") \
  $(cast keccak "pause-<same-salt>") \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY --rpc-url $QTRUST_BASE_SEPOLIA_RPC

# 3) Confirm state
cast call $QTRUST_ASSET_REGISTRY_ADDRESS "paused()(bool)" --rpc-url $QTRUST_BASE_SEPOLIA_RPC
```

> **Emergency caveat:** the timelock delay means SEV1 response cannot be
> instant once admin control has been handed over — this tradeoff is
> deliberate (see `docs/adr/0003-uups-timelock-governance.md`). If admin was
> **not yet** renounced (fresh deploy), the deployer can pause directly:
>
> ```bash
> cast send $QTRUST_ASSET_REGISTRY_ADDRESS "pause()" \
>   --private-key $QTRUST_DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL
> ```

For upgrades or role changes use `QTrustGovernance.schedule(target, data, salt)`
with hand-built calldata; `grantRole`/`revokeRole`/`renounceRole` calls
targeting `DEFAULT_ADMIN_ROLE` are rejected by governance by design.

### 2. Freeze the perimeter

* Set `NODE_ENV=production` API keys are already enforced — rotate
  `QTRUST_API_KEYS` in `.env` and `docker compose up -d api webhook` if write
  abuse is suspected.
* Stop relaying entirely by stopping the containers:
  `docker compose stop api webhook` — users' signed payloads simply fail;
  nothing on-chain is affected because every write requires a user signature.

### 3. Assess and preserve evidence

* Export recent events for the affected contract:

  ```bash
  cast logs --from-block <START> --to-block latest \
    --address $QTRUST_ASSET_REGISTRY_ADDRESS --rpc-url $RPC_URL > incident-logs.json
  ```
* Snapshot the database before touching anything:
  `docker exec qtrust-postgres pg_dump -U qtrust qtrust > incident-$(date +%F).sql`
* Preserve the deployed bytecode + compiler metadata for later diffing
  (`cast code <proxy>`), plus the `broadcast/` directory of the last deploy.
* Do **not** propose an upgrade until the root cause is understood — a hasty
  UUPS upgrade can destroy evidence stored in storage slots.

### 4. Coordinate disclosure

Follow [`SECURITY.md`](../../SECURITY.md). Any public announcement must be
approved by the escalation contacts below.

---

## SEV2 — Relayer down / key compromise

### Relayer unavailable

1. Check `/health` — it returns the configured relayer address; if the service
   throws `QTRUST_RELAYER_PRIVATE_KEY is required...`, the env var was lost.
2. Verify the relayer has gas: `cast balance $RELAYER --rpc-url $RPC_URL`
   (fund with ≥ 0.02 ETH on Base Sepolia; see `docs/deployment/BASE_SEPOLIA.md`).
3. Restart: `docker compose up -d api webhook`.
4. While down, gasless endpoints return 4xx/5xx; direct API-key writes also
   fail (they share the relayer). Reads stay up.

### Relayer key compromise

**Important:** relayer signatures never authorize state changes. Every
gasless flow (`postAuditSigned`, `attestProductSigned`, `registerCBOMSigned`,
`recordMigrationSigned`) verifies an **EIP-712 signature made by the user**
(vendor/org/auditor) against the contract's domain separator, checks the
user's per-address nonce, and records *the signer* as the actor. The relayer
only pays gas and submits calldata — **it cannot forge submissions**, even
when its key is stolen. Worst case exposure is: attacker spends the relayer's
gas submitting arbitrary *valid, previously user-signed* payloads, or spams
the mempool with reverting calls (users lose nothing but the relayer burns
gas).

1. Generate a fresh key offline; do not reuse the compromised one anywhere.
2. Rotate: update `QTRUST_RELAYER_PRIVATE_KEY` in `.env` (and your secrets
   manager), then `docker compose up -d api webhook`.
3. Sweep remaining funds from the compromised address:
   ```bash
   cast send $COMPROMISED_RELAYER --private-key <COMPROMISED_KEY> \
     --value $(cast from-unit $(cast balance $COMPROMISED_RELAYER --rpc-url $RPC_URL) wei ether) \
     $NEW_RELAYER --rpc-url $RPC_URL
   ```
4. Assess forged-submission exposure anyway (defense in depth): pull
   `AuditPosted`/`ProductAttested`/`CBOMRegistered` logs since the suspected
   compromise window and confirm each event's signer matches an expected
   vendor/org/auditor. Because signatures are user-signed, any unexpected
   entry implies a *user* key problem, not a relayer problem — escalate that
   user separately.
5. Record the rotation in the incident log; consider whether the old key ever
   had on-chain roles (it should not — roles belong to governance/deployer,
   see ADR 0003).

---

## Indexer replay procedure

Symptom: read model diverges from chain (wrong counts, missing rows after a
reorg that exceeded `QTRUST_INDEXER_REORG_DEPTH`, or corrupted data).

The indexer backfills automatically from its stored cursor at boot, so a
replay is just: rewind the cursor row, clear processed-block history, restart.

```bash
# 1) Reset the cursor for every stream to the desired replay height
docker exec -i qtrust-postgres psql -U qtrust -d qtrust <<'SQL'
UPDATE indexer_state SET block = 0, block_hash = '', updated_at = now();
DELETE FROM processed_blocks;
-- Optional hard reset of materialized rows (backfill recreates them):
-- TRUNCATE assets, attestations, migrations, audits;
SQL

# 2) Restart the API container — startIndexer() runs initSchema + backfill
docker compose restart api

# 3) Watch catch-up
docker compose logs -f api | grep "Indexer:"
```

Verification after replay:

```sql
SELECT COUNT(*) FROM assets;
SELECT COUNT(*) FROM attestations;
SELECT COUNT(*) FROM migrations;
SELECT COUNT(*) FROM audits;
SELECT * FROM indexer_state;
```

Compare row counts against on-chain event counts:

```bash
cast logs --address $QTRUST_AUDIT_REGISTRY_ADDRESS \
  "AuditPosted(bytes32,address,address,uint8,uint256,uint256,bytes32,string,uint256)" \
  --from-block 0 --to-block latest --rpc-url $RPC_URL | grep -c blockHash
```

(Repeat per contract/event; counts must match the SQL numbers above.)

---

## Escalation contacts

> Replace placeholders with real on-call rota entries before go-live.

| Role | Name | Contact | Hours |
|---|---|---|---|
| Incident commander | `incident@q-trust.io` | `incident@q-trust.io (phone/Signal)` | 24/7 |
| Contracts lead (SEV1 owner) | `incident@q-trust.io` | `incident@q-trust.io` | 24/7 |
| Backend/infra on-call | `incident@q-trust.io` | `incident@q-trust.io` | Business hours |
| Security disclosures | see SECURITY.md | security@qtrust.dev `_REPLACE_` | 24/7 |
| Comms/PR (SEV1 only) | `incident@q-trust.io` | `incident@q-trust.io` | Business hours |

Pager integration: point `QTRUST_ALERT_WEBHOOK` (Alertmanager receiver) at
your paging provider and map `severity=critical` routes to SEV1/SEV2 paging.
