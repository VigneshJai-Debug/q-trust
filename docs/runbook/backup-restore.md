# Backup & Restore Runbook

Covers the Postgres read model (`qtrust-postgres` volume) and, for context,
the chain state that remains the source of truth. Losing the database is an
availability incident, **not** a data-integrity one: every row can be
re-derived from on-chain events (see the replay procedure in
[incident-response.md](incident-response.md)).

## What to back up

| Asset | Mechanism | Frequency | Notes |
|---|---|---|---|
| Postgres read model | `pg_dump` cron | Nightly | Small; fastest restore path |
| Postgres volume | Docker volume snapshot | Weekly + pre-upgrade | Point-in-time, larger |
| `.env` / secrets | Secrets manager export | On change | Contract addresses, API keys — never the raw repo file |
| Grafana/Prometheus data | `grafana-data`, `prometheus-data` volumes | Optional | Dashboards are re-provisionable from `ops/` |

On-chain state is **not** backed up — it lives on Base and is re-readable via
RPC at any time.

## pg_dump cron example

Nightly logical dump inside the container, written to a host directory:

```bash
# /etc/cron.d/qtrust-backup
0 2 * * * root docker exec qtrust-postgres pg_dump -U qtrust -Fc qtrust > /var/backups/qtrust/qtrust-$(date +\%F).dump && find /var/backups/qtrust -name 'qtrust-*.dump' -mtime +30 -delete
```

```bash
sudo chmod 644 /etc/cron.d/qtrust-backup && sudo mkdir -p /var/backups/qtrust
```

Restore from a dump:

```bash
docker exec -i qtrust-postgres dropdb -U qtrust --force qtrust
docker exec -i qtrust-postgres createdb -U qtrust qtrust
cat /var/backups/qtrust/qtrust-2026-08-24.dump | docker exec -i qtrust-postgres pg_restore -U qtrust -d qtrust
docker compose restart api   # indexer resumes from the restored cursor
```

## Volume snapshot alternative

For point-in-time copies (e.g. before a risky migration):

```bash
docker compose stop api webhook            # quiesce writers
docker run --rm -v qtrust_postgres-data:/data -v /var/backups/qtrust:/backup \
  alpine tar czf /backup/postgres-data-$(date +%F).tgz -C /data .
docker compose start api webhook
```

Restore: stop the stack, swap the volume contents back, start.

> Prefer `pg_dump` for routine backups: it is version-portable and validates
> implicitly on restore, whereas raw volume tars must match the Postgres major
> version (16).

## RPO / RTO targets

| Metric | Target | Achieved by |
|---|---|---|
| **RPO** (max data loss) | 24 h with nightly dumps; ~0 for indexed data (replayable from chain) | Cron above; chain is source of truth |
| **RTO** (max restore time) | < 1 h for full DB loss | `pg_restore` of a nightly dump (< minutes for current data sizes) + container restart + indexer catch-up |
| Read-model staleness during rebuild | Minutes–hours depending on chain history | Backfill runs 2000-block batches until head |

## Restore drill — step by step

Run this quarterly against a scratch instance (never prod). Goal: prove a
nightly dump actually restores and matches the chain.

1. **Start a throwaway stack** with an empty DB:
   ```bash
   docker compose up -d postgres
   ```
2. **Load the dump:**
   ```bash
   cat /var/backups/qtrust/qtrust-LATEST.dump | \
     docker exec -i qtrust-postgres pg_restore -U qtrust -d qtrust --clean --if-exists
   ```
3. **Row-count verification** vs on-chain event counts:
   ```sql
   SELECT 'assets' AS t, COUNT(*) FROM assets
   UNION ALL SELECT 'attestations', COUNT(*) FROM attestations
   UNION ALL SELECT 'migrations', COUNT(*) FROM migrations
   UNION ALL SELECT 'audits', COUNT(*) FROM audits;
   ```
   ```bash
   # Per contract, count events from genesis:
   cast logs --address $QTRUST_ASSET_REGISTRY_ADDRESS \
     "CBOMRegistered(bytes32,address,bytes32,string,uint256)" \
     --from-block 0 --to-block latest --rpc-url $RPC_URL | grep -c blockHash
   ```
   Every SQL count must equal its on-chain event count.
4. **Spot-check integrity:** pick one `asset_id` from SQL and verify it live:
   ```bash
   curl -s localhost:3001/v1/assets/<ASSET_ID> | jq .
   cast call $QTRUST_ASSET_REGISTRY_ADDRESS "getAsset(bytes32)" <ASSET_ID> --rpc-url $RPC_URL
   ```
5. **Cursor sanity:** `SELECT key, block FROM indexer_state;` — each cursor
   must be ≤ current chain head and ≥ the deployment block.
6. **Record the drill** in the checklist below; investigate any mismatch via
   the indexer replay procedure before trusting the backup rotation.

## Quarterly drill checklist

- [ ] Latest nightly dump restores into a clean container without errors
- [ ] Row counts match on-chain event counts for all four registries
- [ ] One asset round-trips through `/v1/assets/:id` and `cast call getAsset`
- [ ] Indexer cursors are sane after restart (no negative lag, no gaps)
- [ ] Backup retention prune job deleted only files older than 30 days
- [ ] Restore took < 1 h end-to-end (measured, recorded below)
- [ ] Secrets restore verified: `.env` values load and `/health` reports relayer
- [ ] Drill date + duration + operator logged here: `_DATE_ / _DURATION_ / _OPERATOR_`
