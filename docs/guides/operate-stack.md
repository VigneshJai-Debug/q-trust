# Guide — Operate the stack

Running Q-Trust in compose with observability.

## Compose topology

```
api (3001) + webhook + postgres (5432) + redis (6379) + planner (8000) + prometheus (9090) + grafana (3002)
```

All stores bind to `127.0.0.1` only; healthchecks gate startup (`docker-compose.yml:14-38`).

## Start

```bash
cp .env.example .env  # set REDIS_PASSWORD, POSTGRES_PASSWORD, GRAFANA_PASSWORD, RPC, keys
docker compose up -d --build
docker compose logs -f api
```

## Verify

```bash
./scripts/verify_all.sh
# Checks: forge test (211) · sdk E2E (anvil) · inspector · planner benchmark · backend build · frontend build · notebooks · pilot
```

## Observability

- `http://127.0.0.1:3001/metrics` — Prometheus (HTTP histogram, indexer_lag_blocks, rpc_pool health)
- `http://127.0.0.1:9090` — Prometheus UI; alerts in `ops/prometheus/alerts.yml`
- `http://127.0.0.1:3002` — Grafana (provisioned datasource)
- Sentry: set `QTRUST_SENTRY_DSN` — `beforeSend` scrubs x-api-key/authorization/cookie + 64-hex key shapes

## Runbooks

- [Backup & Restore](../runbook/backup-restore.md) — quarterly drill, RPO/RTO targets
- [Incident Response](../runbook/incident-response.md) — SEV matrix, pause + relayer-key-compromise playbooks, recorder replay
- [Go-Live Checklist](../deployment/GO_LIVE_CHECKLIST.md)

## Rate limits

Global `120/min/IP` (`QTRUST_RATE_LIMIT_MAX`, `0` disables — for edge-proxy fronted prod). Per-route `30/min` on writes, `5/min` on `/v1/evidence/create`.

*Last verified: 2026-08-27 · against commit f02d106 · verifier: ./scripts/verify_all.sh*
