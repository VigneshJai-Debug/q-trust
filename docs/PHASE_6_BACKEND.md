> **⚠ SUPERSEDED (2026-08-26).** Phase snapshot — parts are stale (service list, wallet stack). Current architecture: docs/ARCHITECTURE.md and backend/openapi.yaml.

# Phase 6: Backend Services

## Status: DONE

## Deliverables
- `backend/src/server.ts` — Fastify REST API (TS ESM, `"type":"module"`, NodeNext)
- `backend/src/services/attestation.ts` — relayer service (signs & sends attestations)
- `backend/src/services/verify.ts` — verification API (viem reads against all 4 registries)
- `backend/src/services/webhook.ts` — webhook delivery (BullMQ Worker + Redis, runs standalone)
- `backend/src/config.ts` — publicClient, CONTRACTS, CHAIN, parseAssetId, toBytes32
- `backend/src/lib/abis.ts` — regenerated from forge artifacts (`scripts/generate_abis.py`)
- `backend/src/main.py` — Python CLI entry (register/verify via SDK)
- `docker-compose.yml` + `Dockerfile` — api + webhook + redis services
- `backend/.env.example`, `backend/package.json`, `backend/tsconfig.json`

## Routes (matched to the frontend client)
- `GET /health`
- `GET /v1/assets/:id` (404 if missing)
- `GET /v1/assets/:id/verify`
- `GET /v1/orgs/:did/assets`
- `GET /v1/orgs/:did/migrations` (progress + migrations + latest audit)
- `GET /v1/vendors/:did/attestations`
- `GET /v1/migrations/:id`
- `GET /v1/products/:id/support`
- `POST /v1/webhooks/subscribe`
- Legacy aliases: `/assets/:id`, `/attestation/:id`, `/migration/progress/:org`

## Verification
- `npm run build` (tsc) — clean, no errors
- Live-verified against anvil: health, asset fetch/404, verify, org migrations (1/1 verified + audit Passed), vendor attestations (count 1), product support check — all 200
- Webhook worker compiles and starts (Redis optional at runtime)

## Fixes applied
- `attestation.ts`/`webhook.ts` were syntactically broken (`#` comments, bogus `viem/transimporters` import) — rewritten
- `verify.ts` used non-existent `getMigrationProgress`/tuple casts — rewritten against the real contract ABIs
- `server.ts` routes now match the frontend client's `/v1/...` paths