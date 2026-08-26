> **⚠ SUPERSEDED (2026-08-26).** Phase snapshot — parts are stale (service list, wallet stack). Current architecture: docs/ARCHITECTURE.md and backend/openapi.yaml.

# Phase 7: Frontend Dashboard

## Status: DONE

## Deliverables
- Next.js 16 app in `frontend/` (App Router, TypeScript, Tailwind CSS 4)
- `frontend/src/app/v/[id]/page.tsx` — public verification page: status badge (VALID/REVOKED), asset details, static-SVG provenance graph (Code → Scanner → CBOM → Asset → Migration), IPFS metadata, independent-verify CLI instructions
- `frontend/src/app/dashboard/page.tsx` — org dashboard: migration progress cards, latest audit badge, registered asset list, on-chain verify buttons
- `frontend/src/app/vendors/page.tsx` — vendor portal: attestation list with revoked/supported badges + evidence links, live product-support lookup form
- `frontend/src/app/v/page.tsx` — verify entry page
- `frontend/src/lib/api.ts` — backend client (typed, matches actual API responses)
- `frontend/src/components/` — DynamicProvider (local mock wallet; Dynamic SDK unavailable in registry) + QueryProvider (TanStack Query)
- Tailwind, postcss, tsconfig, next.config (rewrites `/api/*`), icons

## Verification
- `npm run build` (next build) — clean
- `npm run start` — all routes serve 200:
  - `/` (home), `/dashboard`, `/vendors`, `/v`, `/v/[asset-id]` (renders live on-chain attestation as VALID)

## Notes
- Deploy to Vercel: set `NEXT_PUBLIC_QTRUST_API_URL` to the backend URL (default `http://localhost:3001`)
- Wallet auth uses a local mock provider (no credential-dependency); swap in Dynamic Labs or viem injected wallet via the same `WalletContext`
- React Flow is listed as a dependency; the verification page deliberately uses a static SVG graph to keep the server-rendered page dependency-light