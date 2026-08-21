# Phases 4–8: Quantum Analysis, GNN Planner, Backend, Frontend, Pilot

## Phase 4: Quantum Threat Analysis — DONE
- `notebooks/01_quantum_threat_demo.ipynb` (copied from `shor_demo.ipynb`, 12 cells) executes with 0 errors
- Verified outputs: Shor's algorithm resource table (RSA-2048 → 4,096,000 physical qubits), IBM roadmap, risk assessment

## Phase 5: GNN Migration Planner — DONE
- `planner/qtrust_planner/`: model.py (GCN + residuals), train.py, predict.py, data_generator.py
- Fixes: CrossEntropyLoss formulation (RuntimeError) → MSE regression on y_priority; residual connections added; model path fixed
- Trained `planner/planner/model.pt`: 40 epochs, 1000 graphs, lr 5e-3 → val exact-rank acc 24%, Kendall tau 0.924, top-5 overlap 90%
- `predict_detailed()` verified on real CBOM JSON (/tmp/bank_cbom.json): Critical RSA assets ranked first

## Phase 6: Backend API — DONE
- `backend/`: Fastify + viem + BullMQ/ioredis (webhook), TypeScript ESM (`"type":"module"`, NodeNext)
- `scripts/generate_abis.py` → `backend/src/lib/abis.ts` regenerated from forge artifacts (4 ABIs)
- `backend/src/config.ts` (publicClient, CONTRACTS, CHAIN, parseAssetId, toBytes32)
- Services rewritten (were broken): `services/attestation.ts`, `services/webhook.ts`, `services/verify.ts`
- `server.ts` routes reconciled with the frontend client: `/v1/assets/:id`, `/v1/assets/:id/verify`, `/v1/orgs/:did/assets`, `/v1/orgs/:did/migrations`, `/v1/vendors/:did/attestations`, `/v1/migrations/:id`, `/v1/products/:id/support`, `/v1/webhooks/subscribe` + legacy aliases + `/health`
- `npm run build` (tsc): clean. Live-verified against anvil:
  - `/v1/assets/:id` → 200; missing asset → 404
  - `/v1/assets/:id/verify` → exists/active/chain
  - `/v1/orgs/:addr/migrations` → progress {1/1 verified} + latest_audit {Passed}
  - `/v1/vendors/:addr/attestations` → count 1
  - `/v1/products/:id/support` → supported flag
- `backend/src/main.py` is the Python CLI entry (register/verify via SDK)

## Phase 7: Frontend — DONE
- Restructured flat root files into `frontend/` (package.json, next.config.mjs, tsconfig.json, postcss, tailwind.config.ts, src/)
- Pages: `/` (home), `/dashboard` (org migration progress + audit + assets), `/vendors` (attestations + product support check), `/v` (verify entry), `/v/[id]` (public attestation page: status badge, provenance graph, IPFS metadata, independent-verify instructions)
- `frontend/src/lib/api.ts` moved from backend (types reconciled: verified/verified_migrations), `@/components/` providers (DynamicProvider mock wallet + QueryProvider)
- Removed @dynamic-labs/sdk-react (not in registry — provider is mock-mode local wallet)
- `next build`: clean, 5 routes. `next start` verified: all pages 200; `/v/<asset-id>` renders VALID with live on-chain data

## Phase 8: Pilot & Demo — DONE
- `pilot/run_pilot.py` — end-to-end bank PQC migration demo, ALL PASS:
  1. Scan example.com (1 TLS finding, ecdsa-with-SHA256) → CBOM
  2. Register CBOM on-chain (asset id, cbom hash)
  3. Quantum threat table (Shor resource estimates by key size)
  4. GNN planner ranks the CBOM assets (model acc 0.24)
  5. On-chain: vendor attestation (ML-DSA-441 supported), migration record (ecdsa → ML-DSA-441, verified=True), audit post (result=Passed)
  6. Verification: verifyAsset exists/active, checkProductSupport → supported=True, org assets + migrations listed
- Fixes surfaced by the pilot: ScanResult.to_cbom() takes no org_did (build CBOM directly); post_audit requires assets_reviewed/assets_migrated/report_hash; verify_migration returns tx hash (read `get_migration().verified`); AUDITOR_ROLE must be granted before postAudit

## Final state
- Local anvil chain: 4 contracts deployed, SDK E2E + pilot + backend + frontend all verified against it
- Real Base Sepolia deployment + Dynamic Labs wallet SDK remain env-credential-dependent (not performed — no secrets available)