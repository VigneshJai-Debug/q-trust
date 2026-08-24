# Deployment Guide — Base Sepolia

End-to-end rollout of Q-Trust v2.0.0 to Base Sepolia (chain id `84532`):
contracts → roles → backend → frontend → EAS schemas → smoke test → release.

## Prerequisites

| Requirement | Where / how | Notes |
|---|---|---|
| Funded deployer EOA ≥ **0.05 ETH** on 84532 | faucet links below | Covers deploy gas (~0.02–0.03) + verification retries + schema registration |
| Relayer EOA funded ≥ **0.02 ETH** on 84532 | generate offline, fund from deployer | `QTRUST_RELAYER_PRIVATE_KEY` — pays gas for all user writes; never the deployer key |
| `QTRUST_DEPLOYER_PRIVATE_KEY` | your secrets manager | Read by `Deploy.s.sol` / `RegisterSchemas.s.sol` via `vm.envUint` |
| `BASESCAN_API_KEY` | basescan.org account → API keys | Required for `--verify` and the CI `contract-verify` job |
| WalletConnect project ID | cloud.walletconnect.com → *Create Project* → copy ID → set as `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` | Free tier is sufficient; required for real wallet connections in the frontend (dev fallback string `"demo"` compiles but wallets fail) |
| Pinata API key + secret | pinata.cloud → API Keys | Used by the SDK's `PinataClient` for IPFS pinning; hash-only mode works without them |
| Foundry (`forge`, `cast`) ≥ nightly | https://book.getfoundry.sh | `foundryup` |
| Node.js ≥ 20, Docker Compose v2 | — | Backend + ops stack |

Faucets: https://www.alchemy.com/faucets/base-sepolia ·
https://faucet.circle.com · https://www.coinbase.com/faucets/base-ethereum-goerli-sepolia-faucet
(any one suffices; deployer needs the larger balance).

---

## 1. Build the contracts

```bash
cd contracts
forge build
forge test -vvv          # must be fully green before deploying
```

## 2. Deploy with verification

```bash
export RPC_URL=https://sepolia.base.org
export QTRUST_DEPLOYER_PRIVATE_KEY=0x...

forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --verify \
  --chain-id 84532 \
  --verifier etherscan \
  --verifier-url https://api-sepolia.basescan.org/api \
  --etherscan-api-key $BASESCAN_API_KEY \
  --slow
```

The script deploys four core registries behind ERC1967 proxies, a 7-day
`TimelockController`, `QTrustGovernance`, and four trust-infrastructure
proxies, then transfers operational roles to the timelock and renounces the
deployer's admin rights.

## 3. Capture deployed addresses

Collect the proxy addresses from the run output or
`contracts/broadcast/Deploy.s.sol/84532/`:

```bash
jq -r '.transactions[] | select(.transactionType=="CREATE") | .contractName + "=" + .contractAddress' \
  contracts/broadcast/Deploy.s.sol/84532/run-latest.json | sort -u
```

Keep only the **proxy** lines and export them in the CI format documented in
[`contracts/verification/README.md`](../../contracts/verification/README.md)
(one `Name=0xAddress` pair per line — this exact value goes into the repo
variable used by the CI verify job):

```bash
export DEPLOYED_PROXY_ADDRESSES='AssetRegistry=0x…
VendorRegistry=0x…
MigrationRegistry=0x…
AuditRegistry=0x…
RevocationAnchor=0x…
PolicyCommitment=0x…
SchemaRegistry=0x…
TrustAnchorRegistry=0x…'
```

Add this multiline value as the GitHub repo variable `DEPLOYED_PROXY_ADDRESSES`
(*Settings → Secrets and variables → Actions → Variables*) so the
`contract-verify` job verifies every contract after merge to `main`.

## 4. Grant operational roles

After deploy, admin lives on the timelock by design (ADR 0003). The deployer
keeps only `AUDITOR_ROLE` on AuditRegistry (pre-granted for pilots). Grant any
additional runtime roles through governance/timelock — role names per contract:

* AssetRegistry — `REGISTRAR_ROLE`
* VendorRegistry — `VENDOR_ADMIN_ROLE`
* MigrationRegistry — `MIGRATOR_ROLE`, `AUDITOR_ROLE`
* AuditRegistry — `AUDITOR_ROLE`
* RevocationAnchor — `ISSUER_ADMIN_ROLE`
* PolicyCommitment — `POLICY_AUTHORITY_ROLE`
* SchemaRegistry — `SCHEMA_AUTHORITY_ROLE`
* TrustAnchorRegistry — `GOVERNANCE_ROLE`

Example — grant a third-party auditor while admin is still in flight
(pre-handover) or via a direct timelock-held admin path:

```bash
cast send $QTRUST_AUDIT_REGISTRY_ADDRESS \
  "grantRole(bytes32,address)" \
  $(cast call $QTRUST_AUDIT_REGISTRY_ADDRESS "AUDITOR_ROLE()(bytes32)") \
  0xAuditorAddress0000000000000000000000000001 \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL
```

Post-handover, route the same calldata through
`QTrustGovernance.schedule(target, data, salt)` then `execute(...)` after the
timelock delay (see the SEV1 playbook examples in
`docs/runbook/incident-response.md`).

> The **relayer needs no on-chain role**: all gasless entrypoints verify the
> user's EIP-712 signature on-chain; anyone may submit.

## 5. Configure backend env vars

Fill `.env` (template: [`.env.example`](../../.env.example)):

```text
QTRUST_USE_MAINNET=false
QTRUST_BASE_SEPOLIA_RPC=https://sepolia.base.org        # use a provider endpoint in prod
QTRUST_RELAYER_PRIVATE_KEY=0x...                        # relayer EOA (funded)
QTRUST_ASSET_REGISTRY_ADDRESS=0x...                     # proxies from step 3
QTRUST_VENDOR_REGISTRY_ADDRESS=0x...
QTRUST_MIGRATION_REGISTRY_ADDRESS=0x...
QTRUST_AUDIT_REGISTRY_ADDRESS=0x...
QTRUST_REVOCATION_ANCHOR_ADDRESS=0x...
QTRUST_POLICY_COMMITMENT_ADDRESS=0x...
QTRUST_SCHEMA_REGISTRY_ADDRESS=0x...
QTRUST_TRUST_ANCHOR_REGISTRY_ADDRESS=0x...
QTRUST_API_KEYS=<generate: openssl rand -hex 32>
QTRUST_CORS_ORIGINS=https://app.example.com             # required, no wildcards
QTRUST_PG_URL=postgres://qtrust:***@localhost:5433/qtrust
QTRUST_REDIS_URL=redis://localhost:6379
POSTGRES_PASSWORD=***
REDIS_PASSWORD=***
GRAFANA_PASSWORD=***
QTRUST_ALERT_WEBHOOK=https://hooks.example.com/qtrust-alerts
QTRUST_SENTRY_DSN=                                      # optional
```

Bring up the stack and confirm health:

```bash
docker compose up -d
curl -s localhost:3001/health   # {"status":"ok","chain_id":84532,"relayer":"0x..."}
```

## 6. Configure frontend env vars

`frontend/.env.example` → `.env.local` equivalents:

```text
NEXT_PUBLIC_QTRUST_API_URL=https://api.example.com      # or http://localhost:3001
NEXT_PUBLIC_QTRUST_CHAIN_ID=84532
NEXT_PUBLIC_QTRUST_ASSET_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_QTRUST_VENDOR_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_IPFS_GATEWAY=https://ipfs.io/ipfs/
NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=<from cloud.walletconnect.com>
QTRUST_USE_MAINNET=
```

## 7. Register EAS schemas

```bash
cd contracts
forge script script/RegisterSchemas.s.sol \
  --rpc-url $RPC_URL --broadcast --chain-id 84532 --slow
# Optional override of the canonical predeploy:
#   export EAS_SCHEMA_REGISTRY=0x4200000000000000000000000000000000000020
```

Records the PQC compliance / vendor readiness / migration milestone schemas on
the EAS SchemaRegistry predeploy. Save the returned schema UIDs with your
deployment records.

## 8. Smoke checklist

- [ ] `curl -s localhost:3001/health` returns `"status":"ok"`, correct chain id, relayer address
- [ ] `curl -s localhost:3001/docs/json | jq '.paths | keys[]'` includes `/v1/relay/audit`
- [ ] Prometheus targets green at localhost:9090 (`qtrust-api` job UP); alert rules loaded
- [ ] Pilot end-to-end against local anvil first (its defaults are anvil addresses):
      `python pilot/run_pilot.py` — full scan→register→attest→migrate→audit loop passes;
      then re-run against Sepolia with the real addresses exported
- [ ] Verify one asset in the UI: open `/v/<ASSET_ID>` and confirm the on-chain badge resolves
- [ ] Submit one gasless write (e.g. relay CBOM) and see it indexed within seconds
- [ ] `docker exec qtrust-postgres psql -U qtrust -c 'SELECT COUNT(*) FROM audits;'` > 0 after pilot

## 9. Tag and release

```bash
git tag -a v2.0.0 -m "Q-Trust v2.0.0 — Base Sepolia deployment"
git push origin v2.0.0
gh release create v2.0.0 --generate-notes \
  --notes-start-tag <previous-release-tag> \
  --title "v2.0.0"
```

Attach the deployment record (addresses, EAS schema UIDs, deploy tx hashes from
`broadcast/`) to the GitHub Release so the state is reproducible.

---

## Troubleshooting

**Faucet dry / insufficient funds** — Alchemy & Circle faucets require a
verified mainnet balance on the requesting address. Use a fresh funded bridge
via the Base bridge from Sepolia, or ask in the Base Discord #faucet channel.
Deployer needs ≥ 0.05 ETH; relayer ≥ 0.02 ETH.

**Deployment transaction stuck (nonce gap)** — check the pending nonce:
`cast nonce $DEPLOYER --rpc-url $RPC_URL`. If a broadcast died mid-run,
re-run with `--resume` or clear stale artifacts in `broadcast/` before
redeploying; never reuse a partial deployment's addresses.

**Verification mismatches** — Basescan compares bytecode exactly:
(1) ensure the same compiler build (`forge build` with the repo's pinned
`solc 0.8.24` and optimizer settings); (2) proxies must be verified as
`ERC1967Proxy` with the matching init calldata, or use standard-json
verification via the CI job which reads `contracts/verification/<Name>.args`;
(3) if `--verify` fails transiently, retry — the Basescan API rate-limits.

**`InvalidNonce` on gasless routes** — the signer's local nonce is stale:
refetch via `GET /v1/relay/audit-nonce/:did` (and siblings) and re-sign.

**Indexer empty after boot** — `QTRUST_INDEXER_FROM_BLOCK` defaults to 0; if
you set it above the actual deployment block, events are skipped. Reset cursors
per the replay procedure in `docs/runbook/incident-response.md`.
