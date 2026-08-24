# Go-Live Checklist

Code-complete items that need **external accounts or credentials** to flip
from "ready" to "live". Everything runnable locally has been done and
verified — see [PERFORMANCE.md](../PERFORMANCE.md) and
[GPU_FEATURES.md](../GPU_FEATURES.md).

## 1. Base Sepolia contract deployment — Gap 2

Blocked on: funded deployer key ([faucet](https://www.alchemy.com/faucets/base-sepolia)).

```bash
export QTRUST_DEPLOYER_PRIVATE_KEY=0x...
forge script script/Deploy.s.sol --rpc-url https://sepolia.base.org \
  --broadcast --verify --etherscan-api-key $BASESCAN_API_KEY --chain-id 84532
```

Then: fill `QTRUST_*_REGISTRY_ADDRESS` in envs, add addresses to repo
variable `DEPLOYED_PROXY_ADDRESSES` (CI re-verifies automatically), update
README + `MULTI_CHAIN.md` table. The full pipeline was validated end-to-end
on a local anvil chain with chain-id 84532 — see
[CASE_STUDY_EXAMPLE_COM.md](../case-studies/CASE_STUDY_EXAMPLE_COM.md).

## 2. Frontend → Vercel — Gap 3

Blocked on: Vercel account + WalletConnect project ID. Root dir `frontend/`,
env vars per `.env.example`. Build is verified green (`next build`).

## 3. Backend → Railway/Render — Gap 4

Blocked on: hosting account. Dockerfile present; needs Postgres + Redis
add-ons and the deployed contract addresses from step 1.

## 4. Demo video — Gap 5

Blocked on: screen recording. Suggested run-of-show lives in
`docs/demo_run_of_show.md`; the local anvil stack in
[PERFORMANCE.md §Reproduce](../PERFORMANCE.md) provides every scene.

## 5. Multi-chain (Arbitrum/Optimism) — Gap 17

Commands documented in [MULTI_CHAIN.md](MULTI_CHAIN.md); same faucet/key
blocker as item 1.

## 6. PyPI / GHCR publishing — Gaps 12–13

Workflows are merged (`.github/workflows/publish-pypi.yml`,
`publish-docker.yml`). One-time setup:
- PyPI Trusted Publishing: add pending-publisher entries for `qtrust-sdk`
  and `qtrust-inspector` (workflow `publish-pypi.yml`, environment `pypi`).
- GHCR images become public via package settings after first tag push.

## 7. Strategic tier — Gaps 20–22 (ZK CBOM proofs, TEE attestation,
   vendor verification bot)

Multi-week builds tracked in
[`QTrust_Implementation_Gap_Report.md`](../../QTrust_Implementation_Gap_Report.md)
(Tier 4). The side-channel analyzer + bridge (Gap 22's core) already exist;
the bot reduces to an OQS-download loop around it.
