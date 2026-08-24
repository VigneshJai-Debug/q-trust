# Case Study: example.com TLS Post-Quantum Assessment (Local E2E Demo)

> **Scope note (honest):** this run was executed against a *local* anvil
> chain simulating Base Sepolia (chain-id 84532) because no funded public
> testnet key was available in the build environment. The pipeline — scan →
> CBOM → on-chain registration → API verification — is identical to a real
> Base Sepolia run; only the RPC endpoint differs. See `docs/deployment/BASE_SEPOLIA.md`
> for the public-net procedure.

## Summary

- **Date:** 2026-08-24
- **Target:** `example.com:443` (public TLS endpoint)
- **Scanner:** `qtrust-inspector` v1.1.0 (`crypto-inspector host`)
- **Assets discovered:** 1
- **On-chain asset ID:** `0x0b6edef719ada335025b364b7ef126e55a526b2a731e4afbfc573c14fe93312f`
- **CBOM hash:** `0x5f745f347bed5c5a989740332055adeca7674d3db66d150cfdacb77ce617d462`
- **Raw CBOM:** [`demo_cbom_example_com.json`](./demo_cbom_example_com.json)

## Findings

| Type | Algorithm | Key size | Location | Criticality | Quantum-vulnerable? |
|---|---|---|---|---|---|
| tls_certificate | ecdsa-with-SHA256 (P-256) | 256 | example.com:443 | medium | Yes — Shor-vulnerable by ~2030–2035 |

Issuer: `CN=Cloudflare TLS Issuing ECC CA 3, O=SSL Corporation, C=US`.

## Pipeline trace

```
crypto-inspector host example.com --ports 443 --output cbom.json   # 1 asset
crypto-inspector register-cbom cbom.json -m ipfs://...             # on-chain
# → asset_id 0x0b6e…312f, cbom_hash 0x5f74…d462

curl /v1/assets/0x0b6e…312f        # 200 — indexer read model
curl /v1/assets/0x0b6e…312f/verify # exists=true, active=true, chain_id=84532
```

## Planner recommendation

With a single P-256 certificate at medium criticality and no dependency
graph, both the GNN planner and the heuristic baseline agree: migrate the
TLS certificate's key agreement to a hybrid X25519+ML-KEM-768 offering at
next renewal. Estimated effort: one certificate rotation — trivially within
OMB M-23-02 / CNSA 2.0 timelines.

## What this validates

1. Live TLS probing with certificate fingerprinting.
2. Schema-valid CBOM generation (`cbom.v1`).
3. Deterministic content-addressed registration (ADR-0006).
4. Indexer read model serving verified state over REST.

## Reproduce locally

See [PERFORMANCE.md §Reproduce](../PERFORMANCE.md) for the anvil +
deployment + backend bootstrap, then:

```bash
QTRUST_BASE_SEPOLIA_RPC=http://127.0.0.1:8545 \
QTRUST_ASSET_REGISTRY_ADDRESS=<proxy> \
QTRUST_DEPLOYER_PRIVATE_KEY=<anvil-key> \
  crypto-inspector host example.com --ports 443 --output cbom.json

QTRUST_... crypto-inspector register-cbom cbom.json \
  -m "ipfs://<cid>"
```
