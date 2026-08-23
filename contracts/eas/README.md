# Q-Trust × EAS — PQC Compliance Attestations

Public, first-mover publication of post-quantum compliance schemas for
[Ethereum Attestation Service](https://attest.so) (EAS).

## Why EAS

- **Multichain reach from day one.** EAS runs on 10+ chains including Base,
  Optimism, Arbitrum, and Ethereum. Schemas registered once are reusable
  anywhere EAS is deployed.
- **Zero prior art.** As of August 2026, no PQC-compliance schemas exist in
  any EAS ecosystem schema registry. These three are a first mover:
  compliance scoring, vendor readiness, and migration milestones.
- **Composable trust.** Any wallet, dapp, or procurement pipeline can verify
  a vendor's PQC posture with a single attestation lookup — no custom
  indexer required.

Q-Trust's own contracts (`contracts/src/`) keep rich application state
(registries, roles, revocation). The EAS layer publishes *minimal,
interoperable claims* derived from that state. See `schemas.md` for exact
field mappings.

## Schema registry addresses

| Network      | EAS (proxy)                            | SchemaRegistry                         |
| ------------ | -------------------------------------- | -------------------------------------- |
| Base mainnet | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |
| Base Sepolia | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |

These canonical predeploy-style addresses follow the documented EAS Base
deployment pattern — **verify at <https://docs.eas.attest.so> before
transacting**.

## Registering the schemas

`script/RegisterSchemas.s.sol` (Foundry) registers all three schemas via
the EAS `SchemaRegistry.register()` interface and logs the returned schema
UIDs. It deploys nothing custom.

```bash
export QTRUST_DEPLOYER_PRIVATE_KEY=0x...        # deployer key
export EAS_SCHEMA_REGISTRY=0x4200...0020        # optional; defaults to Base predeploy

cd contracts
forge script eas/script/RegisterSchemas.s.sol \
    --rpc-url base_sepolia --broadcast
```

Recorded schema UIDs should be committed to documentation after first run;
they are deterministic only per-chain and first-registration-wins.

## Files

- `schemas.md` — schema definitions, revocability policy, issuer roles,
  and mappings from Q-Trust on-chain registries.
- `script/RegisterSchemas.s.sol` — Foundry registration script.
