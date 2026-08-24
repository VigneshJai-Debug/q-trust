# 1. Base L2 selection

## Status

Accepted — 2026-08-24

## Context

Q-Trust anchors cryptographic-assurance records that vendors, auditors, and
verifiers must be able to read cheaply and write to without enterprise-grade
gas budgets. Candidates evaluated: Ethereum L1, Polygon PoS, Arbitrum One,
Optimism, Base.

## Decision

Deploy on Base: Base Sepolia (chain id 84532) for staging/pilots, with a
config flag (`QTRUST_USE_MAINNET`) for Base mainnet (8453).

Consequences:

* Gas costs are orders of magnitude below L1; gasless-relay economics work
  even at testnet scale.
* OP-stack security (inherited from Ethereum via fault proofs) instead of a
  sidechain's validator set.
* Coinbase ecosystem alignment gives credible vendor/enterprise reach.
* EAS predeploys exist on both Base networks out of the box, which the schema
  registration script relies on.
* L2 sequencer decentralization is still maturing; reorg handling in the
  indexer assumes shallow reorgs (see the confirmations window).
* All tooling (Foundry, viem, Basescan verification) treats it as a standard
  EVM chain — no bespoke infra.
