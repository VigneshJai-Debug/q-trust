# 2. EIP-712 gasless relay for all user writes

## Status

Accepted — 2026-08-24

## Context

Every meaningful user action (CBOM registration, product attestation,
migration recording, audit posting) is a transaction. Requiring each vendor,
org, or auditor to hold ETH and manage wallets would block onboarding.
A naive "admin submits on behalf" model would make the platform the trusted
author of all data — unacceptable for an assurance platform.

## Decision

All user-facing write paths are EIP-712 meta-transactions. Users sign typed
data off-chain (SDK or MetaMask); an operator-run relayer verifies the
signature locally, checks the signer's per-address nonce, and submits the
matching `...Signed` contract entrypoint. Contracts recover the signer via
ECDSA against a domain separator bound to name/version/chainId/proxy address,
check `nonces[signer] == nonce`, verify the signer's role where applicable,
and record **the signer** as the actor. The relayer holds funds but no
authority: stolen relayer keys cannot forge submissions, only spend gas.
Relay endpoints are rate-limited (10/min) to bound gas abuse.

Consequences:

* Vendors/orgs/auditors never need ETH; signature UX is wallet-friendly.
* Nonce management moves to clients (fetch nonce → sign); stale nonces fail
  fast with a clear error before any chain interaction.
* Each registry carries its own domain name ("QTrustAssetRegistry", …), so
  signatures are not replayable across registries or chains.
* The relayer is a liveness dependency only — reads and direct role-gated
  writes keep working if it is down.
