# 6. Deterministic content-addressed IDs

## Status

Accepted — 2026-08-24

## Context

Registry entries need stable identifiers that verifiers can compute
independently from data they already hold, without a lookup, and that prevent
accidental duplicates. Sequential IDs would leak volume and require a registry
query to resolve; random IDs would allow unbounded duplicate spam.

## Decision

Core registries derive IDs deterministically via keccak256 over their content
and actor:

* AssetRegistry: `assetId = keccak256(abi.encode(orgDid, cbomHash))`
* VendorRegistry: `attestationId = keccak256(vendorDid, productIdHash)`
* AuditRegistry: `auditId = keccak256(auditorDid, orgDid, reportHash)`

(MigrationRegistry takes caller-chosen `migrationId` bytes32 because migrations
are inherently step-oriented and orgs may legitimately record several steps
with identical payloads.)

A second submission of identical content therefore deterministically collides
with the first and hits an explicit `Duplicate*` error rather than creating a
shadow record. Anyone can precompute the ID of an asset/attestation/audit from
its public inputs and verify it against the chain without any API call.

EIP-712 domain separators follow OpenZeppelin's defensive-copy pattern: the
separator is cached at initialization together with `_cachedChainId`, and any
fork that changes `block.chainid` triggers recomputation instead of reusing
the stale cached separator — signatures remain chain-bound even across L2
fork events.

Consequences:

* Client-side ID computation matches on-chain IDs exactly (SDK relies on
  this); changing the derivation is a breaking change.
* Re-registration of identical content fails loudly instead of silently
  duplicating — intentional, surfaced as `DuplicateAudit` etc.
* No enumeration primitive: IDs cannot be listed on-chain directly; the
  Postgres read model (ADR 0004) provides listing.
