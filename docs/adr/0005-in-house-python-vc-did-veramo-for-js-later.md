# 5. In-house Python VC/DID stack, Veramo for JS later

## Status

Accepted — 2026-08-24

## Context

The platform needs verifiable credentials (issuer/holder/verifier triangle)
anchored to `did:ethr`-style identifiers, with Ed25519 signing. Options:
adopt Veramo (TypeScript) immediately and make Node a hard runtime dependency
of the SDK; adopt a heavyweight Python VC framework; or implement the minimal
VC/DID surface in-house inside the existing Python SDK.

## Decision

Implement the minimal VC/DID primitives in-house in the Python SDK
(`qtrust.vc.VCIssuer` / `VCVerifier`, DID utilities) using established crypto
libraries only — no bespoke cryptography. The backend now implements the same
issuance/verification in TypeScript (`backend/src/services/vc.ts`) using
`@noble/curves` + `@scure/base` (audited, dependency-free crypto), with a
canonical payload byte-compatible with the SDK (sorted keys, compact
separators, ensure_ascii) so both languages verify each other's credentials.

Consequences:

* The Python SDK stays self-contained (no Node sidecar for CI or pilots).
* We own maintenance of a small, well-scoped VC layer instead of a large
  dependency tree; W3C conformance is tested explicitly.
* Backend `/v1/credentials/issue` signs real Ed25519Signature2020 credentials
  and `/v1/credentials/verify` performs fail-closed cryptographic verification
  (structure + expiry + signature vs the resolved issuer DID key; did:key
  offline, did:web via HTTPS with an SSRF guard). Cross-language compatibility
  is covered by tests in both `backend/tests/vc.test.ts` and the SDK.
* If JS-local verification grows further (e.g. Veramo), the data model mirrors
  standard VCs so migration is cheap.
