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
libraries only — no bespoke cryptography. The backend's credential endpoints
are deliberately conservative: they never claim signature validity the backend
cannot verify, and direct full verification to the SDK. A JS integration on
Veramo is deferred until the frontend needs local verification.

Consequences:

* The Python SDK stays self-contained (no Node sidecar for CI or pilots).
* We own maintenance of a small, well-scoped VC layer instead of a large
  dependency tree; W3C conformance is tested explicitly.
* Backend fail-closed behavior (`signature_verification_unavailable_in_backend`)
  avoids false trust assertions at the cost of duplicated client-side work.
* If JS-local verification becomes a product requirement, Veramo adoption will
  be re-evaluated; the data model mirrors standard VCs so migration is cheap.
