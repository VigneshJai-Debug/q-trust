# EAS PQC Schema Definitions

Three schemas, published first in the EAS ecosystem (no PQC schemas existed
ecosystem-wide as of August 2026). Schema strings are exact, byte-for-byte,
as passed to `SchemaRegistry.register()`.

---

## 1. PQC Compliance Attestation

```text
bytes32 cbomHash,string framework,uint8 score,bool compliant,uint64 validUntil,string evidenceURI
```

- **Revocability:** `revocable = true`. Compliance can lapse or be
  invalidated (e.g. a new critical classical-crypto finding); revocation
  must be possible without waiting for expiry.
- **Intended issuers:** accredited auditors / the Q-Trust auditor role
  (`AuditRegistry.AUDITOR_ROLE`), or an org attesting its own CBOM-derived
  compliance score for self-assessment workflows.
- **Mapping from Q-Trust registries:**

| Field         | Source                                                        |
| ------------- | ------------------------------------------------------------- |
| `cbomHash`    | `AssetRegistry` asset `cbomHash` (keccak256 of CycloneDX CBOM) |
| `framework`   | Compliance framework name from SDK `ComplianceEngine` result (`"CNSA-2.0"`, `"NIST-SP-800-131A"`, …) |
| `score`       | `ComplianceEngine` score (0–100) for that framework            |
| `compliant`   | `AuditRegistry.AuditAttestation.result ∈ {Passed}` or engine pass flag |
| `validUntil`  | Issuer-chosen validity window (uint64 unix seconds)           |
| `evidenceURI` | `AuditAttestation.reportURI` (IPFS/HTTPS evidence bundle)      |

---

## 2. Vendor PQC Readiness

```text
address vendor,string productId,string[] algorithms,bool pqReady,uint64 attestedAt
```

- **Revocability:** `revocable = false`. Point-in-time claims stay
  immutable for accountability; superseded readiness is expressed by
  issuing a newer attestation, not rewriting history.
- **Intended issuers:** the vendor itself (`VendorRegistry.VENDOR_ROLE`)
  or a vendor admin (`VENDOR_ADMIN_ROLE`) attesting its own products;
  third-party assessors may issue their own variant under a distinct UID.
- **Mapping from Q-Trust registries:**

| Field        | Source                                                              |
| ------------ | -------------------------------------------------------------------- |
| `vendor`     | `VendorRegistry.ProductAttestation.vendorDid` (address)               |
| `productId`  | `ProductAttestation.productId`                                       |
| `algorithms` | Aggregated `ProductAttestation.algorithm` values across the product   |
| `pqReady`    | Derived: all listed algorithms are NIST PQC (`ML-KEM-*`, `ML-DSA-*`, `SLH-DSA-*`, HQC) and `supported = true` |
| `attestedAt` | `ProductAttestation.timestamp`                                        |

---

## 3. Migration Milestone

```text
bytes32 evidenceRoot,uint8 phase,uint256 assetsTotal,uint256 assetsMigrated
```

- **Revocability:** `revocable = true`. A milestone can be revoked if its
  evidence root is later shown invalid or double-counted; corrected
  milestones are re-issued at a higher `phase`.
- **Intended issuers:** the migrating organization
  (`MigrationRegistry.MIGRATOR_ROLE`); countersigned downstream by auditors
  (`AUDITOR_ROLE`) via `AuditAttestation`.
- **Mapping from Q-Trust registries:**

| Field             | Source                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `evidenceRoot`    | Merkle root over `Migration.evidenceHash` batch for the milestone window (single-step migrations may use the lone `Migration.evidenceHash`) |
| `phase`           | Migration roadmap phase (SDK `MigrationPhase`, 1–5)                     |
| `assetsTotal`     | `AssetRegistry` total active assets in scope (or `AuditAttestation.assetsReviewed`) |
| `assetsMigrated`  | `MigrationRegistry` verified migrations in scope (`AuditAttestation.assetsMigrated`) |

---

## Registration UIDs

Schema UIDs are assigned by EAS on first registration per chain and are
deterministic given `(schema string, resolver, revocable)` — but only the
chain's registry is authoritative. Run `script/RegisterSchemas.s.sol` and
record returned UIDs here after first deployment:

| Schema                    | Base Sepolia UID | Base mainnet UID |
| ------------------------- | ---------------- | ---------------- |
| PQC Compliance Attestation | _pending_        | _pending_        |
| Vendor PQC Readiness       | _pending_        | _pending_        |
| Migration Milestone        | _pending_        | _pending_        |
