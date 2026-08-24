# CBOM / CycloneDX 1.7 Conformance

`qtrust-inspector` emits Cryptographic Bill of Materials (CBOM) documents in
**CycloneDX 1.7** format (`bomFormat: CycloneDX`, `specVersion: 1.7`). This
document maps the inspector's native inventory schema (`qtrust.cbom.v1`, see
`ScanResult.to_cbom()` in `inspector/qtrust_inspector/models.py`) onto the
CycloneDX 1.7 JSON paths produced by `generate_cyclonedx()` in
`inspector/qtrust_inspector/cyclonedx.py`.

> Formalization of CBOM as an Ecma standard (**ECMA-424**, based on CycloneDX)
> is tracked: once field-level guidance for crypto properties stabilizes in
> that formal text, this mapping will be re-validated against it.

## Field mapping: qtrust.cbom.v1 → CycloneDX 1.7

| qtrust.cbom.v1 field | CycloneDX 1.7 JSON path | Notes |
|---|---|---|
| *(document root)* | `bomFormat`, `specVersion`, `version` | Always `"CycloneDX"`, `"1.7"`, `1` |
| *(generated per export)* | `serialNumber` | `urn:uuid:<uuid4>` |
| `scan_timestamp` | `metadata.timestamp` | ISO-8601 UTC |
| `scanner` | `metadata.tools[0].{vendor,name,version}` | `qtrust` / `qtrust-inspector` |
| `target` | — | **Gap:** not emitted into `metadata.component`; see gap list |
| `asset_count` | — | Derivable from `len(components)` |
| `assets[].type` | `components[].cryptoProperties.assetType` | Via `ASSET_TYPE_MAP`: `tls_certificate→certificate`, `ssh_host_key/file_key/ssh_private_key→key`, `algorithm→algorithm`, `protocol→protocol`, `library→library` |
| `assets[].host` | `components[].name` | Emitted as `"<asset_type>:<host>"` |
| `assets[].port` | — | **Gap:** folded into nothing; location not emitted separately |
| `assets[].algorithm` | `components[].cryptoProperties.algorithmProperties.name` (+`.scheme`) | Normalized via `ALGORITHM_PROPERTIES`; unknown algorithms pass through verbatim |
| `assets[].key_size` | `components[].cryptoProperties.algorithmProperties.strength` | Serialized as string |
| `assets[].key_type` | — | **Gap:** no direct CycloneDX slot; omitted |
| `assets[].vendor` | — | **Gap:** omitted (no component publisher emitted) |
| `assets[].criticality` | `components[].properties[name="qtrust:criticality"].value` | Q-Trust extension property |
| risk score (per host) | `components[].properties[name="qtrust:risk_score"].value` | Q-Trust extension property |
| quantum-safety verdict | `components[].cryptoProperties.quantumSafe` and top-level `components[].quantumSafe` | Derived from weak-algorithm heuristics (`WEAK_ALGORITHMS`) |
| `assets[].fingerprint_sha256` | `components[].hashes[{alg:"SHA-256", content}]` | Only when a fingerprint is known |
| `assets[].issuer` | `components[].cryptoProperties.certificates[0].issuer` | Certificate block, TLS findings only |
| `assets[].subject` | `components[].cryptoProperties.certificates[0].subject` | |
| `assets[].serial_number` | `components[].cryptoProperties.certificates[0].serialNumber` | |
| `assets[].not_before` | `components[].cryptoProperties.certificates[0].notBefore` | |
| `assets[].not_after` | `components[].cryptoProperties.certificates[0].notAfter` | |
| `assets[].expired` | `components[].cryptoProperties.certificates[0].expired` | Boolean |
| `assets[].metadata` | — | Free-form dict; intentionally not mapped |
| high risk scores (≥7) | `vulnerabilities[]` | `{id: "qtrust-<host>", source, ratings[{score, severity}], description}` |

Conformance of the emitted envelope is asserted by
`inspector/tests/test_cyclonedx_conformance.py`.

## Fields we emit outside the strict CycloneDX 1.7 spec

These are pragmatic extensions; consumers must tolerate unknown keys, but
strict validators may flag them:

1. **`components[].quantumSafe`** (top level) — duplicate of
   `cryptoProperties.quantumSafe` at an unspecified location.
2. **`cryptoProperties.algorithmProperties.{scheme,strength,version,mode}`** —
   the spec's algorithm properties define `parameterSetIdentifier`,
   `primitive`, `namespace`, `oid`, `name`; our extra keys are extensions.
3. **`cryptoProperties.certificates[]` field naming** — we emit
   `issuer`/`subject`/`serialNumber`/`notBefore`/`notAfter`/`expired`;
   the spec's certificate properties use different names
   (e.g. `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`)
   and live under `certificateProperties`.
4. **`properties[]` names `qtrust:risk_score` and `qtrust:criticality`** —
   namespaced extension properties (legal in CycloneDX, but non-standard).
5. **`metadata.componentCount`** — not a spec field.
6. **`vulnerabilities[].ratings[].severity` values `critical|high`** — aligned,
   but the surrounding object is simplified relative to the full spec shape.

## Spec fields we omit (gaps)

1. `metadata.component` — scan target identity is not represented.
2. `components[].version`, `.purl`, `.cpe` — package identity fields unused.
3. `cryptoProperties.algorithmProperties.parameterSetIdentifier`, `.primitive`,
   `.namespace` — richer algorithm identification not populated.
4. `certificateProperties.subjectName`, `.issuerName`, `.notValidBefore/.notValidAfter`,
   key/signature references — spec-native certificate block not used (see
   extension #3 above).
5. `dependencies`, `compositions` — relationship graph not emitted.
6. `assets[].port`, `.key_type`, `.vendor` — carried in neither spec nor
   extension slots (recoverable only from `components[].name`).
