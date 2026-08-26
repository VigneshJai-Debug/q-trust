# Guide — Scan your first CBOM

This is the 60-second path from clone to a verifiable cryptographic bill of materials.

## 1 — Install the scanner

```bash
git clone https://github.com/humoge7502/q-trust && cd q-trust/inspector
pip install -e .
```

## 2 — Scan a live TLS endpoint

```bash
crypto-inspector scan example.com --cyclonedx cbom.json --risk --compliance nist,cnsa
cat cbom.json | jq '.components[0]'
```

Output is CycloneDX 1.7 with `cryptoProperties` — algorithm, key size, quantumSafe flag — ready for regulatory reporting.

## 3 — Scan a local codebase

```bash
crypto-inspector scan ./src --cyclonedx cbom.json --sarif results.sarif --risk --compliance nist,cnsa --evidence ledger.json --roadmap plan.json
```

SARIF goes straight to GitHub Advanced Security code scanning.

## 4 — Verify locally

```bash
crypto-inspector evidence-verify ledger.json
crypto-inspector compliance-check cbom.json -f nist,cnsa,fips
```

Next: [Integrate the SDK](integrate-sdk.md) to pin to IPFS and anchor on-chain, or [Deploy to Base Sepolia](deploy-base-sepolia.md).

Source: `inspector/` · `docs/CBOM_CONFORMANCE.md` · `docs/PERFORMANCE.md`

*Last verified: 2026-08-27 · against commit f02d106 · verifier: ./scripts/verify_all.sh*
