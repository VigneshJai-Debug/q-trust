---
title: qtrust-inspector
outline: [2, 3]
---

# qtrust-inspector

Multi-language cryptographic inventory and post-quantum risk scanner:
discover, score, comply, plan. The CLI is `crypto-inspector` (Typer +
Rich — every command below is the real invocation pattern from
`inspector/qtrust_inspector/cli.py`).

- **PyPI:** <https://pypi.org/project/qtrust-inspector/> (v1.1.0)
- **Source:** [`inspector/`](https://github.com/humoge7502/q-trust/tree/main/inspector)

## Install

```bash
pip install qtrust-inspector
# extras: [net] adds nmap network scans, [ml] adds PyTorch detectors
pip install "qtrust-inspector[net,ml]"
```

## Scanning

```bash
# Single host (TLS/SSH) with CBOM + SARIF export and compliance scoring
crypto-inspector host example.com --ports 443,8443,22 \
  --output scan.json --cyclonedx cbom.json --sarif findings.sarif \
  --compliance nist,cnsa

# Directory: certs/keys + source (regex) + AST + manifests + binaries
crypto-inspector directory ./src --cyclonedx cbom.json

# Universal: auto-detects host / directory / CIDR and runs all scanners
crypto-inspector scan 10.0.0.0/24 --evidence ledger.json --roadmap plan.json

# Source-only tree scan, SARIF for GitHub code-scanning
crypto-inspector scan-source ./src --format sarif --output out.sarif

# Deep TLS probe: groups, signature algorithms, PQC codepoints
crypto-inspector deep-probe example.com --port 443

# Harvest-Now-Decrypt-Later exposure from PCAP / Zeek / Suricata EVE
crypto-inspector pcap-scan capture.pcap --deep --top 10

# List the active AST/regex detector capabilities as JSON
crypto-inspector --detectors
```

## Scoring & compliance

```bash
# Per-finding risk: quantum vulnerability, NIST 800-131A, HNDL exposure
crypto-inspector risk-score scan.json

# Framework evaluation (CLI supports 7 headline frameworks; the engine
# additionally knows pci, bsi, ncsc, asd)
crypto-inspector compliance-check scan.json --framework nist,cnsa,fips,nis2,fisma,fedramp,cmmc

# PQC parameter-set conformance vs FIPS 203/204/205 spec tables
crypto-inspector conformance ML-KEM --level 768

# Generated code fixes for a vulnerable algorithm
crypto-inspector auto-remediate RSA-2048 --language python --dry-run

# Kubernetes PQC enforcement policies (Kyverno / Gatekeeper)
crypto-inspector k8s-policy --engine kyverno --output policies.yaml
```

## On-chain operations (requires qtrust-sdk)

```bash
crypto-inspector register-cbom cbom.json --metadata-uri "ipfs://..."
crypto-inspector attest-product "ACME-HSM" "2.1" "ML-KEM-768" --supported
crypto-inspector verify <asset_id>
crypto-inspector retire <asset_id>
```

## Output formats

| Format | Flag | Consumed by |
| --- | --- | --- |
| CycloneDX 1.7 CBOM | `--cyclonedx` | planner, SDK, dependency-management tooling |
| SARIF 2.1 | `--sarif` | GitHub code-scanning, IDEs |
| Scan JSON | `--output` | every other subcommand (risk-score, export, …) |
| Evidence ledger | `--evidence` | `evidence-verify` (hash-chain integrity check) |
| Migration roadmap | `--roadmap` | effort/cost/timeline estimates (`--daily-rate`) |

`crypto-inspector export scan.json --cyclonedx … --sarif … --roadmap …`
re-exports any previous scan without re-scanning.

## MCP server & benchmarks

`crypto-inspector mcp start` launches a JSON-RPC tool server exposing the
scan/risk/compliance surface to AI coding agents (Claude, Copilot, Cursor).

A ground-truth corpus and scoring harness live in `inspector/benchmarks/`
(vulnerable + clean files in Python/JavaScript/Go) so detection quality is
measured in-repo rather than asserted.

::: tip Scope note
The inspector recognizes ML-KEM, ML-DSA, SLH-DSA, HQC, FALCON and SPHINCS+
among PQC algorithms, and maps legacy ones (RSA, ECC, DSA) with criticality
scoring. Conformance checks are deterministic spec-table comparisons —
implementation-level ACVP known-answer testing is reported as *skipped*, not
faked.
:::
