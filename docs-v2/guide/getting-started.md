---
title: Getting Started
outline: [2, 3]
---

# Getting Started

From zero to your first cryptographic bill of materials in about five
minutes. The only thing you need to install is the inspector — everything in
the tour below runs offline against hosts you already control.

## Prerequisites

| Tool | Version | Needed for |
| --- | --- | --- |
| Node.js | 20+ | backend / frontend / this docs site |
| Python | 3.10+ (3.11 recommended) | inspector, SDK, planner |
| [Foundry](https://getfoundry.sh) | latest (`foundryup`) | contracts, invariant tests |
| Docker | any recent | full-stack compose profile |

## 5-minute tour: scan a TLS endpoint

Install the inspector from PyPI:

```bash
pip install qtrust-inspector
```

Scan a host you own or are authorized to test — say `example.com` — exporting
a CycloneDX 1.7 CBOM and a SARIF report in one pass:

```bash
crypto-inspector host example.com --ports 443,8443,22 \
  --output scan.json \
  --cyclonedx cbom.json \
  --sarif findings.sarif \
  --compliance nist,cnsa
```

The command prints a findings table (algorithm, location, criticality), a
risk assessment per finding, and a compliance score per framework you
requested. You now have three artifacts:

- `scan.json` — the raw `ScanResult` (re-usable by every other subcommand)
- `cbom.json` — a CycloneDX 1.7 CBOM of the endpoint's cryptographic assets
- `findings.sarif` — SARIF 2.1, ready for GitHub code-scanning

## Deep-dive and re-scoring (no network needed)

```bash
# Per-finding risk table (quantum vulnerability, NIST 800-131A, HNDL exposure)
crypto-inspector risk-score scan.json

# Compliance against more frameworks
crypto-inspector compliance-check scan.json --framework nist,cnsa,fips,nis2

# Deep TLS probe: cipher suites, groups, PQC codepoint detection
crypto-inspector deep-probe example.com --port 443
```

## Where to go next

- [Installation](/guide/installation) — PyPI packages, monorepo checkout,
  and the Docker Compose profile.
- [Architecture](/architecture/overview) — how the six subsystems connect,
  from scanner to Base L2.
- [qtrust-inspector CLI](/packages/inspector) — the full command reference.
- [qtrust-sdk](/packages/sdk) — register your new CBOM on-chain in Python.

::: tip Honesty note
The inspector only reports what it can observe. A clean scan of one endpoint
is an inventory of that endpoint — not a statement that the organization is
post-quantum ready.
:::
