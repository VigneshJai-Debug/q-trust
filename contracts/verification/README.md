# Contract Verification (Basescan)

This directory supports the automated `contract-verify` job in
`.github/workflows/ci.yml`, which verifies deployed Q-Trust contracts on
Base mainnet (chain ID 8453) via Basescan after every push to `main`.

## Required repository configuration

| Type    | Name                        | Purpose                                              |
|---------|-----------------------------|------------------------------------------------------|
| Secret  | `BASESCAN_API_KEY`          | Basescan API key for the Etherscan-compatible verifier |
| Variable| `DEPLOYED_PROXY_ADDRESSES`  | Multiline list of deployed contracts to verify        |

Both are optional at the repository level: if either is missing, the job
logs a notice and exits successfully (no red CI for unconfigured repos).

## DEPLOYED_PROXY_ADDRESSES format

One `Name=0xAddress` pair per line, where `Name` matches both:

- a Solidity source file: `contracts/src/<Name>.sol`
- a contract inside that file with the same name

```text
AssetRegistry=0x1111111111111111111111111111111111111111
MigrationRegistry=0x2222222222222222222222222222222222222222
AuditRegistry=0x3333333333333333333333333333333333333333
```

Blank lines and lines starting with `#` are ignored.

## Constructor arguments

If a contract was deployed with constructor arguments, place them
(one argument per line, ABI-encoded as plain text — e.g. one address or
uint per line) in this directory as `<Name>.args`. The CI job detects the
file automatically and passes it to Forge as `--constructor-args-path`.
Contracts with no constructor args need no file.

## Manual verification

To verify a single contract locally:

```sh
cd contracts
forge verify-contract \
  --chain-id 8453 \
  --verifier etherscan \
  --verifier-url https://api.basescan.org/api \
  0xYourContractAddress src/AssetRegistry.sol:AssetRegistry
```

Set `BASESCAN_API_KEY` in your environment first. Verification failures in
CI emit warnings but do not fail the workflow.
