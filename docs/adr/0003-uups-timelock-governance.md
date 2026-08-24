# 3. UUPS upgradeability behind timelock governance

## Status

Accepted — 2026-08-24

## Context

Registries anchor long-lived assurance records; bugs or evolving PQC
requirements will require upgrades, but an upgrade path is itself the most
attractive exploit. A single EOA admin could silently replace logic. At the
same time, incident response (e.g. pausing a registry) must remain possible.

## Decision

Each registry is deployed as a UUPS proxy (ERC1967) with upgrade authorization
restricted to `DEFAULT_ADMIN_ROLE`. After `Deploy.s.sol` runs:

* Operational roles (`REGISTRAR_ROLE`, `VENDOR_ADMIN_ROLE`, `MIGRATOR_ROLE`,
  `AUDITOR_ROLE`, …) are granted to a 7-day `TimelockController`.
* `DEFAULT_ADMIN_ROLE` moves to the timelock and the deployer renounces it.
* `QTrustGovernance` is the sole timelock proposer/executor wrapper: pause /
  unpause / role grants / arbitrary calls go through schedule → delay →
  execute, with grant/revoke of `DEFAULT_ADMIN_ROLE` forbidden by design.
* The deployer retains only `AUDITOR_ROLE` on AuditRegistry for pilots/E2E.

Consequences:

* No silent upgrades: users get ≥ 7 days' notice on-chain before any logic
  change executes.
* Emergency pause is deliberately **not** instant post-handover — pausing is a
  scheduled governance action (documented tradeoff; see runbook SEV1).
* Upgrade storage-layout discipline required: new contract versions must be
  append-only in storage to avoid slot collisions.
* The deployer key is a launch-phase risk only; after renounce it holds no
  admin power anywhere.
