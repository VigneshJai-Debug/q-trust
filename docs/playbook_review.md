# Playbook Review — Findings (August 2026)

Review of the Go-Live & Pitch Playbook against the actual repo state at `/home/nvidia/Project`.
Full verification was re-run after fixes: **ALL CHECKS PASSED** (contracts 49/49, SDK unit+E2E,
inspector, planner benchmark, backend tsc, frontend build, both notebooks, pilot).

## 1. Bug found and fixed

**`notebooks/08_bank_pilot.ipynb` failed to execute** — cell 1 hardcoded
`sys.path.insert(0, '/home/nvidia/Vibe_Project/pilot')`, a stale path from a previous machine
layout (`ModuleNotFoundError: No module named 'run_pilot'`). This contradicted the claim
"pilot notebook executes with 0 errors".

Fixed: the cell now resolves `pilot/` relative to its location (works from any CWD).
Re-verified end-to-end.

## 2. Credential readiness — Steps 1–5 are blocked as follows

| Item | Status | Detail |
|---|---|---|
| `QTRUST_DEPLOYER_PRIVATE_KEY` | placeholder | It is the **anvil well-known key #0** (`0xac0974…ff80`). Useless on Base Sepolia (unfunded) and unsafe to reuse. `QTRUST_RELAYER_PRIVATE_KEY` is the same key. |
| `QTRUST_BASE_SEPOLIA_RPC` | placeholder | Points to `http://127.0.0.1:8545` (local anvil), not Alchemy. |
| `QTRUST_PINATA_API_KEY/_SECRET` | **missing** | SDK degrades gracefully (hash-only mode), but the demo line "pinned to IPFS" would be false without them. |
| `QTRUST_BASESCAN_API_KEY` | placeholder | Present but ≤8 chars; real keys are ~34 chars. |
| Contract addresses in `.env` | local-only | Deterministic anvil first-deploy addresses (`0x5FbD…`, `0xe7f1…`, …). Replace after Step 3. |
| `QTRUST_GOVERNANCE_ADDRESS` | missing | Step 3 says to add it; SDK reads it but tolerates absence. |

Conclusion: matches the playbook's own admission that only credential work remains — but note
that **none** of the five required secrets is real yet, despite three of five slots existing.

## 3. Step 4 (role grants) — corrections against contract source

| Playbook command | Verdict |
|---|---|
| Grant `ATTESTER_ROLE` on AssetRegistry | **Remove.** No such role exists; AssetRegistry uses `REGISTRAR_ROLE`, auto-granted to the deployer in the constructor (`AssetRegistry.sol:51-55`). The command would succeed but grant an unused role hash. |
| Grant `MIGRATOR_ROLE` on MigrationRegistry | Redundant — already granted in the constructor (`MigrationRegistry.sol:61`). Harmless; may drop. |
| Grant `VENDOR_ROLE` on VendorRegistry | **Keep.** Constructor grants only `VENDOR_ADMIN_ROLE`; `attestProduct` requires `VENDOR_ROLE` (`VendorRegistry.sol:270-276`). Deployer (admin) can self-grant. |
| Grant `AUDITOR_ROLE` on AuditRegistry | **Keep.** Constructor grants only `DEFAULT_ADMIN_ROLE`; `AUDITOR_ROLE` must be granted explicitly (`AuditRegistry.sol:51-59`). |

## 4. Doc/repo mismatches

1. **§8 vs `scripts/verify_all.sh`:** doc claims the verifier runs the 3-seed benchmark
   (`--seeds 42 43 44`); the script actually runs `--seeds 42 --epochs 10` (single fast seed).
   Align one or the other.
2. **Paths:** playbook commands use `/home/z/qtrust`; repo lives at `/home/nvidia/Project`.
3. **Demo script cell numbers:** notebook 01's qubit table/plot are around cells 3–4 and the
   Shor simulation around cell 8 — not "Cell 2/3/5". Reference by content when recording.
4. **Hardcoded phase stats in narration** ("Phase 1: 13 assets, avg_priority=0.845"): actual
   pilot output is a ranked list with per-asset criticality, and values differ every run.
   Don't read scripted numbers aloud; narrate the on-screen output.

## 5. What checked out true

- All verification claims reproduce locally (after the notebook fix).
- GNN honesty framing (§2, §6) is consistent with the benchmark module's mean±std reporting.
- Hash-only on-chain design means missing IPFS credentials degrade gracefully rather than break.
- `.env` is properly gitignored (verified via `git check-ignore`); no secrets tracked.

## 6. Minor notes

- `verify_all.sh` stage 1 greps for the literal string "49 tests passed" — brittle if the test
  count changes; consider matching "tests passed" or a count variable.
- Foundry warns "Failed to get git revision for dependency 'lib/forge-std' /
  'openzeppelin-contracts'" — vendored libs aren't git submodules here. Cosmetic; `forge install`
  would clean it up.
