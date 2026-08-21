# Q-Trust Demo Video — Run of Show

> Target runtime: 4:30. Record with OBS Studio (1920x1080, 60fps) or Loom.
> Terminal font >= 18pt, browser zoom 125%. Do one full dry run before recording.
> Record each scene as a separate clip; stitch if a take fails.

## Pre-flight (before hitting record)

1. `source .env` equivalents loaded in the terminal shell (local anvil demo: nothing else needed).
2. Fresh anvil + contracts deployed:
   ```bash
   anvil --host 127.0.0.1 --port 8545 --chain-id 84532 &
   cd contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
   ```
3. Tabs pre-opened: Basescan (sepolia.basescan.org or localhost anvil equivalent), Jupyter (`notebooks/01_quantum_threat_demo.ipynb`), frontend `/v/<asset_id>` page (or dashboard fallback).
4. **Network caveat:** STEP 1 falls back to a synthetic bank CBOM if the live scan finds nothing
   ("No findings from network scan — using synthetic bank CBOM for the demo."). If recording offline,
   narrate the synthetic path; do not claim a live scan happened.

---

## Scene 1 — Scan (0:00–0:40)

**Action:** run `python pilot/run_pilot.py` from repo root.

**Narrate:** "We scan a real TLS endpoint and discover its cryptographic assets — key algorithms,
sizes, vendors. The scan produces a CBOM, a Cryptographic Bill of Materials."

**Wait for / point at:**
- `STEP 1: Scan ... for cryptographic assets`
- `Findings: N | by_algorithm: {...}` line
- If fallback fired, say "pre-collected bank inventory" instead of "live scan".

## Scene 2 — On-chain registration (0:40–1:40)

**Action:** keep the same terminal output on screen.

**Point at:**
- `STEP 2` block: `Asset ID`, `CBOM hash`
- `Metadata: ipfs://...` — or `(no IPFS configured — hash-only)` if Pinata keys are absent;
  in that case say "only the hash goes on-chain", which is true either way.

**Narrate:** "Only the SHA-256 hash of the CBOM is written to the chain. The full document stays
off-chain. Anyone can later prove this exact CBOM existed at this point in time, without trusting
Q-Trust as a company."

**Optional cutaway:** explorer showing the registration tx (Basescan when live; skip on anvil).

## Scene 3 — Quantum threat (1:40–3:10)

**Action:** switch to `notebooks/01_quantum_threat_demo.ipynb`, Run All.

**Point at (by content, not cell number):**
- The qubit-estimate table: RSA-2048 → ~2M logical / ~2B physical qubits at 1000:1 overhead,
  with the projected breakable-by year.
- The qubits-vs-key-size plot.
- The Shor simulation cell factoring N=15 (runs only if qiskit is installed; if not available,
  show the printed table and say the simulation is in the repo).

**Narrate:** "Shor's algorithm is real and works today on toy numbers. Hardware roadmaps put
RSA-2048 at risk in the 2030s. 'Harvest now, decrypt later' means traffic captured today is
already exposed."

## Scene 4 — Migration plan (3:10–4:10)

**Action:** back to the pilot terminal output.

**Point at:**
- `STEP 4` ranked list: rank, algorithm, criticality per asset.
- `Assets ranked: N | model accuracy: X.XXX`

**Narrate:** "The planner orders migration by learned criticality over the dependency graph —
HSM firmware and code-signing keys first, leaf TLS certs later. Output is a phased plan with
per-asset priority." (Do NOT read specific phase numbers from any script — they differ per run.)

**Honesty note if asked:** model accuracy shown is Kendall tau against the heuristic label source
on synthetic graphs; real-world evaluation is future work.

## Scene 5 — Attestation + public verification (4:10–5:00)

**Point at:**
- `STEP 5`: attestation id, migration id + `verified on-chain: True`, audit record.
- `STEP 6`: `verifyAsset -> exists=True active=True`.

**If frontend is deployed:** open `https://<app>/v/<asset_id>` — CBOM summary, asset graph,
migration record. Otherwise show the STEP 6 verification block as the stand-in.

**Narrate:** "A regulator or auditor replays verification against their own node. OMB M-23-02
compliance becomes provable, not self-attested."

---

## Post-production checklist

- [ ] Total under 5 minutes
- [ ] No private keys, seed phrases, or `.env` values visible anywhere (blur terminal title bars)
- [ ] No unreproducible claims (no "tau 0.924"-style numbers; use the on-screen model accuracy)
- [ ] Upload unlisted to YouTube; add link to README
