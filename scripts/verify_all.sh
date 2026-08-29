#!/usr/bin/env bash
# Q-Trust full-stack verification. Run from the repo root.
# Verifies: contracts, SDK (unit + E2E), inspector, planner benchmark, backend,
# frontend, pilot, notebooks. Fails loudly on the first error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILED=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }

echo "==> [1/9] Contracts (forge build + test)"
(cd "$ROOT/contracts" && forge build > /dev/null && forge test 2>&1 | tail -1 | grep -q "tests passed") \
  && pass "forge build + all tests pass" || fail "contracts"

echo "==> [2/9] SDK unit tests"
(cd "$ROOT/sdk" && python -m pytest -q > /dev/null 2>&1) && pass "sdk pytest" || fail "sdk unit"

echo "==> [3/9] SDK E2E (fresh anvil + deploy)"
"$ROOT/sdk/tests/run_e2e.sh" 2>&1 | tail -1 | grep -q "ALL E2E CHECKS PASSED" \
  && pass "sdk E2E" || fail "sdk E2E"

echo "==> [4/9] Inspector tests"
(cd "$ROOT/inspector" && python -m pytest -q > /dev/null 2>&1) && pass "inspector pytest" || fail "inspector"

echo "==> [5/9] Planner benchmark (multi-seed, honest metrics)"
(cd "$ROOT/planner" && python -m qtrust_planner.benchmark --seeds 42 43 44 --epochs 10 \
  --out-dir /tmp/qtrust-bench-verify > /dev/null 2>&1) \
  && pass "planner benchmark" || fail "planner benchmark"

echo "==> [6/9] Backend build (tsc)"
(cd "$ROOT/backend" && npm run build > /dev/null 2>&1) && pass "backend build" || fail "backend build"

echo "==> [7/9] Frontend build (next)"
# A non-'demo' project ID makes wagmi happy even in production builds; CI
# uses the same all-zeros placeholder (0000...0000).
(cd "$ROOT/frontend" && NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID="00000000000000000000000000000000" \
  npm run build > /dev/null 2>&1) && pass "frontend build" || fail "frontend build"

echo "==> [8/9] Notebooks execute"
# Notebook location moved to research/notebooks per Blueprint §5.1 — handle both old and new paths
NB_DIR="$ROOT/notebooks"
if [ ! -d "$NB_DIR" ] && [ -d "$ROOT/research/notebooks" ]; then NB_DIR="$ROOT/research/notebooks"; fi
jupyter nbconvert --to notebook --execute "$NB_DIR/01_quantum_threat_demo.ipynb" --output /tmp/qtrust_nb1.ipynb > /dev/null 2>&1 \
  && pass "notebooks (01 quantum demo)" || fail "notebooks (01)"

echo "==> [9/9] Pilot + bank-pilot notebook (fresh anvil + deploy)"
setsid anvil --host 127.0.0.1 --port 8545 --chain-id 84532 > /tmp/qtrust-anvil-pilot.log 2>&1 < /dev/null &
ANVIL_PID=$!
sleep 3
DEPLOY_LOG=$(mktemp)
# QTRUST_DEV_GRANTEE grants the deployer (account 0, the pilot's default
# signing account) the REGISTRAR/operational roles, exactly as the SDK E2E
# does — otherwise the pilot cannot register the scanned CBOM on-chain.
(cd "$ROOT/contracts" && \
  QTRUST_DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
  QTRUST_DEV_GRANTEE="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" \
  forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast 2>&1 | tee "$DEPLOY_LOG")
export QTRUST_ASSET_REGISTRY_ADDRESS="$(grep 'AssetRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_VENDOR_REGISTRY_ADDRESS="$(grep 'VendorRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_MIGRATION_REGISTRY_ADDRESS="$(grep 'MigrationRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_AUDIT_REGISTRY_ADDRESS="$(grep 'AuditRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
# The pilot refuses to run without an explicit deployer key against local
# anvil; export it (plus the RPC) so the pilot subshell sees them.
export QTRUST_DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
rm -f "$DEPLOY_LOG"
(cd "$ROOT/pilot" && python run_pilot.py > /tmp/qtrust-pilot-debug.log 2>&1; \
  s=$?; tail -30 /tmp/qtrust-pilot-debug.log | grep -q "PILOT COMPLETE" && s=0; exit $s) \
  && pass "pilot" || fail "pilot"
jupyter nbconvert --to notebook --execute "$NB_DIR/08_bank_pilot.ipynb" --output /tmp/qtrust_nb8.ipynb > /dev/null 2>&1 \
  && pass "notebooks (08 bank pilot)" || fail "notebooks (08)"
kill "$ANVIL_PID" 2>/dev/null || true

echo "==> [bonus] Dependency audit (npm)"
(cd "$ROOT/backend" && npm audit --omit dev 2>&1 | tail -3) && pass "backend npm audit" || fail "backend npm audit"
(cd "$ROOT/frontend" && npm audit --omit dev 2>&1 | tail -3) && pass "frontend npm audit" || fail "frontend npm audit"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "ONE OR MORE CHECKS FAILED"
  exit 1
fi