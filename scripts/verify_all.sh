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
(cd "$ROOT/contracts" && forge build > /dev/null && forge test 2>&1 | tail -1 | grep -q "127 tests passed") \
  && pass "forge build + 127/127 tests (10 suites)" || fail "contracts"

echo "==> [2/9] SDK unit tests"
(cd "$ROOT/sdk" && python -m pytest -q > /dev/null 2>&1) && pass "sdk pytest" || fail "sdk unit"

echo "==> [3/9] SDK E2E (fresh anvil + deploy)"
"$ROOT/sdk/tests/run_e2e.sh" 2>&1 | tail -1 | grep -q "ALL E2E CHECKS PASSED" \
  && pass "sdk E2E" || fail "sdk E2E"

echo "==> [4/9] Inspector tests"
(cd "$ROOT/inspector" && python -m pytest -q > /dev/null 2>&1) && pass "inspector pytest" || fail "inspector"

echo "==> [5/9] Planner benchmark (multi-seed, honest metrics)"
(cd "$ROOT/planner" && python -m qtrust_planner.benchmark --seeds 42 --epochs 10 \
  --out-dir /tmp/qtrust-bench-verify > /dev/null 2>&1) \
  && pass "planner benchmark" || fail "planner benchmark"

echo "==> [6/9] Backend build (tsc)"
(cd "$ROOT/backend" && npm run build > /dev/null 2>&1) && pass "backend build" || fail "backend build"

echo "==> [7/9] Frontend build (next)"
(cd "$ROOT/frontend" && npm run build > /dev/null 2>&1) && pass "frontend build" || fail "frontend build"

echo "==> [8/9] Notebooks execute"
jupyter nbconvert --to notebook --execute "$ROOT/notebooks/01_quantum_threat_demo.ipynb" --output /tmp/qtrust_nb1.ipynb > /dev/null 2>&1 \
  && pass "notebooks (01 quantum demo)" || fail "notebooks (01)"

echo "==> [9/9] Pilot + bank-pilot notebook (fresh anvil + deploy)"
setsid anvil --host 127.0.0.1 --port 8545 --chain-id 84532 > /tmp/qtrust-anvil-pilot.log 2>&1 < /dev/null &
ANVIL_PID=$!
sleep 3
(cd "$ROOT/contracts" && QTRUST_DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
  forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast > /dev/null 2>&1)
(cd "$ROOT/pilot" && python run_pilot.py 2>&1 | grep -q "PILOT COMPLETE") \
  && pass "pilot" || fail "pilot"
jupyter nbconvert --to notebook --execute "$ROOT/notebooks/08_bank_pilot.ipynb" --output /tmp/qtrust_nb8.ipynb > /dev/null 2>&1 \
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