#!/usr/bin/env bash
# Restart a fresh anvil chain, deploy the contracts, and run the SDK E2E test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANVIL_PORT="${ANVIL_PORT:-8545}"
ANVIL_BIN="${ANVIL_BIN:-$(command -v anvil)}"
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "==> Stopping any existing anvil on :${ANVIL_PORT}"
pkill -f "anvil.*--port ${ANVIL_PORT}" 2>/dev/null || true
sleep 1

echo "==> Starting fresh anvil (chain-id 84532)"
nohup "$ANVIL_BIN" --port "$ANVIL_PORT" --chain-id 84532 > /tmp/qtrust-anvil.log 2>&1 &
ANVIL_PID=$!
disown
sleep 2

trap 'kill "$ANVIL_PID" 2>/dev/null || true' EXIT

echo "==> Deploying contracts"
(cd "$ROOT/../contracts" && QTRUST_DEPLOYER_PRIVATE_KEY="$DEPLOYER_KEY" \
  forge script script/Deploy.s.sol --rpc-url "http://127.0.0.1:${ANVIL_PORT}" --broadcast > /dev/null)

echo "==> Extracting deployed addresses from broadcast"
ADDRS="$(python3 - "$ROOT/../contracts" <<'EOF'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
latest = root / "broadcast/Deploy.s.sol/84532/run-latest.json"
data = json.loads(latest.read_text())
for tx in data["transactions"]:
    name = tx.get("contractName", "")
    if name and tx.get("transactionType") == "CREATE":
        print(f"{name}={tx['contractAddress']}")
EOF
)"

echo "$ADDRS"
export QTRUST_ASSET_REGISTRY_ADDRESS="$(echo "$ADDRS" | awk -F= '/^AssetRegistry=/{print $2}')"
export QTRUST_VENDOR_REGISTRY_ADDRESS="$(echo "$ADDRS" | awk -F= '/^VendorRegistry=/{print $2}')"
export QTRUST_MIGRATION_REGISTRY_ADDRESS="$(echo "$ADDRS" | awk -F= '/^MigrationRegistry=/{print $2}')"
export QTRUST_AUDIT_REGISTRY_ADDRESS="$(echo "$ADDRS" | awk -F= '/^AuditRegistry=/{print $2}')"

echo "==> Running SDK E2E test"
python3 "$ROOT/tests/e2e_anvil.py"