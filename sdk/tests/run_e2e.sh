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
DEPLOY_LOG=$(mktemp)
# Dev/E2E grantees: the deployer + the E2E auditor account receive the
# operational roles (QTRUST_DEV_GRANTEE) in addition to the timelock, so the
# SDK E2E can exercise register/attest/migrate/audit against a hardened
# deployment (all roles otherwise live exclusively on the timelock).
AUDITOR_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
DEPLOYER_ADDR="$(cast wallet address --private-key "$DEPLOYER_KEY")"
AUDITOR_ADDR="$(cast wallet address --private-key "$AUDITOR_KEY")"
(cd "$ROOT/../contracts" && QTRUST_DEPLOYER_PRIVATE_KEY="$DEPLOYER_KEY" \
  QTRUST_DEV_GRANTEE="$DEPLOYER_ADDR,$AUDITOR_ADDR" \
  forge script script/Deploy.s.sol --rpc-url "http://127.0.0.1:${ANVIL_PORT}" --broadcast 2>&1 | tee "$DEPLOY_LOG")

echo "==> Extracting proxy addresses from deploy output"
export QTRUST_ASSET_REGISTRY_ADDRESS="$(grep 'AssetRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_VENDOR_REGISTRY_ADDRESS="$(grep 'VendorRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_MIGRATION_REGISTRY_ADDRESS="$(grep 'MigrationRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
export QTRUST_AUDIT_REGISTRY_ADDRESS="$(grep 'AuditRegistry proxy:' "$DEPLOY_LOG" | awk '{print $NF}')"
rm -f "$DEPLOY_LOG"

echo "  AssetRegistry:       $QTRUST_ASSET_REGISTRY_ADDRESS"
echo "  VendorRegistry:      $QTRUST_VENDOR_REGISTRY_ADDRESS"
echo "  MigrationRegistry:   $QTRUST_MIGRATION_REGISTRY_ADDRESS"
echo "  AuditRegistry:       $QTRUST_AUDIT_REGISTRY_ADDRESS"

echo "==> Running SDK E2E test"
python3 "$ROOT/tests/e2e_anvil.py"
