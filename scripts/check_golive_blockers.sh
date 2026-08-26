#!/usr/bin/env bash
# Go-live preflight (audit §18/§22.8): the repository must not carry
# placeholder operational content into production deployments.
#
# Fails when known placeholders are still present outside historical/docs
# contexts. Maintainers replace the values; this script makes forgetting
# impossible.
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL=0

check() {
    local pattern="$1"
    local label="$2"
    local hits
    hits=$(git grep -n "$pattern" -- \
        ':(exclude)scripts/**' \
        ':(exclude).github/**' \
        ':(exclude)docs/QTrust_Implementation_Guide.md' \
        ':(exclude)*Audit*' || true)
    if [ -n "$hits" ]; then
        echo "::error::$label placeholder(s) still present:"
        echo "$hits"
        FAIL=1
    else
        echo "OK: no $label placeholders"
    fi
}

check '_PLACEHOLDER_' 'incident-response escalation'
check 'security@q-trust.example' 'SECURITY.md contact'

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "Go-live preflight passed."
