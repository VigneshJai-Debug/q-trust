#!/usr/bin/env bash
# Audit remediation: integrity check for the tracked .pt model checkpoints.
#
# The repo ships trained checkpoints as binary blobs. Without a manifest a
# supply-chain swap is undetectable; with models.sha256 (and this script wired
# into CI) any modification to a committed checkpoint fails the build.
#
# Usage:
#   scripts/verify_models.sh          # verify against models.sha256
#   scripts/verify_models.sh --update # regenerate models.sha256 (maintainers)
set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="models.sha256"

if [[ "${1:-}" == "--update" ]]; then
    git ls-files | grep '\.pt$' | xargs sha256sum > "$MANIFEST"
    echo "Regenerated $MANIFEST:"
    cat "$MANIFEST"
    exit 0
fi

if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: $MANIFEST not found — run scripts/verify_models.sh --update" >&2
    exit 1
fi

# sha256sum -c needs paths relative to CWD; the manifest already uses
# repo-relative paths.
sha256sum --check --quiet "$MANIFEST"
echo "OK: all $(grep -c . "$MANIFEST") model checkpoints match $MANIFEST"
