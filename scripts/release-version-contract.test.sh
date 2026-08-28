#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="$ROOT/scripts/release-version-contract.sh"
TAG="${1:-v1.0.0-rc.4}"

bash "$CONTRACT" "$TAG"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
cp "$ROOT/crates/panel/Cargo.toml" "$tmp/panel.toml"
cp "$ROOT/crates/node/Cargo.toml" "$tmp/node.toml"
sed 's/^version = "1\.0\.0-rc\.4"$/version = "1.0.0-rc.3"/' \
    "$tmp/panel.toml" > "$tmp/panel-mismatch.toml"

if PANEL_MANIFEST="$tmp/panel-mismatch.toml" NODE_MANIFEST="$tmp/node.toml" \
    bash "$CONTRACT" "$TAG" >"$tmp/mismatch.out" 2>&1; then
    printf '[FAIL] Mismatched package version unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'does not match tag' "$tmp/mismatch.out"

printf '[OK] Mismatched package version is rejected\n'
