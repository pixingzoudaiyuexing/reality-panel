#!/usr/bin/env bash
# Validates that a release tag matches both package manifests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-}"
PANEL_MANIFEST="${PANEL_MANIFEST:-$ROOT/crates/panel/Cargo.toml}"
NODE_MANIFEST="${NODE_MANIFEST:-$ROOT/crates/node/Cargo.toml}"

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

[ -n "$TAG" ] || fail "Usage: $0 vX.Y.Z[-pre]"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || \
    fail "Invalid release tag: $TAG"

version="${TAG#v}"
panel_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$PANEL_MANIFEST" | head -n1)"
node_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$NODE_MANIFEST" | head -n1)"

[ "$panel_version" = "$version" ] || \
    fail "Panel package version $panel_version does not match tag $TAG"
[ "$node_version" = "$version" ] || \
    fail "Node package version $node_version does not match tag $TAG"

printf '[OK] Release tag %s matches Panel and Node package versions\n' "$TAG"
