#!/usr/bin/env bash
# Static pre-tag contract for the unified Reality Panel release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
ok() { printf '[OK] %s\n' "$*"; }

[ -n "$VERSION" ] || { echo "Usage: $0 X.Y.Z[-pre]" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "invalid semver: $VERSION"

panel_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/panel/Cargo.toml" | head -n1)"
node_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/node/Cargo.toml" | head -n1)"
node_installer_version="$(sed -n 's/^SCRIPT_VERSION="\(.*\)"/\1/p' "$ROOT/scripts/relay-node-install.sh" | head -n1)"
[ "$panel_version" = "$VERSION" ] || fail "Panel version is $panel_version, expected $VERSION"
[ "$node_version" = "$VERSION" ] || fail "Node version is $node_version, expected $VERSION"
[ "$node_installer_version" = "$VERSION" ] || fail "Node installer version is $node_installer_version, expected $VERSION"
grep -q 'pixingzoudaiyuexing/reality-panel' "$ROOT/install.sh" || fail "installer repository is not Reality Panel"
grep -q "tags:" "$ROOT/.github/workflows/binary-release.yml" || fail "tag-only release workflow missing"
grep -q "cargo build --release --locked" "$ROOT/.github/workflows/binary-release.yml" || fail "release build is not locked"
grep -q 'reality-panel-linux-amd64' "$ROOT/.github/workflows/binary-release.yml" || fail "Panel asset missing"
grep -q 'reality-node-linux-amd64' "$ROOT/.github/workflows/binary-release.yml" || fail "Node asset missing"
grep -q 'SHA256SUMS' "$ROOT/.github/workflows/binary-release.yml" || fail "checksum manifest missing"
grep -q 'container: rust:1.96-bookworm' "$ROOT/.github/workflows/binary-release.yml" || fail "release binaries are not built on Debian 12"
grep -q 'releases/download' "$ROOT/install.sh" || fail "installer is not Release-only"
grep -q 'PUBLIC_PANEL_URL' "$ROOT/install.sh" || fail "PUBLIC_PANEL_URL contract missing"
grep -q 'ASSET_NAME="reality-node-linux-${ARCH}"' "$ROOT/scripts/relay-node-install.sh" || fail "legacy Node installer asset name is stale"
grep -q '/SHA256SUMS"' "$ROOT/scripts/relay-node-install.sh" || fail "legacy Node installer does not use the unified checksum manifest"
for script in install.sh deploy.sh update.sh scripts/relay-node-install.sh; do
    bash -n "$ROOT/$script" || fail "shell syntax failed: $script"
done
ok "Reality Panel $VERSION release contract is ready"
