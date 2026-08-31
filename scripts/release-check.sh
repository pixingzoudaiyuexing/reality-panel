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
bash "$ROOT/scripts/release-version-contract.sh" "v$VERSION"
[ "$panel_version" = "$VERSION" ] || fail "Panel version is $panel_version, expected $VERSION"
[ "$node_version" = "$VERSION" ] || fail "Node version is $node_version, expected $VERSION"
[ "$node_installer_version" = "$VERSION" ] || fail "Node installer version is $node_installer_version, expected $VERSION"
grep -Fq "## [$VERSION]" "$ROOT/CHANGELOG.md" || fail "Panel changelog has no $VERSION entry"
grep -Fq "## [$VERSION]" "$ROOT/CHANGELOG-NODE.md" || fail "Node changelog has no $VERSION entry"
grep -Fq "candidate is \`v$VERSION\`" "$ROOT/docs/VERSIONS.md" || \
    fail "docs/VERSIONS.md does not declare v$VERSION as the development candidate"
grep -q 'pixingzoudaiyuexing/reality-panel' "$ROOT/install.sh" || fail "installer repository is not Reality Panel"
grep -q "tags:" "$ROOT/.github/workflows/binary-release.yml" || fail "tag-only release workflow missing"
grep -q "cargo build --release --locked" "$ROOT/.github/workflows/binary-release.yml" || fail "release build is not locked"
grep -q 'reality-panel-linux-amd64' "$ROOT/.github/workflows/binary-release.yml" || fail "Panel asset missing"
grep -q 'reality-node-linux-amd64' "$ROOT/.github/workflows/binary-release.yml" || fail "Node asset missing"
grep -q 'SHA256SUMS' "$ROOT/.github/workflows/binary-release.yml" || fail "checksum manifest missing"
grep -q 'container: rust:1.96-bookworm' "$ROOT/.github/workflows/binary-release.yml" || fail "release binaries are not built on Debian 12"
grep -A2 -q 'defaults:' "$ROOT/.github/workflows/binary-release.yml" || fail "release job has no explicit run shell"
grep -q 'shell: bash' "$ROOT/.github/workflows/binary-release.yml" || fail "release job does not use Bash"
grep -q 'releases/download' "$ROOT/install.sh" || fail "installer is not Release-only"
grep -q 'PUBLIC_PANEL_URL' "$ROOT/install.sh" || fail "PUBLIC_PANEL_URL contract missing"
grep -Fq 'install -m 0755 "$release_dir/update.sh" "$SCRIPT_ROOT/update.sh"' "$ROOT/deploy.sh" || \
    fail "first install does not install the updater"
grep -Fq 'ln -sfn "$SCRIPT_ROOT/update.sh" "$UPDATE_COMMAND"' "$ROOT/deploy.sh" || \
    fail "reality-panel-update command is not installed"
grep -Fq 'exec "$installer" update "$@"' "$ROOT/update.sh" || \
    fail "updater does not preserve default and explicit-tag arguments"
grep -Fq 'releases/latest' "$ROOT/install.sh" || fail "default updater is not stable-Release-only"
grep -q 'ASSET_NAME="reality-node-linux-${ARCH}"' "$ROOT/scripts/relay-node-install.sh" || fail "legacy Node installer asset name is stale"
grep -q '/SHA256SUMS"' "$ROOT/scripts/relay-node-install.sh" || fail "legacy Node installer does not use the unified checksum manifest"
public_docs=("$ROOT"/README*.md "$ROOT"/CHANGELOG*.md "$ROOT"/docs/*.md)
if grep -Ein 'V2Board|v2node|wyx2685/v2board|wyx2685/v2node' "${public_docs[@]}"; then
    fail "public documentation names a product-specific Reality backend"
fi
for script in install.sh deploy.sh update.sh scripts/relay-node-install.sh \
    scripts/release-version-contract.sh scripts/release-version-contract.test.sh; do
    bash -n "$ROOT/$script" || fail "shell syntax failed: $script"
done
ok "Reality Panel $VERSION release contract is ready"
