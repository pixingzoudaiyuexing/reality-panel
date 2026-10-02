#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="$ROOT/scripts/release-version-contract.sh"
TAG="${1:-v1.4.2}"

bash "$CONTRACT" "$TAG"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
cp "$ROOT/crates/panel/Cargo.toml" "$tmp/panel.toml"
cp "$ROOT/crates/node/Cargo.toml" "$tmp/node.toml"
awk '
    !changed && /^version = ".*"$/ {
        print "version = \"1.0.0-rc.3\""
        changed = 1
        next
    }
    { print }
' "$tmp/panel.toml" > "$tmp/panel-mismatch.toml"

if PANEL_MANIFEST="$tmp/panel-mismatch.toml" NODE_MANIFEST="$tmp/node.toml" \
    bash "$CONTRACT" "$TAG" >"$tmp/mismatch.out" 2>&1; then
    printf '[FAIL] Mismatched package version unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'does not match tag' "$tmp/mismatch.out"

printf '[OK] Mismatched package version is rejected\n'

printf '## [%s] - Candidate\n## [%s.00] - Similar but distinct\n## [%s-rc.1] - Prerelease\n' \
    "${TAG#v}" "${TAG#v}" "${TAG#v}" > "$tmp/panel-changelog.md"
printf '## [%s] - Candidate\n' "${TAG#v}" > "$tmp/node-changelog.md"
PANEL_CHANGELOG="$tmp/panel-changelog.md" NODE_CHANGELOG="$tmp/node-changelog.md" \
    bash "$ROOT/scripts/release-check.sh" "${TAG#v}" >"$tmp/unique.out" 2>&1

printf '## [%s] - Duplicate\n' "${TAG#v}" >> "$tmp/panel-changelog.md"
if PANEL_CHANGELOG="$tmp/panel-changelog.md" NODE_CHANGELOG="$tmp/node-changelog.md" \
    bash "$ROOT/scripts/release-check.sh" "${TAG#v}" >"$tmp/panel-duplicate.out" 2>&1; then
    printf '[FAIL] Duplicate Panel release heading unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq "CHANGELOG.md must contain exactly one release heading for ${TAG#v} (found 2)" "$tmp/panel-duplicate.out"

# Restore the unique Panel heading so the next case isolates the Node changelog.
printf '## [%s] - Candidate\n' "${TAG#v}" > "$tmp/panel-changelog.md"
printf '## [%s] - Duplicate\n' "${TAG#v}" >> "$tmp/node-changelog.md"
if PANEL_CHANGELOG="$tmp/panel-changelog.md" NODE_CHANGELOG="$tmp/node-changelog.md" \
    bash "$ROOT/scripts/release-check.sh" "${TAG#v}" >"$tmp/node-duplicate.out" 2>&1; then
    printf '[FAIL] Duplicate Node release heading unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq "CHANGELOG-NODE.md must contain exactly one release heading for ${TAG#v} (found 2)" "$tmp/node-duplicate.out"

printf '[OK] Duplicate exact release headings are rejected; similar version headings remain distinct\n'
