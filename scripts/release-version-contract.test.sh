#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="$ROOT/scripts/release-version-contract.sh"
TAG="${1:-v$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/panel/Cargo.toml" | head -n1)}"

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

awk '!/^DEFAULT_RELEASE_TAG=/' "$ROOT/install.sh" > "$tmp/installer-absent.sh"
cp "$ROOT/install.sh" "$tmp/installer-duplicate.sh"
printf 'DEFAULT_RELEASE_TAG=""\n' >> "$tmp/installer-duplicate.sh"
sed 's/^DEFAULT_RELEASE_TAG=.*/DEFAULT_RELEASE_TAG="v0.0.1"/' "$ROOT/install.sh" > "$tmp/installer-pinned.sh"
for kind in absent duplicate pinned; do
    if INSTALLER_SOURCE="$tmp/installer-$kind.sh" bash "$ROOT/scripts/release-check.sh" "${TAG#v}" >"$tmp/marker-$kind.out" 2>&1; then
        printf '[FAIL] Invalid source installer marker passed: %s\n' "$kind" >&2
        exit 1
    fi
    grep -Fq 'source installer must contain exactly one empty DEFAULT_RELEASE_TAG marker' "$tmp/marker-$kind.out"
done
awk '!/sed -i .*DEFAULT_RELEASE_TAG/' "$ROOT/.github/workflows/binary-release.yml" > "$tmp/workflow-no-injection.yml"
awk '!/grep -Fxc.*RELEASE_TAG/' "$ROOT/.github/workflows/binary-release.yml" > "$tmp/workflow-no-verification.yml"
awk '!/grep -c.*DEFAULT_RELEASE_TAG/' "$ROOT/.github/workflows/binary-release.yml" > "$tmp/workflow-no-uniqueness.yml"
for kind in injection verification uniqueness; do
    if RELEASE_WORKFLOW="$tmp/workflow-no-$kind.yml" bash "$ROOT/scripts/release-check.sh" "${TAG#v}" >"$tmp/workflow-$kind.out" 2>&1; then
        printf '[FAIL] Incomplete workflow staging passed: %s\n' "$kind" >&2
        exit 1
    fi
    grep -Fq 'release workflow does not' "$tmp/workflow-$kind.out"
done
printf '[OK] Missing, duplicate or pinned source markers and incomplete workflow injection are rejected\n'
