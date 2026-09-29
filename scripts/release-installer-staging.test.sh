#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

# Run the actual workflow commands between installer-copy and SOURCE_COMMIT.
awk '
    /^          cp install.sh deploy.sh update.sh scripts\/relay-node-install.sh release-dist\/$/ { capture = 1; next }
    capture && /^          printf .*GITHUB_SHA.*release-dist\/SOURCE_COMMIT$/ { exit }
    capture { sub(/^          /, ""); print }
' "$ROOT/.github/workflows/binary-release.yml" > "$TMP/inject.sh"
[ -s "$TMP/inject.sh" ] || fail "workflow installer staging commands were not found"
mkdir "$TMP/release-dist"

stage() {
    (cd "$TMP" && PATH="${STAGING_PATH:-$PATH}" RELEASE_TAG=v1.4.0 bash -euo pipefail inject.sh)
}

printf '#!/bin/sh\n' > "$TMP/release-dist/install.sh"
if stage >"$TMP/absent.log" 2>&1; then
    fail "workflow silently accepted an absent marker"
fi
printf 'DEFAULT_RELEASE_TAG=""\nDEFAULT_RELEASE_TAG=""\n' > "$TMP/release-dist/install.sh"
if stage >"$TMP/duplicate.log" 2>&1; then
    fail "workflow accepted duplicate markers"
fi
printf 'DEFAULT_RELEASE_TAG="v1.3.0"\n' > "$TMP/release-dist/install.sh"
if stage >"$TMP/prepinned.log" 2>&1; then
    fail "workflow accepted a non-source marker"
fi
mkdir "$TMP/fake-bin"
printf '#!/bin/sh\nexit 0\n' > "$TMP/fake-bin/sed"
chmod +x "$TMP/fake-bin/sed"
printf 'DEFAULT_RELEASE_TAG=""\n' > "$TMP/release-dist/install.sh"
if STAGING_PATH="$TMP/fake-bin:$PATH" stage >"$TMP/noop.log" 2>&1; then
    fail "workflow accepted a successful but ineffective sed"
fi
printf '#!/bin/sh\nDEFAULT_RELEASE_TAG=""\n' > "$TMP/release-dist/install.sh"
stage
[ "$(grep -Fxc 'DEFAULT_RELEASE_TAG="v1.4.0"' "$TMP/release-dist/install.sh")" = 1 ] || fail "workflow did not inject the exact release tag"
[ "$(grep -c '^DEFAULT_RELEASE_TAG=' "$TMP/release-dist/install.sh")" = 1 ] || fail "workflow produced duplicate assignments"
printf 'release installer staging contract: PASS (absent, duplicate, prepinned, no-op rejected; exact tag injected)\n'
