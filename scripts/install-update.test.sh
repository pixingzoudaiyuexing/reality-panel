#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
FAKE="$TMP/bin"
CURL_LOG="$TMP/curl.log"
mkdir -p "$FAKE"

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

cat > "$TMP/os-release" <<'EOF'
ID=debian
VERSION_ID="12"
VERSION="12 (bookworm)"
EOF
cat > "$FAKE/id" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = -u ] && printf '0\n'
EOF
cat > "$FAKE/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in -s) printf 'Linux\n' ;; -m) printf 'x86_64\n' ;; esac
EOF
cat > "$FAKE/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$FAKE/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$FAKE/ss" <<'EOF'
#!/usr/bin/env bash
if [ -n "${FAKE_OCCUPIED_PORT:-}" ] && [[ "$*" == *":$FAKE_OCCUPIED_PORT"* ]]; then
    printf 'LISTEN 0 4096 0.0.0.0:%s 0.0.0.0:*\n' "$FAKE_OCCUPIED_PORT"
fi
EOF
cat > "$FAKE/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CURL_LOG"
case "$*" in
    *https://github.com/pixingzoudaiyuexing/reality-panel/releases/latest*)
        printf 'https://github.com/pixingzoudaiyuexing/reality-panel/releases/tag/%s' "${FAKE_LATEST_TAG:-v1.0.0}"
        ;;
    *https://api.ipify.org*)
        [ "${FAKE_IPIFY_FAIL:-0}" != 1 ] || exit 22
        printf '%s' "${FAKE_PUBLIC_IP:-203.0.113.10}"
        ;;
    *)
        printf 'unexpected curl request: %s\n' "$*" >&2
        exit 1
        ;;
esac
EOF
chmod +x "$FAKE"/*

parse() {
    : > "$CURL_LOG"
    env \
        PATH="$FAKE:$PATH" \
        REALITY_PANEL_OS_RELEASE_FILE="$TMP/os-release" \
        REALITY_PANEL_TEST_PARSE_ONLY=1 \
        CURL_LOG="$CURL_LOG" \
        FAKE_LATEST_TAG="${FAKE_LATEST_TAG:-}" \
        FAKE_PUBLIC_IP="${FAKE_PUBLIC_IP:-}" \
        FAKE_IPIFY_FAIL="${FAKE_IPIFY_FAIL:-0}" \
        FAKE_OCCUPIED_PORT="${FAKE_OCCUPIED_PORT:-}" \
        TARGET_VERSION="${TEST_TARGET_VERSION:-}" \
        bash "${TEST_ENTRYPOINT:-$ROOT/install.sh}" "$@"
}

out="$(FAKE_LATEST_TAG=v1.0.0 FAKE_PUBLIC_IP=203.0.113.10 parse)"
grep -Fqx 'command=install' <<< "$out"
grep -Fqx 'target_version=v1.0.0' <<< "$out"
grep -Fqx 'panel_port=18888' <<< "$out"
grep -Fqx 'public_url=http://203.0.113.10:18888' <<< "$out"
[ "$(grep -Fc '/releases/latest' "$CURL_LOG")" = 1 ] || fail "default install did not resolve latest exactly once"
[ "$(grep -Fc 'https://api.ipify.org' "$CURL_LOG")" = 1 ] || fail "default install did not query ipify exactly once"

out="$(FAKE_PUBLIC_IP=203.0.113.11 parse v1.1.0-rc.1)"
grep -Fqx 'command=install' <<< "$out"
grep -Fqx 'target_version=v1.1.0-rc.1' <<< "$out"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "exact RC unexpectedly resolved latest"

out="$(FAKE_PUBLIC_IP=203.0.113.12 parse v1.0.0)"
grep -Fqx 'target_version=v1.0.0' <<< "$out"

out="$(parse install --version v1.0.0 --public-panel-url http://203.0.113.13:18888)"
grep -Fqx 'target_version=v1.0.0' <<< "$out"
grep -Fqx 'public_url=http://203.0.113.13:18888' <<< "$out"

out="$(FAKE_PUBLIC_IP=203.0.113.14 parse --port 28888)"
grep -Fqx 'panel_port=28888' <<< "$out"
grep -Fqx 'public_url=http://203.0.113.14:28888' <<< "$out"

out="$(parse --port 28888 --public-panel-url https://panel.example.com)"
grep -Fqx 'public_url=https://panel.example.com' <<< "$out"
! grep -Fq 'https://api.ipify.org' "$CURL_LOG" || fail "explicit PUBLIC_PANEL_URL still queried ipify"

if FAKE_IPIFY_FAIL=1 parse v1.0.0 >"$TMP/ip-fail.out" 2>"$TMP/ip-fail.err"; then
    fail "ipify failure unexpectedly succeeded"
fi
grep -Fq 'Unable to automatically obtain the public IPv4' "$TMP/ip-fail.err"
! grep -Fq '/releases/download/' "$CURL_LOG" || fail "ipify failure continued to release downloads"

if FAKE_PUBLIC_IP=not-an-ip parse v1.0.0 >"$TMP/ip-invalid.out" 2>"$TMP/ip-invalid.err"; then
    fail "invalid public IPv4 unexpectedly succeeded"
fi
grep -Fq 'Unable to automatically obtain a valid public IPv4' "$TMP/ip-invalid.err"

if FAKE_OCCUPIED_PORT=18888 parse v1.0.0 --public-panel-url http://203.0.113.10:18888 \
    >"$TMP/port.out" 2>"$TMP/port.err"; then
    fail "occupied port unexpectedly succeeded"
fi
grep -Fq 'Panel port 18888 is already in use' "$TMP/port.err"
grep -Fq -- '--port <PORT>' "$TMP/port.err"
! grep -Fq '18889' "$TMP/port.err" || fail "occupied-port failure suggested a next port"

out="$(FAKE_LATEST_TAG=v1.0.0 parse update --public-panel-url http://203.0.113.10:18888)"
grep -Fqx 'command=update' <<< "$out"
grep -Fqx 'target_version=v1.0.0' <<< "$out"

out="$(parse update v1.0.0-rc.6 --public-panel-url http://203.0.113.10:18888)"
grep -Fqx 'target_version=v1.0.0-rc.6' <<< "$out"
out="$(parse update --version v1.0.0-rc.6 --public-panel-url http://203.0.113.10:18888)"
grep -Fqx 'target_version=v1.0.0-rc.6' <<< "$out"

if FAKE_LATEST_TAG=v1.1.0-rc.1 parse --public-panel-url http://203.0.113.10:18888 \
    >"$TMP/prerelease.out" 2>"$TMP/prerelease.err"; then
    fail "latest endpoint prerelease unexpectedly succeeded"
fi
grep -Fq 'did not resolve to a stable vX.Y.Z tag' "$TMP/prerelease.err"

: > "$CURL_LOG"
if env \
    PATH="$FAKE:$PATH" \
    REALITY_PANEL_OS_RELEASE_FILE="$TMP/os-release" \
    CURL_LOG="$CURL_LOG" \
    PUBLIC_PANEL_URL=http://203.0.113.10:18888 \
    bash "$ROOT/install.sh" v9.9.9 >"$TMP/missing.out" 2>"$TMP/missing.err"; then
    fail "missing exact release unexpectedly succeeded"
fi
grep -Fq 'Unable to download SHA256SUMS for exact release v9.9.9' "$TMP/missing.err"
grep -Fq '/releases/download/v9.9.9/SHA256SUMS' "$CURL_LOG"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "missing exact release fell back to latest"

grep -Fq 'base="https://github.com/$REPOSITORY/releases/download/$target_version"' "$ROOT/install.sh"
grep -Fq 'assets=(reality-panel-linux-amd64 reality-node-linux-amd64 reality-panel-web.tar.gz install.sh update.sh deploy.sh)' "$ROOT/install.sh"
grep -Fq 'SHA256 mismatch for $asset' "$ROOT/install.sh"
if rg -n 'target_version="\$\{VERSION' "$ROOT/install.sh"; then
    fail "target version still reads generic VERSION"
fi
grep -Fq 'ca-certificates certbot curl file iproute2 openssl sqlite3 tar' "$ROOT/install.sh"
grep -Fq 'install -d -o relay-panel -g relay-panel -m 0700 "$DATA_ROOT/certificates"' "$ROOT/deploy.sh"
grep -Fq 'PANEL_CERTIFICATE_STATE_DIR=$DATA_ROOT/certificates' "$ROOT/deploy.sh"
grep -Fq 'PANEL_CERTBOT_BINARY_PATH=/usr/bin/certbot' "$ROOT/deploy.sh"
grep -Fq 'PANEL_CERTIFICATE_CHECK_INTERVAL_SECS=60' "$ROOT/deploy.sh"

grep -Fqx 'DEFAULT_RELEASE_TAG=""' "$ROOT/install.sh" || fail "source installer has no empty release marker"
staged="${STAGED_INSTALLER_UNDER_TEST:-$TMP/staged-install.sh}"
if [ -z "${STAGED_INSTALLER_UNDER_TEST:-}" ]; then
    sed 's/^DEFAULT_RELEASE_TAG=.*/DEFAULT_RELEASE_TAG="v1.4.0"/' "$ROOT/install.sh" > "$staged"
    chmod +x "$staged"
fi
[ "$(grep -Fxc 'DEFAULT_RELEASE_TAG="v1.4.0"' "$staged")" = 1 ] || fail "staged installer marker is not exactly v1.4.0"

out="$(TEST_ENTRYPOINT="$staged" parse --public-panel-url https://panel.example.com)"
grep -Fqx 'command=install' <<< "$out"
grep -Fqx 'target_version=v1.4.0' <<< "$out"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "bundled default queried latest"
out="$(TEST_ENTRYPOINT="$staged" parse install --public-panel-url https://panel.example.com)"
grep -Fqx 'target_version=v1.4.0' <<< "$out"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "bundled install queried latest"

out="$(TEST_ENTRYPOINT="$staged" FAKE_LATEST_TAG=v1.5.0 parse update --public-panel-url https://panel.example.com)"
grep -Fqx 'target_version=v1.5.0' <<< "$out"
[ "$(grep -Fc '/releases/latest' "$CURL_LOG")" = 1 ] || fail "bundled updater was pinned"

for args in 'v1.2.3' 'install v1.2.3' 'install --version v1.2.3' 'update v1.2.3' 'update --version v1.2.3'; do
    # Each form must override both the environment and the bundled default.
    read -r -a version_args <<< "$args"
    out="$(TEST_ENTRYPOINT="$staged" TEST_TARGET_VERSION=v1.2.7 parse "${version_args[@]}" --public-panel-url https://panel.example.com)"
    grep -Fqx 'target_version=v1.2.3' <<< "$out" || fail "CLI did not override environment: $args"
    ! grep -Fq '/releases/latest' "$CURL_LOG" || fail "explicit version queried latest: $args"
done
for mode in install update; do
    out="$(TEST_ENTRYPOINT="$staged" TEST_TARGET_VERSION=v1.2.7 parse "$mode" --public-panel-url https://panel.example.com)"
    grep -Fqx 'target_version=v1.2.7' <<< "$out" || fail "environment lost to bundled default: $mode"
    ! grep -Fq '/releases/latest' "$CURL_LOG" || fail "environment version queried latest: $mode"
done

for invalid in not-a-tag '' 'v1.4.0;echo'; do
    if TEST_ENTRYPOINT="$staged" parse install --version "$invalid" --public-panel-url https://panel.example.com >"$TMP/invalid.out" 2>&1; then
        fail "invalid explicit version succeeded"
    fi
    ! grep -Fq '/releases/latest' "$CURL_LOG" || fail "invalid explicit version fell back to latest"
done
out="$(TEST_ENTRYPOINT="$staged" TEST_TARGET_VERSION=invalid parse --version v1.2.3 --public-panel-url https://panel.example.com)"
grep -Fqx 'target_version=v1.2.3' <<< "$out"

# Exercise the installed updater wrapper with only its filesystem path redirected.
sed "s#installer=\"/usr/local/lib/reality-panel/install.sh\"#installer=\"$staged\"#" "$ROOT/update.sh" > "$TMP/installed-update.sh"
out="$(TEST_ENTRYPOINT="$TMP/installed-update.sh" FAKE_LATEST_TAG=v1.5.0 parse --public-panel-url https://panel.example.com)"
grep -Fqx 'command=update' <<< "$out"
grep -Fqx 'target_version=v1.5.0' <<< "$out"
[ "$(grep -Fc '/releases/latest' "$CURL_LOG")" = 1 ] || fail "installed updater was pinned"
out="$(TEST_ENTRYPOINT="$TMP/installed-update.sh" parse v1.4.0 --public-panel-url https://panel.example.com)"
grep -Fqx 'target_version=v1.4.0' <<< "$out"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "explicit installed update queried latest"

: > "$CURL_LOG"
if env PATH="$FAKE:$PATH" REALITY_PANEL_OS_RELEASE_FILE="$TMP/os-release" CURL_LOG="$CURL_LOG" \
    TARGET_VERSION="" PUBLIC_PANEL_URL=https://panel.example.com \
    bash "$staged" >"$TMP/staged-missing.out" 2>"$TMP/staged-missing.err"; then
    fail "missing bundled exact release unexpectedly succeeded"
fi
grep -Fq 'Unable to download SHA256SUMS for exact release v1.4.0' "$TMP/staged-missing.err"
! grep -Fq '/releases/latest' "$CURL_LOG" || fail "missing bundled release fell back to latest"
grep -Fqx 'DEFAULT_RELEASE_TAG=""' "$ROOT/install.sh" || fail "test staging mutated source installer"

printf 'bundled install / latest updater / CLI-environment precedence contract: PASS\n'
printf 'installer entrypoint contract: PASS\n'
