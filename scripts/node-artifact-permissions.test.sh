#!/usr/bin/env bash
# Linux contract for fresh install and same-version artifact refresh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
ok() { printf '[OK] %s\n' "$*"; }

[ "$(uname -s)" = "Linux" ] || fail "Linux filesystem semantics are required"
[ "$(id -u)" -eq 0 ] || fail "run this contract as root"
command -v runuser >/dev/null 2>&1 || fail "runuser is required"
command -v sqlite3 >/dev/null 2>&1 || fail "sqlite3 is required"

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
chmod 0755 "$TMP"

INSTALL_ROOT="$TMP/opt/relay-panel"
CONFIG_ROOT="$TMP/etc/relay-panel"
DATA_ROOT="$TMP/var/lib/relay-panel"
SCRIPT_ROOT="$TMP/usr/local/lib/reality-panel"
SERVICE_FILE="$TMP/etc/systemd/system/relay-panel.service"
UPDATE_COMMAND="$TMP/usr/local/sbin/reality-panel-update"
RELEASE_DIR="$TMP/release"
FAKE_BIN="$TMP/bin"
LOG="$TMP/systemctl.log"
mkdir -p "$RELEASE_DIR" "$FAKE_BIN" "$TMP/etc/systemd/system" "$TMP/usr/local/sbin"

if ! id relay-panel >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_ROOT" --shell /usr/sbin/nologin relay-panel
fi

cat > "$FAKE_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$HARNESS_LOG"
exit 0
EOF
cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *api/v1/health*) printf '{"status":"ok","version":"1.0.0-rc.5"}\n' ;;
    *) exit 1 ;;
esac
EOF
cat > "$FAKE_BIN/file" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *reality-panel-linux-amd64*) printf 'ELF 64-bit LSB pie executable, x86-64\n' ;;
    *reality-node-linux-amd64*) printf 'ELF 64-bit LSB pie executable, x86-64\n' ;;
    *) printf 'data\n' ;;
esac
EOF
chmod 0755 "$FAKE_BIN/systemctl" "$FAKE_BIN/curl" "$FAKE_BIN/file"

cat > "$RELEASE_DIR/reality-panel-linux-amd64" <<'EOF'
#!/usr/bin/env bash
printf 'relay-panel 1.0.0-rc.5\n'
EOF
cat > "$RELEASE_DIR/reality-node-linux-amd64" <<'EOF'
#!/usr/bin/env bash
printf 'relay-node 1.0.0-rc.5\n'
EOF
chmod 0755 "$RELEASE_DIR/reality-panel-linux-amd64" "$RELEASE_DIR/reality-node-linux-amd64"
mkdir "$TMP/web"
printf '<html>contract</html>\n' > "$TMP/web/index.html"
tar -czf "$RELEASE_DIR/reality-panel-web.tar.gz" -C "$TMP/web" .
for asset in install.sh update.sh deploy.sh; do
    printf '#!/usr/bin/env bash\n' > "$RELEASE_DIR/$asset"
done
chmod 0755 "$RELEASE_DIR"/*.sh

TEST_DEPLOY="$TMP/deploy.sh"
sed \
    -e "s#INSTALL_ROOT=\"/opt/relay-panel\"#INSTALL_ROOT=\"$INSTALL_ROOT\"#" \
    -e "s#CONFIG_ROOT=\"/etc/relay-panel\"#CONFIG_ROOT=\"$CONFIG_ROOT\"#" \
    -e "s#DATA_ROOT=\"/var/lib/relay-panel\"#DATA_ROOT=\"$DATA_ROOT\"#" \
    -e "s#SCRIPT_ROOT=\"/usr/local/lib/reality-panel\"#SCRIPT_ROOT=\"$SCRIPT_ROOT\"#" \
    -e "s#UPDATE_COMMAND=\"/usr/local/sbin/reality-panel-update\"#UPDATE_COMMAND=\"$UPDATE_COMMAND\"#" \
    -e "s#SERVICE_FILE=\"/etc/systemd/system/relay-panel.service\"#SERVICE_FILE=\"$SERVICE_FILE\"#" \
    "$ROOT/deploy.sh" > "$TEST_DEPLOY"
chmod 0755 "$TEST_DEPLOY"

run_deploy() {
    HARNESS_LOG="$LOG" PATH="$FAKE_BIN:$PATH" \
        RELEASE_DIR="$RELEASE_DIR" RELEASE_VERSION=v1.0.0-rc.5 \
        PUBLIC_PANEL_URL=http://203.0.113.10:18888 bash "$TEST_DEPLOY" install
}

run_deploy
metadata="$INSTALL_ROOT/node-assets/amd64/metadata.json"
[ "$(stat -c '%a' "$metadata")" = "644" ] || fail "fresh metadata mode is not 0644"
[ "$(stat -c '%U:%G' "$metadata")" = "root:root" ] || fail "fresh metadata owner changed"
runuser -u relay-panel -- cat "$metadata" >/dev/null || fail "relay-panel cannot read fresh metadata"
ok "fresh install metadata is 0644 and relay-panel-readable"

printf 'JWT_SECRET=preserve-me\nPANEL_KEY=preserve-me\n' > "$CONFIG_ROOT/relay-panel.env"
sqlite3 "$DATA_ROOT/data.db" \
    'CREATE TABLE harness_sentinel (value TEXT NOT NULL); INSERT INTO harness_sentinel VALUES ("database sentinel");'
chmod 0600 "$metadata"
[ "$(stat -c '%a' "$metadata")" = "600" ] || fail "failed to create rc.4 permission fixture"
run_deploy
[ "$(stat -c '%a' "$metadata")" = "644" ] || fail "update did not repair metadata mode"
[ "$(stat -c '%U:%G' "$metadata")" = "root:root" ] || fail "update changed metadata owner"
runuser -u relay-panel -- cat "$metadata" >/dev/null || fail "relay-panel cannot read repaired metadata"
grep -Fq 'JWT_SECRET=preserve-me' "$CONFIG_ROOT/relay-panel.env" || fail "update changed config"
sqlite3 "$DATA_ROOT/data.db" 'SELECT value FROM harness_sentinel;' | \
    grep -Fqx 'database sentinel' || fail "update changed database"
ok "0600 metadata was repaired to 0644 without changing config or data"

printf 'node artifact permission contract: PASS\n'
