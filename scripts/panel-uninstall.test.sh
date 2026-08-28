#!/usr/bin/env bash
# Offline uninstall harness for the fixed bare-metal Panel layout.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
INSTALL_ROOT="$TMP/opt/relay-panel"
CONFIG_ROOT="$TMP/etc/relay-panel"
DATA_ROOT="$TMP/var/lib/relay-panel"
SCRIPT_ROOT="$TMP/usr/local/lib/reality-panel"
UPDATE_COMMAND="$TMP/usr/local/sbin/reality-panel-update"
SERVICE_FILE="$TMP/etc/systemd/system/relay-panel.service"
SCRIPT="$TMP/install-under-test.sh"
FAKE="$TMP/fakebin"
LOG="$TMP/system.log"
UNRELATED="$TMP/unrelated"

mkdir -p "$FAKE" "$UNRELATED"
cat > "$FAKE/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >> "${HARNESS_LOG:?}"
exit 0
EOF
chmod +x "$FAKE/systemctl"

# Substitute only the fixed absolute paths in a temporary copy. The guard
# checks remain in place with their expected test paths, so the harness cannot
# accidentally exercise a broader deletion scope.
sed \
  -e "s#INSTALL_ROOT=\"/opt/relay-panel\"#INSTALL_ROOT=\"$INSTALL_ROOT\"#" \
  -e "s#CONFIG_ROOT=\"/etc/relay-panel\"#CONFIG_ROOT=\"$CONFIG_ROOT\"#" \
  -e "s#DATA_ROOT=\"/var/lib/relay-panel\"#DATA_ROOT=\"$DATA_ROOT\"#" \
  -e "s#SCRIPT_ROOT=\"/usr/local/lib/reality-panel\"#SCRIPT_ROOT=\"$SCRIPT_ROOT\"#" \
  -e "s#UPDATE_COMMAND=\"/usr/local/sbin/reality-panel-update\"#UPDATE_COMMAND=\"$UPDATE_COMMAND\"#" \
  -e "s#/etc/systemd/system/relay-panel.service#$SERVICE_FILE#g" \
  -e "s#\[ \"\$INSTALL_ROOT\" = \"/opt/relay-panel\" \]#[ \"\$INSTALL_ROOT\" = \"$INSTALL_ROOT\" ]#" \
  -e "s#\[ \"\$CONFIG_ROOT\" = \"/etc/relay-panel\" \]#[ \"\$CONFIG_ROOT\" = \"$CONFIG_ROOT\" ]#" \
  -e "s#\[ \"\$DATA_ROOT\" = \"/var/lib/relay-panel\" \]#[ \"\$DATA_ROOT\" = \"$DATA_ROOT\" ]#" \
  "$ROOT/install.sh" > "$SCRIPT"
chmod +x "$SCRIPT"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[OK] $*"; }
run_uninstall() {
  HARNESS_LOG="$LOG" PATH="$FAKE:$PATH" bash "$SCRIPT" uninstall "$@"
}
run_confirmed() {
  TEST_ANSWER="$1" TEST_SCRIPT="$SCRIPT" TEST_LOG="$LOG" TEST_PATH="$FAKE:$PATH" \
    expect <<'EOF'
set timeout 5
log_user 0
spawn env HARNESS_LOG=$env(TEST_LOG) PATH=$env(TEST_PATH) bash $env(TEST_SCRIPT) uninstall
expect {
  -re {Type [A-Z]+ to continue: } { send -- "$env(TEST_ANSWER)\r"; exp_continue }
  eof {}
  timeout { exit 2 }
}
catch wait result
exit [lindex $result 3]
EOF
}
make_install() {
  mkdir -p "$INSTALL_ROOT/releases" "$INSTALL_ROOT/public" \
    "$INSTALL_ROOT/node-assets" "$CONFIG_ROOT" "$DATA_ROOT" \
    "$SCRIPT_ROOT" "$(dirname "$UPDATE_COMMAND")" "$(dirname "$SERVICE_FILE")"
  printf 'local runtime\n' > "$INSTALL_ROOT/current"
  printf 'JWT_SECRET=fixture\nPANEL_KEY=fixture\n' > "$CONFIG_ROOT/relay-panel.env"
  printf 'database\n' > "$DATA_ROOT/data.db"
  printf 'update\n' > "$UPDATE_COMMAND"
  printf 'unit\n' > "$SERVICE_FILE"
}

# A cancelled confirmation leaves every owned and unrelated sentinel intact.
make_install
before="$(find "$TMP" -type f -print | sort | shasum)"
run_confirmed NO
[ -e "$INSTALL_ROOT/current" ] || fail "confirmation rejection deleted the install"
[ "$(find "$TMP" -type f -print | sort | shasum)" = "$before" ] || \
  fail "confirmation rejection changed local resources"
ok "confirmation rejection leaves resources intact"

# Explicit confirmation removes the runtime-owned paths but keeps config/data.
: > "$LOG"
run_confirmed UNINSTALL
[ ! -e "$INSTALL_ROOT" ] || fail "confirmed uninstall retained runtime files"
[ ! -e "$SCRIPT_ROOT" ] || fail "confirmed uninstall retained helper scripts"
[ ! -e "$SERVICE_FILE" ] || fail "confirmed uninstall retained systemd unit"
[ -e "$CONFIG_ROOT/relay-panel.env" ] || fail "default uninstall deleted config"
[ -e "$DATA_ROOT/data.db" ] || fail "default uninstall deleted data"
[ -e "$UNRELATED" ] || fail "unrelated path was removed"
grep -q 'systemctl disable --now relay-panel.service' "$LOG" || \
  fail "service stop was not attempted"
ok "confirmed uninstall removes runtime and preserves config/data"

# --yes is the explicit non-interactive path and purge removes only fixed data.
make_install
: > "$LOG"
run_uninstall --yes --purge
[ ! -e "$INSTALL_ROOT" ] || fail "--yes purge retained runtime files"
[ ! -e "$CONFIG_ROOT" ] || fail "--yes purge retained config"
[ ! -e "$DATA_ROOT" ] || fail "--yes purge retained data"
[ -e "$UNRELATED" ] || fail "--yes purge removed unrelated path"
ok "--yes purge removes only the local Panel deployment"

# Missing and partial installations are safe and idempotent.
: > "$LOG"
run_uninstall --yes
if grep -Evq '^systemctl (disable --now relay-panel\.service|daemon-reload)$' "$LOG"; then
  fail "already absent uninstall performed unexpected cleanup"
fi
mkdir -p "$INSTALL_ROOT/releases"
printf 'partial\n' > "$INSTALL_ROOT/releases/partial.txt"
run_uninstall --yes
[ ! -e "$INSTALL_ROOT" ] || fail "partial install was not removed"
ok "missing and partial installs are idempotent"

bash -n "$ROOT/install.sh" "$ROOT/deploy.sh" "$ROOT/update.sh"
grep -Fq 'Remote Relay nodes were not contacted' "$ROOT/install.sh" || \
  fail "remote safety message missing"
if rg -n '(^|[[:space:]])ssh([[:space:]]|\()' "$ROOT/install.sh"; then
  fail "Panel uninstall must not contact Relay hosts"
fi
ok "shell syntax and local-only boundary are intact"
echo "panel uninstall harness: PASS"
