#!/usr/bin/env bash
# Offline uninstall harness. It substitutes only the fixed install root in a
# temporary copy, then uses a fake Docker CLI to assert project-scoped cleanup.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
INSTALL_ROOT="$TMP/opt/relay-panel"
SCRIPT="$TMP/install-under-test.sh"
FAKE="$TMP/fakebin"
LOG="$TMP/docker.log"
UNRELATED_CONTAINER="$TMP/unrelated-container"
UNRELATED_VOLUME="$TMP/unrelated-volume"

mkdir -p "$FAKE"
sed \
  -e "s#INSTALL_DIR=\"/opt/relay-panel\"#INSTALL_DIR=\"$INSTALL_ROOT\"#" \
  -e "s#\[ \"\$INSTALL_DIR\" = \"/opt/relay-panel\" \]#[ \"\$INSTALL_DIR\" = \"$INSTALL_ROOT\" ]#" \
  "$ROOT/install.sh" > "$SCRIPT"
chmod +x "$SCRIPT"

cat > "$FAKE/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${HARNESS_LOG:?}"
if [ "${1:-}" = "compose" ]; then
  exit 0
fi
exit 1
EOF
chmod +x "$FAKE/docker"

cat > "$FAKE/uname" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-s" ]; then
  printf 'Linux\n'
else
  command /usr/bin/uname "$@"
fi
EOF
chmod +x "$FAKE/uname"

cat > "$FAKE/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$FAKE/apt-get"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[OK] $*"; }
run_uninstall() {
  HARNESS_LOG="$LOG" PATH="$FAKE:$PATH" bash "$SCRIPT" uninstall "$@"
}
make_install() {
  mkdir -p "$INSTALL_ROOT"
  cp "$ROOT/docker-compose.release.yaml" "$INSTALL_ROOT/"
  cp "$ROOT/docker-compose.yaml" "$INSTALL_ROOT/"
  printf 'JWT_SECRET=test\nPANEL_KEY=test\n' > "$INSTALL_ROOT/.env"
}

# Confirmation rejection must not call Docker or delete local files.
make_install
: > "$LOG"
printf 'no\n' | HARNESS_LOG="$LOG" PATH="$FAKE:$PATH" bash "$SCRIPT" uninstall
[ -d "$INSTALL_ROOT" ] || fail "rejected confirmation deleted the install root"
[ ! -s "$LOG" ] || fail "rejected confirmation contacted Docker"
ok "confirmation rejection leaves all resources intact"

# Interactive DELETE confirmation removes only the fixed project's declared
# Compose resources and root.
touch "$UNRELATED_CONTAINER" "$UNRELATED_VOLUME"
: > "$LOG"
printf 'DELETE\n' | HARNESS_LOG="$LOG" PATH="$FAKE:$PATH" bash "$SCRIPT" uninstall
[ ! -e "$INSTALL_ROOT" ] || fail "accepted uninstall retained the install root"
[ -e "$UNRELATED_CONTAINER" ] || fail "unrelated container sentinel was removed"
[ -e "$UNRELATED_VOLUME" ] || fail "unrelated volume sentinel was removed"
grep -q -- '--volumes --remove-orphans' "$LOG" || fail "Compose volume cleanup flags missing"
grep -q -- "--project-directory $INSTALL_ROOT" "$LOG" || fail "Compose cleanup escaped fixed root"
if grep -Eq 'rm |volume rm|container rm|system prune|network prune' "$LOG"; then
  fail "uninstall issued a broad Docker deletion command"
fi
ok "interactive confirmation removes only declared project resources and local root"

# --yes is an explicit non-interactive equivalent, never the default.
make_install
: > "$LOG"
run_uninstall --yes
[ ! -e "$INSTALL_ROOT" ] || fail "--yes retained the install root"
grep -q -- '--volumes --remove-orphans' "$LOG" || fail "--yes did not clean Compose volumes"
ok "--yes removes the local deployment without a prompt"

# Missing and partial installs both succeed without widening cleanup scope.
: > "$LOG"
run_uninstall --yes
[ ! -s "$LOG" ] || fail "already-uninstalled path contacted Docker"
ok "already-uninstalled is idempotent"

mkdir -p "$INSTALL_ROOT"
printf 'partial\n' > "$INSTALL_ROOT/.env"
: > "$LOG"
run_uninstall --yes
[ ! -e "$INSTALL_ROOT" ] || fail "partial install root was not removed"
if grep -q ' down ' "$LOG"; then
  fail "partial install without compose files ran Compose cleanup"
fi
ok "partial install cleanup is safe"

# Uninstall leaves no sentinel or reservation under the known root, so the
# normal fresh-install path can recreate it. Fresh deploy behavior itself is
# covered by scripts/deploy-web-mode-check.sh without network or a live Docker.
[ ! -e "$INSTALL_ROOT" ] || fail "uninstall left an install-root blocker"
ok "clean install root is ready for fresh install"

bash "$ROOT/deploy.sh" uninstall --help >/dev/null
grep -q 'INSTALL_DIR="/opt/relay-panel"' "$ROOT/install.sh" || fail "install root is no longer fixed"
if grep -Eq 'ssh |ssh\(' "$ROOT/install.sh"; then
  fail "Panel uninstall must not contact Relay hosts"
fi
ok "deploy command dispatch and local-only boundary are intact"

echo "panel uninstall harness: PASS"
