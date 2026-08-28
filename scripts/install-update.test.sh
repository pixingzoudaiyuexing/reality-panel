#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
FAKE="$TMP/bin"
mkdir -p "$FAKE"

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
chmod +x "$FAKE"/*

parse() {
  PATH="$FAKE:$PATH" \
  REALITY_PANEL_OS_RELEASE_FILE="$TMP/os-release" \
  REALITY_PANEL_TEST_PARSE_ONLY=1 \
  PUBLIC_PANEL_URL=http://203.0.113.10:18888 \
    bash "$ROOT/install.sh" update "$@"
}

parse v1.0.0-rc.6 | grep -Fqx 'target_version=v1.0.0-rc.6'
parse --version v1.0.0-rc.6 | grep -Fqx 'target_version=v1.0.0-rc.6'
parse | grep -Fqx 'target_version='
grep -Fq 'releases/latest' "$ROOT/install.sh"
if rg -n 'target_version="\$\{VERSION' "$ROOT/install.sh"; then
  printf '[FAIL] target version still reads generic VERSION\n' >&2
  exit 1
fi

printf 'installer update argument contract: PASS\n'
