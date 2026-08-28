#!/usr/bin/env bash
# Reality Panel release installer/updater/uninstaller for Debian 12 amd64.
set -euo pipefail

REPOSITORY="pixingzoudaiyuexing/reality-panel"
DEFAULT_RELEASE_TAG="v1.0.0-rc.4"
INSTALL_ROOT="/opt/relay-panel"
CONFIG_ROOT="/etc/relay-panel"
DATA_ROOT="/var/lib/relay-panel"
SCRIPT_ROOT="/usr/local/lib/reality-panel"
UPDATE_COMMAND="/usr/local/sbin/reality-panel-update"

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  install.sh install --version v1.0.0-rc.4 --public-panel-url URL
  install.sh update [VERSION]
  install.sh uninstall [--yes] [--purge]

Install requires an explicit GitHub Release tag. Update without VERSION selects
the latest non-prerelease GitHub Release. Uninstall preserves configuration and
data unless --purge is explicitly supplied.
EOF
}

valid_release_tag() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
}

valid_public_panel_url() {
    local url="$1" authority host port
    [[ "$url" =~ ^https?://[^/@[:space:]?#]+/?$ ]] || return 1
    authority="${url#*://}"
    authority="${authority%/}"
    if [[ "$authority" == \[*\]* ]]; then
        host="${authority%%\]*}]"
        host="${host#\[}"
        port="${authority#*\]}"
        [ -n "$host" ] && [[ "$host" == *:* ]] || return 1
        if [ -n "$port" ]; then
            [[ "$port" =~ ^:[0-9]{1,5}$ ]] || return 1
            [ "${port#:}" -le 65535 ] || return 1
        fi
    else
        [[ "$authority" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || return 1
        if [[ "$authority" == *:* ]]; then
            port="${authority##*:}"
            [ "$port" -le 65535 ] || return 1
        fi
    fi
}

confirm() {
    local expected="$1" prompt="$2" answer=""
    printf '%s\nType %s to continue: ' "$prompt" "$expected"
    if [ -t 0 ]; then
        read -r answer
    elif { read -r answer < /dev/tty; } 2>/dev/null; then
        :
    else
        fail "No interactive terminal is available; review the warning and use --yes if appropriate."
    fi
    [ "$answer" = "$expected" ] || { info "Cancelled. Nothing was deleted."; exit 0; }
}

local_uninstall() {
    local yes=0 purge=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --yes) yes=1 ;;
            --purge) purge=1 ;;
            -h|--help) usage; exit 0 ;;
            *) fail "Unknown uninstall option: $1" ;;
        esac
        shift
    done
    [ "$INSTALL_ROOT" = "/opt/relay-panel" ] || fail "Unexpected install root"
    [ "$CONFIG_ROOT" = "/etc/relay-panel" ] || fail "Unexpected config root"
    [ "$DATA_ROOT" = "/var/lib/relay-panel" ] || fail "Unexpected data root"

    if [ "$yes" -ne 1 ]; then
        warn "This removes only the local Reality Panel service and installed release files."
        warn "Remote Relay nodes, DNS records, and Reality backends are not contacted."
        if [ "$purge" -eq 1 ]; then
            warn "--purge permanently deletes the local database, configuration, and secrets."
            confirm "PURGE" "Export important Rules before purging; exports are not created automatically."
        else
            confirm "UNINSTALL" "Panel data and configuration will be retained for a later reinstall."
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now relay-panel.service >/dev/null 2>&1 || true
    fi
    rm -f -- /etc/systemd/system/relay-panel.service "$UPDATE_COMMAND"
    rm -rf -- "$INSTALL_ROOT/releases" "$INSTALL_ROOT/current" \
        "$INSTALL_ROOT/public" "$INSTALL_ROOT/node-assets" "$SCRIPT_ROOT"
    rmdir "$INSTALL_ROOT" 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true

    if [ "$purge" -eq 1 ]; then
        rm -rf -- "$CONFIG_ROOT" "$DATA_ROOT"
        info "Reality Panel binaries, configuration, and local data removed."
    else
        info "Reality Panel removed; configuration remains in $CONFIG_ROOT and data in $DATA_ROOT."
    fi
    info "Remote Relay nodes were not contacted."
}

command_name="${1:-install}"
[ "$#" -eq 0 ] || shift
case "$command_name" in
    uninstall)
        if [ -x "$SCRIPT_ROOT/deploy.sh" ]; then
            exec "$SCRIPT_ROOT/deploy.sh" uninstall "$@"
        fi
        local_uninstall "$@"
        exit 0
        ;;
    install|update) ;;
    -h|--help|help) usage; exit 0 ;;
    *) fail "Unknown command: $command_name" ;;
esac

[ "$(id -u)" -eq 0 ] || fail "Run as root."
[ "$(uname -s)" = "Linux" ] || fail "Only Linux is supported."
[ "$(uname -m)" = "x86_64" ] || fail "Reality Panel v1 requires Linux amd64 (x86_64)."
[ -r /etc/os-release ] || fail "Cannot identify the operating system."
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = "debian" ] && [ "${VERSION_ID:-}" = "12" ] || \
    fail "The supported v1 host is Debian 12 amd64."
command -v systemctl >/dev/null 2>&1 || fail "systemd is required."

version="${VERSION:-}"
if [ "$command_name" = "install" ] && [ -z "$version" ]; then
    version="$DEFAULT_RELEASE_TAG"
fi
public_url="${PUBLIC_PANEL_URL:-}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || fail "--version requires a value"; version="$2"; shift 2 ;;
        --public-panel-url) [ "$#" -ge 2 ] || fail "--public-panel-url requires a value"; public_url="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        v*) [ "$command_name" = "update" ] && [ -z "$version" ] || fail "Unexpected argument: $1"; version="$1"; shift ;;
        *) fail "Unknown option: $1" ;;
    esac
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl file openssl sqlite3 tar >/dev/null

if [ "$command_name" = "update" ] && [ -z "$version" ]; then
    info "Resolving latest stable Reality Panel release..."
    latest_url="$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPOSITORY/releases/latest")"
    version="${latest_url##*/}"
fi
[ -n "$version" ] || fail "Install requires --version vX.Y.Z (RC tags are allowed)."
valid_release_tag "$version" || fail "Invalid release tag: $version"

env_file="$CONFIG_ROOT/relay-panel.env"
if [ -z "$public_url" ] && [ -r "$env_file" ]; then
    public_url="$(sed -n 's/^PUBLIC_PANEL_URL=//p' "$env_file" | tail -n 1)"
fi
if [ -z "$public_url" ] && [ -r /dev/tty ]; then
    printf 'Public Panel URL (http://IP:PORT or https://hostname): ' > /dev/tty
    read -r public_url < /dev/tty
fi
[ -n "$public_url" ] || fail "PUBLIC_PANEL_URL is required for remote Relay bootstrap."
valid_public_panel_url "$public_url" || fail "PUBLIC_PANEL_URL must be a credential-free http:// or https:// origin with no path, query, or fragment."

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
base="https://github.com/$REPOSITORY/releases/download/$version"
info "Downloading verified assets for $version..."
curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
assets=(reality-panel-linux-amd64 reality-node-linux-amd64 reality-panel-web.tar.gz install.sh update.sh deploy.sh)
for asset in "${assets[@]}"; do
    curl --proto '=https' --tlsv1.2 -fsSL "$base/$asset" -o "$tmp/$asset"
    expected="$(awk -v name="$asset" '$2 == name || $2 == ("*" name) { print $1 }' "$tmp/SHA256SUMS")"
    [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = "1" ] && [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || \
        fail "SHA256SUMS has no unique checksum for $asset"
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || fail "SHA256 mismatch for $asset"
done
chmod +x "$tmp/install.sh" "$tmp/update.sh" "$tmp/deploy.sh" \
    "$tmp/reality-panel-linux-amd64" "$tmp/reality-node-linux-amd64"

RELEASE_DIR="$tmp" RELEASE_VERSION="$version" PUBLIC_PANEL_URL="$public_url" \
    exec "$tmp/deploy.sh" "$command_name"
