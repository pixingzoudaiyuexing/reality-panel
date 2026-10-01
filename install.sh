#!/usr/bin/env bash
# Reality Panel release installer/updater/uninstaller for Debian/Ubuntu amd64.
set -euo pipefail

REPOSITORY="pixingzoudaiyuexing/reality-panel"
INSTALL_ROOT="/opt/relay-panel"
CONFIG_ROOT="/etc/relay-panel"
DATA_ROOT="/var/lib/relay-panel"
SCRIPT_ROOT="/usr/local/lib/reality-panel"
UPDATE_COMMAND="/usr/local/sbin/reality-panel-update"

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
success() { printf '\033[32m\342\234\223 %s\033[0m\n' "$*"; }

usage() {
    cat <<'EOF'
Usage:
  install.sh [VERSION] [--port PORT] [--public-panel-url URL]
  install.sh install [--version VERSION] [--port PORT] [--public-panel-url URL]
  install.sh update [VERSION]
  install.sh uninstall [--yes] [--purge]

Install and update without VERSION select the latest stable GitHub Release.
VERSION may be a stable or prerelease tag such as v1.0.0 or v1.1.0-rc.1.
New installations listen on port 18888 by default. Uninstall preserves
configuration and data unless --purge is explicitly supplied.
EOF
}

valid_release_tag() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
}

valid_stable_release_tag() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_ipv4() {
    local ip="$1" octet
    local -a octets
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [ "$((10#$octet))" -le 255 ] || return 1
    done
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

    [ "$(id -u)" -eq 0 ] || fail "Run as root."
    # Refuse symlinked roots/ancestors before either deleting children or invoking
    # installed helpers. Never follow a product-looking path into foreign state.
    local managed ancestor account_owned=0 account_entry="" account_uid="" group_owned=0 owned_gid=""
    for managed in "$INSTALL_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$SCRIPT_ROOT" \
        "$UPDATE_COMMAND" "$CONFIG_ROOT/installer-account" /etc/systemd/system/relay-panel.service; do
        ancestor="$managed"
        while [ "$ancestor" != / ] && [ -n "$ancestor" ]; do
            [ ! -L "$ancestor" ] || fail "Refusing symlinked uninstall path: $ancestor"
            ancestor="$(dirname "$ancestor")"
        done
    done
    if [ "$purge" -eq 1 ]; then
        account_entry="$(getent passwd relay-panel || true)"
        if [ -n "$account_entry" ]; then
            local account_name account_password account_gid account_gecos account_home account_shell
            IFS=: read -r account_name account_password account_uid account_gid account_gecos account_home account_shell <<< "$account_entry"
            if [ "$account_name" = relay-panel ] && [[ "$account_uid" =~ ^[0-9]+$ ]] && \
               [ "$account_uid" -gt 0 ] && [ "$account_uid" -lt 1000 ] && \
               [ "$account_home" = "$DATA_ROOT" ] && \
               { [ "$account_shell" = /usr/sbin/nologin ] || [ "$account_shell" = /sbin/nologin ]; }; then
                if [ -f "$CONFIG_ROOT/installer-account" ] && \
                    [ "$(cat "$CONFIG_ROOT/installer-account")" = "$account_uid:$account_gid" ]; then
                    account_owned=1
                elif [ -f /etc/systemd/system/relay-panel.service ] && \
                    grep -Fqx 'User=relay-panel' /etc/systemd/system/relay-panel.service && \
                    grep -Fq "$INSTALL_ROOT/" /etc/systemd/system/relay-panel.service; then
                    # Legacy installers had no marker. A matching system account
                    # plus an actual product service establishes conservative ownership.
                    account_owned=1
                fi
            fi
        fi
    fi
    if [ "$purge" -eq 1 ]; then
        if [ "$account_owned" -eq 1 ]; then
            # Persist legacy ownership evidence before deleting its service so
            # a failed account cleanup can be retried after files are gone.
            install -d -m 0750 "$CONFIG_ROOT"
            printf '%s:%s\n' "$account_uid" "$account_gid" > "$CONFIG_ROOT/installer-account"
            chmod 0600 "$CONFIG_ROOT/installer-account"
        fi
        if [ -f "$CONFIG_ROOT/installer-account" ]; then
            local ownership_record group_entry group_name group_password group_gid group_members
            ownership_record="$(cat "$CONFIG_ROOT/installer-account")"
            if [[ "$ownership_record" =~ ^[0-9]+:[0-9]+$ ]]; then
                owned_gid="${ownership_record#*:}"
                group_entry="$(getent group relay-panel || true)"
                IFS=: read -r group_name group_password group_gid group_members <<< "$group_entry"
                if [ "$group_name" = relay-panel ] && [ "$group_gid" = "$owned_gid" ] && [ -z "$group_members" ]; then group_owned=1; fi
            fi
        fi
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl cat relay-panel.service >/dev/null 2>&1; then
            systemctl disable --now relay-panel.service || fail "Could not stop/disable Panel; installation retained."
            if systemctl is-active --quiet relay-panel.service; then
                fail "Panel is still running; installation retained."
            fi
        fi
    else
        fail "systemctl is required to verify that the Panel has stopped."
    fi
    rm -f -- /etc/systemd/system/relay-panel.service "$UPDATE_COMMAND"
    # The complete install root includes legacy binaries, staging releases,
    # certificate state and failed-update artifacts as well as current assets.
    rm -rf -- "$INSTALL_ROOT" "$SCRIPT_ROOT"
    systemctl daemon-reload || fail "Panel files removed but systemd reload failed; retry uninstall."
    systemctl reset-failed relay-panel.service >/dev/null 2>&1 || true
    if [ "$purge" -eq 1 ]; then
        if [ "$account_owned" -eq 1 ]; then
            userdel relay-panel || fail "Panel data removed but owned account cleanup failed; retry after checking account."
        elif [ -n "$account_entry" ]; then
            warn "Account relay-panel ownership is unproven; preserved the existing account."
        fi
        if [ "$group_owned" -eq 1 ]; then
            # Preserve a group still used by another account, including primary GIDs.
            if getent passwd | awk -F: -v gid="$owned_gid" '$4 == gid { found=1 } END { exit !found }'; then
                warn "Group relay-panel is still used by another account; preserved shared group."
            else
                groupdel relay-panel || fail "Owned group cleanup failed; retry uninstall."
            fi
        fi
        rm -rf -- "$CONFIG_ROOT" "$DATA_ROOT"
        info "Reality Panel binaries, configuration, and local data removed."
        info "Panel local data was purged."
    else
        info "Reality Panel removed; configuration remains in $CONFIG_ROOT and data in $DATA_ROOT."
    fi
    info "Remote Relay nodes were not contacted."
    success "卸载成功"
}

command_name=install
target_version="${TARGET_VERSION:-}"
panel_port="${PANEL_PORT:-18888}"
public_url="${PUBLIC_PANEL_URL:-}"
port_was_explicit=0

case "${1:-}" in
    install|update|uninstall)
        command_name="$1"
        shift
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    ""|--*) ;;
    v*)
        valid_release_tag "$1" || fail "Invalid release tag: $1"
        target_version="$1"
        shift
        ;;
    *) fail "Unknown command or release tag: $1" ;;
esac

case "$command_name" in
    uninstall)
        [ "$(id -u)" -eq 0 ] || fail "Run as root."
        helper_path="$SCRIPT_ROOT/deploy.sh"
        while [ "$helper_path" != / ]; do
            [ ! -L "$helper_path" ] || fail "Refusing symlinked uninstall helper"
            helper_path="$(dirname "$helper_path")"
        done
        if [ -x "$SCRIPT_ROOT/deploy.sh" ]; then
            exec "$SCRIPT_ROOT/deploy.sh" uninstall "$@"
        fi
        local_uninstall "$@"
        exit 0
        ;;
    install|update) ;;
    *) fail "Unknown command: $command_name" ;;
esac

[ "$(id -u)" -eq 0 ] || fail "Run as root."
[ "$(uname -s)" = "Linux" ] || fail "Only Linux is supported."
[ "$(uname -m)" = "x86_64" ] || fail "Reality Panel v1 requires Linux amd64 (x86_64)."
os_release_file="${REALITY_PANEL_OS_RELEASE_FILE:-/etc/os-release}"
[ -r "$os_release_file" ] || fail "Cannot identify the operating system."
# 在子 shell 中读取系统信息，避免 Debian 的 VERSION 污染目标发布版本。
os_id="$(. "$os_release_file"; printf '%s' "${ID:-}")"
os_version_id="$(. "$os_release_file"; printf '%s' "${VERSION_ID:-}")"
case "$os_id:$os_version_id" in
    debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;;
    *) fail "Supported hosts: Debian 12/13 or Ubuntu 22.04/24.04 amd64." ;;
esac
command -v apt-get >/dev/null 2>&1 || fail "apt-get is required."
command -v systemctl >/dev/null 2>&1 || fail "systemd is required."
systemctl show --property=Version --value >/dev/null 2>&1 || fail "A running systemd manager is required."

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || fail "--version requires a value"; target_version="$2"; shift 2 ;;
        --port) [ "$#" -ge 2 ] || fail "--port requires a value"; panel_port="$2"; port_was_explicit=1; shift 2 ;;
        --public-panel-url) [ "$#" -ge 2 ] || fail "--public-panel-url requires a value"; public_url="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        v*) [ -z "$target_version" ] || fail "Multiple release versions were provided"; target_version="$1"; shift ;;
        *) fail "Unknown option: $1" ;;
    esac
done
valid_port "$panel_port" || fail "Panel port must be an integer from 1 to 65535."

env_file="$CONFIG_ROOT/relay-panel.env"

if [ "${REALITY_PANEL_TEST_PARSE_ONLY:-0}" != 1 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates certbot curl file iproute2 openssl sqlite3 tar >/dev/null
fi

if [ ! -e "$env_file" ] && ss -H -ltn "sport = :$panel_port" 2>/dev/null | grep -q .; then
    fail "Panel port $panel_port is already in use. Re-run with --port <PORT>."
fi

if [ -z "$target_version" ]; then
    info "Resolving latest stable Reality Panel release..."
    latest_url="$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPOSITORY/releases/latest")" || \
        fail "Unable to resolve the latest stable Reality Panel release."
    target_version="${latest_url##*/}"
    valid_stable_release_tag "$target_version" || \
        fail "The latest Release endpoint did not resolve to a stable vX.Y.Z tag."
fi
valid_release_tag "$target_version" || fail "Invalid release tag: $target_version"

if [ -z "$public_url" ] && [ -r "$env_file" ]; then
    public_url="$(sed -n 's/^PUBLIC_PANEL_URL=//p' "$env_file" | tail -n 1)"
fi
if [ -z "$public_url" ]; then
    public_ip="$(curl -4 -fsSL https://api.ipify.org)" || \
        fail "Unable to automatically obtain the public IPv4. Re-run with --public-panel-url http://YOUR_IP:$panel_port or your HTTPS domain."
    valid_ipv4 "$public_ip" || \
        fail "Unable to automatically obtain a valid public IPv4. Re-run with --public-panel-url http://YOUR_IP:$panel_port or your HTTPS domain."
    public_url="http://$public_ip:$panel_port"
fi
valid_public_panel_url "$public_url" || fail "PUBLIC_PANEL_URL must be a credential-free http:// or https:// origin with no path, query, or fragment."

if [ "${REALITY_PANEL_TEST_PARSE_ONLY:-0}" = 1 ]; then
    printf 'command=%s\ntarget_version=%s\npanel_port=%s\npublic_url=%s\n' \
        "$command_name" "$target_version" "$panel_port" "$public_url"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
base="https://github.com/$REPOSITORY/releases/download/$target_version"
info "Downloading verified assets for $target_version..."
curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || \
    fail "Unable to download SHA256SUMS for exact release $target_version."
assets=(reality-panel-linux-amd64 reality-node-linux-amd64 reality-panel-web.tar.gz install.sh update.sh deploy.sh)
for asset in "${assets[@]}"; do
    curl --proto '=https' --tlsv1.2 -fsSL "$base/$asset" -o "$tmp/$asset"
    expected="$(awk -v name="$asset" '$2 == name || $2 == ("*" name) { print $1 }' "$tmp/SHA256SUMS")"
    [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = "1" ] && [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || \
        fail "SHA256SUMS has no unique checksum for $asset"
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || fail "SHA256 mismatch for $asset"
done

if [ "$port_was_explicit" -eq 1 ] && [ "$panel_port" != "18888" ] && \
   ! grep -Fq 'PANEL_PORT' "$tmp/deploy.sh"; then
    fail "Release $target_version does not support --port. Use the default port 18888 or install a newer Release that supports custom Panel ports."
fi

chmod +x "$tmp/install.sh" "$tmp/update.sh" "$tmp/deploy.sh" \
    "$tmp/reality-panel-linux-amd64" "$tmp/reality-node-linux-amd64"

RELEASE_DIR="$tmp" RELEASE_VERSION="$target_version" PUBLIC_PANEL_URL="$public_url" PANEL_PORT="$panel_port" \
    "$tmp/deploy.sh" "$command_name"
