#!/usr/bin/env bash
# Installs an already downloaded and SHA-verified Reality Panel release.
set -euo pipefail

INSTALL_ROOT="/opt/relay-panel"
CONFIG_ROOT="/etc/relay-panel"
DATA_ROOT="/var/lib/relay-panel"
SCRIPT_ROOT="/usr/local/lib/reality-panel"
UPDATE_COMMAND="/usr/local/sbin/reality-panel-update"
SERVICE_FILE="/etc/systemd/system/relay-panel.service"

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
success() { printf '\033[32m\342\234\223 %s\033[0m\n' "$*"; }

confirm() {
    local expected="$1" prompt="$2" answer=""
    printf '%s\nType %s to continue: ' "$prompt" "$expected"
    if [ -t 0 ]; then read -r answer; else read -r answer < /dev/tty; fi
    [ "$answer" = "$expected" ] || { info "Cancelled. Nothing was deleted."; exit 0; }
}

uninstall_panel() {
    local yes=0 purge=0
    while [ "$#" -gt 0 ]; do
        case "$1" in --yes) yes=1 ;; --purge) purge=1 ;; *) fail "Unknown uninstall option: $1" ;; esac
        shift
    done
    [ "$INSTALL_ROOT" = "/opt/relay-panel" ] || fail "Unexpected install root"
    [ "$CONFIG_ROOT" = "/etc/relay-panel" ] || fail "Unexpected config root"
    [ "$DATA_ROOT" = "/var/lib/relay-panel" ] || fail "Unexpected data root"
    if [ "$yes" -ne 1 ]; then
        warn "Remote Relay nodes, DNS records, and Reality backends will not be touched."
        if [ "$purge" -eq 1 ]; then
            warn "--purge permanently deletes the local database, configuration, and secrets."
            confirm PURGE "Export important Rules first; exports are not created automatically."
        else
            confirm UNINSTALL "Local Panel data and configuration will be retained."
        fi
    fi
    systemctl disable --now relay-panel.service >/dev/null 2>&1 || true
    rm -f -- "$SERVICE_FILE" "$UPDATE_COMMAND"
    rm -rf -- "$INSTALL_ROOT/releases" "$INSTALL_ROOT/current" \
        "$INSTALL_ROOT/public" "$INSTALL_ROOT/node-assets" "$SCRIPT_ROOT"
    rmdir "$INSTALL_ROOT" 2>/dev/null || true
    systemctl daemon-reload || true
    if [ "$purge" -eq 1 ]; then
        rm -rf -- "$CONFIG_ROOT" "$DATA_ROOT"
        info "Reality Panel and local data removed."
        info "Panel local data was purged."
    else
        info "Reality Panel removed; retained $CONFIG_ROOT and $DATA_ROOT."
    fi
    info "Remote Relay nodes were not contacted."
    success "卸载成功"
}

mode="${1:-}"
[ "$#" -eq 0 ] || shift
case "$mode" in
    uninstall) uninstall_panel "$@"; exit 0 ;;
    install|update) ;;
    *) fail "Usage: deploy.sh install|update|uninstall" ;;
esac

[ "$(id -u)" -eq 0 ] || fail "Run as root."
release_dir="${RELEASE_DIR:?RELEASE_DIR is required}"
release_tag="${RELEASE_VERSION:?RELEASE_VERSION is required}"
public_url="${PUBLIC_PANEL_URL:?PUBLIC_PANEL_URL is required}"
panel_port="${PANEL_PORT:-18888}"
version="${release_tag#v}"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || fail "Invalid release tag"
[[ "$panel_port" =~ ^[0-9]+$ ]] && [ "$panel_port" -ge 1 ] && [ "$panel_port" -le 65535 ] || \
    fail "PANEL_PORT must be an integer from 1 to 65535"

required=(reality-panel-linux-amd64 reality-node-linux-amd64 reality-panel-web.tar.gz install.sh update.sh deploy.sh)
for asset in "${required[@]}"; do [ -s "$release_dir/$asset" ] || fail "Missing release asset: $asset"; done
file "$release_dir/reality-panel-linux-amd64" | grep -q 'ELF 64-bit.*x86-64' || fail "Panel asset is not Linux amd64 ELF"
file "$release_dir/reality-node-linux-amd64" | grep -q 'ELF 64-bit.*x86-64' || fail "Node asset is not Linux amd64 ELF"
panel_version="$($release_dir/reality-panel-linux-amd64 --version | awk '{print $NF}')"
node_version="$($release_dir/reality-node-linux-amd64 --version | awk '{print $NF}')"
[ "$panel_version" = "$version" ] || fail "Panel binary version $panel_version does not match $version"
[ "$node_version" = "$version" ] || fail "Node binary version $node_version does not match $version"

id relay-panel >/dev/null 2>&1 || useradd --system --home-dir "$DATA_ROOT" --shell /usr/sbin/nologin relay-panel
install -d -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
install -d -o relay-panel -g relay-panel -m 0750 "$DATA_ROOT"
install -d -o relay-panel -g relay-panel -m 0700 "$DATA_ROOT/certificates"
install -d -m 0750 "$CONFIG_ROOT"

env_file="$CONFIG_ROOT/relay-panel.env"
created_default_admin=0
if [ "$mode" = install ] && [ ! -e "$DATA_ROOT/data.db" ]; then
    created_default_admin=1
fi
if [ ! -e "$env_file" ]; then
    jwt_secret="$(openssl rand -hex 32)"
    panel_key="$(openssl rand -hex 32)"
    umask 077
    cat > "$env_file" <<EOF
DATABASE_URL=sqlite:$DATA_ROOT/data.db?mode=rwc
LISTEN=0.0.0.0:$panel_port
PUBLIC_DIR=$INSTALL_ROOT/public
NODE_ARTIFACT_DIR=$INSTALL_ROOT/node-assets
PUBLIC_PANEL_URL=$public_url
JWT_SECRET=$jwt_secret
PANEL_KEY=$panel_key
REGISTRATION_ENABLED=0
PANEL_CERTIFICATE_STATE_DIR=$DATA_ROOT/certificates
PANEL_CERTBOT_BINARY_PATH=/usr/bin/certbot
PANEL_CERTIFICATE_CHECK_INTERVAL_SECS=60
EOF
    chown root:relay-panel "$env_file"
    chmod 0640 "$env_file"
else
    info "Preserving existing configuration and secrets in $env_file"
fi

listen="$(sed -n 's/^LISTEN=//p' "$env_file" | tail -n 1)"
health_port="${listen##*:}"
[[ "$health_port" =~ ^[0-9]+$ ]] && [ "$health_port" -ge 1 ] && [ "$health_port" -le 65535 ] || \
    fail "Existing LISTEN does not contain a valid health-check port"

staging="$INSTALL_ROOT/releases/.${version}.staging.$$"
final="$INSTALL_ROOT/releases/$version"
old_final=""
old_current=""
rm -rf -- "$staging"
install -d -m 0755 "$staging/public" "$staging/node-assets/amd64"
install -m 0755 "$release_dir/reality-panel-linux-amd64" "$staging/relay-panel"
tar -xzf "$release_dir/reality-panel-web.tar.gz" -C "$staging/public"
[ -s "$staging/public/index.html" ] || fail "Web asset is missing index.html"
install -m 0755 "$release_dir/reality-node-linux-amd64" "$staging/node-assets/amd64/relay-node"
node_sha="$(sha256sum "$staging/node-assets/amd64/relay-node" | awk '{print $1}')"
node_size="$(stat -c '%s' "$staging/node-assets/amd64/relay-node")"
printf '{"version":"%s","sha256":"%s","size":%s}\n' "$version" "$node_sha" "$node_size" \
    > "$staging/node-assets/amd64/metadata.json"
chmod 0644 "$staging/node-assets/amd64/metadata.json"

if [ -L "$INSTALL_ROOT/current" ]; then old_current="$(readlink "$INSTALL_ROOT/current")"; fi
if [ -e "$final" ]; then
    old_final="$INSTALL_ROOT/releases/.${version}.old.$$"
    mv -T "$final" "$old_final"
fi
mv -T "$staging" "$final"
ln -sfn "releases/$version" "$INSTALL_ROOT/.current.new.$$"
mv -Tf "$INSTALL_ROOT/.current.new.$$" "$INSTALL_ROOT/current"
ln -sfn current/public "$INSTALL_ROOT/public"
ln -sfn current/node-assets "$INSTALL_ROOT/node-assets"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Reality Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=relay-panel
Group=relay-panel
WorkingDirectory=$DATA_ROOT
EnvironmentFile=$env_file
ExecStart=$INSTALL_ROOT/current/relay-panel
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$DATA_ROOT
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable relay-panel.service >/dev/null
systemctl restart relay-panel.service

healthy=0
for _ in $(seq 1 30); do
    body="$(curl -fsS "http://127.0.0.1:$health_port/api/v1/health" 2>/dev/null || true)"
    if printf '%s' "$body" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' && \
       printf '%s' "$body" | grep -Fq "\"version\":\"$version\""; then
        healthy=1
        break
    fi
    sleep 1
done

if [ "$healthy" -ne 1 ]; then
    warn "New release failed its health check; restoring the previous release."
    systemctl stop relay-panel.service || true
    # A same-version reinstall temporarily moved the previous release aside.
    # Restore that directory before repointing/restarting, otherwise current
    # still resolves to the failed replacement during the restart attempt.
    if [ -n "$old_final" ]; then
        rm -rf -- "$final"
        mv -T "$old_final" "$final"
        old_final=""
    fi
    if [ -n "$old_current" ]; then
        ln -sfn "$old_current" "$INSTALL_ROOT/.current.rollback.$$"
        mv -Tf "$INSTALL_ROOT/.current.rollback.$$" "$INSTALL_ROOT/current"
        systemctl start relay-panel.service || true
    fi
    fail "Reality Panel $release_tag did not become healthy"
fi

if [ -f "$DATA_ROOT/data.db" ]; then
    [ "$(sqlite3 "$DATA_ROOT/data.db" 'PRAGMA integrity_check;' 2>/dev/null)" = "ok" ] || fail "SQLite integrity check failed"
fi
rm -rf -- "$old_final"
install -d -m 0755 "$SCRIPT_ROOT"
install -m 0755 "$release_dir/install.sh" "$SCRIPT_ROOT/install.sh"
install -m 0755 "$release_dir/update.sh" "$SCRIPT_ROOT/update.sh"
install -m 0755 "$release_dir/deploy.sh" "$SCRIPT_ROOT/deploy.sh"
ln -sfn "$SCRIPT_ROOT/update.sh" "$UPDATE_COMMAND"

info "Reality Panel $release_tag is active and healthy."
info "Panel URL: $public_url"
info "Node artifact: $INSTALL_ROOT/node-assets/amd64/relay-node ($node_sha)"
if [ "$mode" = install ]; then
    success "安装成功"
else
    success "升级成功"
fi
if [ "$created_default_admin" -eq 1 ] && [ -f "$DATA_ROOT/data.db" ]; then
    initial_admin="$(sqlite3 "$DATA_ROOT/data.db" \
        "SELECT username FROM users WHERE id = 1 AND must_change_password = 1 LIMIT 1;" 2>/dev/null || true)"
    if [ "$initial_admin" = admin ]; then
        printf '管理员账号：%s\n初始密码：%s\n请首次登录后立即修改密码\n' "$initial_admin" 'admin123'
    fi
fi
