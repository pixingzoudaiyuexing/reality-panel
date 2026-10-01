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
    [ "$(id -u)" -eq 0 ] || fail "Run as root."
    # Refuse symlinked roots/ancestors before either deleting children or invoking
    # installed helpers. Never follow a product-looking path into foreign state.
    local managed ancestor account_owned=0 account_entry="" account_uid="" group_owned=0 owned_gid=""
    for managed in "$INSTALL_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$SCRIPT_ROOT" \
        "$UPDATE_COMMAND" "$CONFIG_ROOT/installer-account" /etc/systemd/system/relay-panel.service; do
        ancestor="$managed"
        while [ "$ancestor" != / ] && [ -n "$ancestor" ]; do
            if [ -L "$ancestor" ]; then
                # The installer creates this exact leaf shortcut. Unlink it
                # without following the target; keep checking its ancestors.
                if [ "$ancestor" != "$UPDATE_COMMAND" ] || \
                   [ "$(readlink "$ancestor")" != "$SCRIPT_ROOT/update.sh" ]; then
                    fail "Refusing symlinked uninstall path: $ancestor"
                fi
            fi
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
            # Some userdel implementations already remove the private group.
            # Recheck identity/membership before deleting any remaining group.
            group_entry="$(getent group relay-panel || true)"
            IFS=: read -r group_name group_password group_gid group_members <<< "$group_entry"
            if [ -z "$group_entry" ]; then
                :
            elif [ "$group_gid" != "$owned_gid" ] || [ -n "$group_members" ]; then
                warn "Group relay-panel ownership changed; preserved the current group."
            # Preserve a group still used by another account, including primary GIDs.
            elif getent passwd | awk -F: -v gid="$owned_gid" '$4 == gid { found=1 } END { exit !found }'; then
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

account_created=0
if ! id relay-panel >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_ROOT" --shell /usr/sbin/nologin relay-panel
    account_created=1
fi
install -d -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
install -d -o relay-panel -g relay-panel -m 0750 "$DATA_ROOT"
install -d -o relay-panel -g relay-panel -m 0700 "$DATA_ROOT/certificates"
install -d -m 0750 "$CONFIG_ROOT"
if [ "$account_created" -eq 1 ]; then
    printf '%s:%s\n' "$(id -u relay-panel)" "$(id -g relay-panel)" > "$CONFIG_ROOT/installer-account"
    chmod 0600 "$CONFIG_ROOT/installer-account"
fi

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
