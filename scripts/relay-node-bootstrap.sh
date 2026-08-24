#!/usr/bin/env bash
# RelayPanel Stage 1 bootstrap. Invoked by the panel over an authenticated SSH
# session with a mode-0600 config file and a verified relay-node artifact.
set -euo pipefail

BOOTSTRAP_STEP="bootstrap"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  printf 'BOOTSTRAP_FAILED_STEP=%s exit=1\n' "$BOOTSTRAP_STEP" >&2
  exit 1
}
info() { printf 'INFO: %s\n' "$*"; }
step() {
  BOOTSTRAP_STEP="$1"
  printf '[bootstrap] %s: start\n' "$BOOTSTRAP_STEP" >&2
}
step_ok() { printf '[bootstrap] %s: ok\n' "$BOOTSTRAP_STEP" >&2; }
report_failure() {
  local status=$?
  printf 'BOOTSTRAP_FAILED_STEP=%s exit=%s\n' "$BOOTSTRAP_STEP" "$status" >&2
}
trap report_failure ERR

NGINX_ROOT=""
CERTBOT_ROOT=""

nginx_path() {
  printf '%s%s\n' "$NGINX_ROOT" "$1"
}

certbot_path() {
  printf '%s%s\n' "$CERTBOT_ROOT" "$1"
}

ensure_certbot_base() {
  mkdir -p \
    "$(certbot_path /var/www/relay-panel-certbot/.well-known/acme-challenge)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/deploy)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/pre)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/post)"
}

ensure_relay_panel_stream_layout() {
  local nginx_dir nginx_conf stream_root stream_dir include_line expected_stream_root
  local external_streams include_locations include_count
  nginx_dir="$(nginx_path /etc/nginx)"
  nginx_conf="$(nginx_path /etc/nginx/nginx.conf)"
  stream_root="$(nginx_path /etc/nginx/relay-panel-stream.conf)"
  stream_dir="$(nginx_path /etc/nginx/relay-panel-stream.d)"
  include_line='include /etc/nginx/relay-panel-stream.conf;'
  expected_stream_root='# RelayPanel managed stream root; do not edit
stream {
    include /etc/nginx/relay-panel-stream.d/*.conf;
}
'

  [ -f "$nginx_conf" ] || fail "NGINX_CONFIG_INVALID: nginx.conf is missing"

  # Nginx accepts only one top-level stream context. The file below is ours;
  # anything else is an existing owner we cannot safely merge into.
  external_streams="$(find "$nginx_dir" -type f -print 2>/dev/null | while IFS= read -r file; do
    [ "$file" = "$stream_root" ] && continue
    if grep -qE '^[[:space:]]*stream[[:space:]]*\{' "$file"; then
      printf '%s\n' "$file"
    fi
  done)"
  if [ -n "$external_streams" ]; then
    fail "NGINX_STREAM_CONFLICT: existing non-RelayPanel top-level stream context: $(printf '%s' "$external_streams" | tr '\n' ' ')"
  fi

  include_locations="$(grep -RFlx -- "$include_line" "$nginx_dir" 2>/dev/null || true)"
  if [ -n "$include_locations" ]; then
    include_count="$(printf '%s\n' "$include_locations" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "$include_count" != 1 ] || [ "$include_locations" != "$nginx_conf" ]; then
      fail "NGINX_STREAM_CONFLICT: RelayPanel stream include is duplicated or outside nginx.conf"
    fi
  else
    printf '\n%s\n' "$include_line" >> "$nginx_conf"
  fi

  install -d -m 0755 "$stream_dir"
  printf '%s' "$expected_stream_root" > "$stream_root.tmp"
  mv -f "$stream_root.tmp" "$stream_root"
}

if [ "${1:-}" = "--test-nginx-layout" ]; then
  NGINX_ROOT="${2:?test nginx root required}"
  ensure_relay_panel_stream_layout
  exit 0
fi

if [ "${1:-}" = "--test-certbot-base" ]; then
  CERTBOT_ROOT="${2:?test certbot root required}"
  ensure_certbot_base
  exit 0
fi

CONFIG_FILE="${1:?bootstrap config path required}"
ARTIFACT_FILE="${2:?relay-node artifact path required}"
trap 'rm -f "$CONFIG_FILE" "$ARTIFACT_FILE"' EXIT

# shellcheck disable=SC1090
source "$CONFIG_FILE"

step preflight
[ "$(id -u)" = "0" ] || fail "root privileges are required"
command -v bash >/dev/null 2>&1 || fail "bash is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
[ -r /etc/os-release ] || fail "unsupported Linux distribution"
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) fail "only Debian or Ubuntu is supported" ;; esac

case "$(uname -m)" in
  x86_64|amd64) detected_arch=amd64 ;;
  aarch64|arm64) detected_arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
[ "$detected_arch" = "$RELAY_NODE_ARCH" ] || fail "artifact architecture mismatch"
[ "$(df -Pk / | awk 'NR == 2 { print $4 }')" -ge 524288 ] || fail "at least 512 MiB free disk is required"
step_ok

export DEBIAN_FRONTEND=noninteractive
step dependencies
apt-get update -y -qq
# curl is deliberately installed here rather than assumed by preflight.
apt-get install -y -qq ca-certificates curl docker.io nginx libnginx-mod-stream openssl certbot
step_ok

step certbot-base
ensure_certbot_base
step_ok

step docker
systemctl enable --now docker
docker info >/dev/null
step_ok

step nginx-layout
ensure_relay_panel_stream_layout
step_ok

step relay-node-files
install -d -m 0755 /opt/relay-node /etc/relay-node /var/lib/relay-panel \
  /etc/nginx/relay-panel-certs

actual_sha="$(sha256sum "$ARTIFACT_FILE" | awk '{print $1}')"
[ "$actual_sha" = "$RELAY_NODE_SHA256" ] || fail "relay-node sha256 verification failed"
install -m 0755 "$ARTIFACT_FILE" /opt/relay-node/relay-node.new
mv -f /opt/relay-node/relay-node.new /opt/relay-node/relay-node
/opt/relay-node/relay-node --version >/dev/null

# relay-node itself owns initial node-id creation. A pre-existing id (and both
# P0 LKG files) is never replaced during a repair/redeploy.
if [ -f /opt/relay-node/node-id ]; then
  chmod 0600 /opt/relay-node/node-id
fi

cat > /etc/relay-node/relay-node.env <<EOF
PANEL_URL='$PANEL_URL'
NODE_TOKEN='$NODE_TOKEN'
NGINX_SNI_ENABLED=1
NGINX_SNI_CONF_PATH=/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf
NGINX_SNI_DEFAULT_BACKEND=127.0.0.1:8443
NGINX_SNI_TEST_CMD='nginx -t'
NGINX_SNI_RELOAD_CMD='systemctl reload nginx'
NGINX_SNI_ACCESS_LOG_PATH=/var/log/nginx/relay-panel-sni.log
NGINX_SNI_TRAFFIC_STATE_PATH=/opt/relay-node/nginx-sni-log.offset
EOF
chmod 0600 /etc/relay-node/relay-node.env

cat > /etc/systemd/system/relay-node.service <<'EOF'
[Unit]
Description=RelayPanel relay-node
After=network-online.target docker.service nginx.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/relay-node/relay-node.env
WorkingDirectory=/opt/relay-node
ExecStart=/opt/relay-node/relay-node
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
step_ok

# Pin a versioned image. Existing RelayPanel data is always retained and an
# already-correct container is left untouched. This pinned image runs as UID
# 1001, so the bind mount must be writable by that account.
step openlist
OPENLIST_IMAGE="openlistteam/openlist@sha256:3bfba7ab379594c3f140e61ecc9096d66360cd4654ccea9f6cb8164b679a669d"
install -d -m 0750 -o 1001 -g 1001 /var/lib/relay-panel/openlist
chown -R 1001:1001 /var/lib/relay-panel/openlist
if ! docker inspect relay-panel-openlist >/dev/null 2>&1; then
  docker pull "$OPENLIST_IMAGE"
  docker run -d --name relay-panel-openlist --restart unless-stopped \
    -p 127.0.0.1:5244:5244 \
    -v /var/lib/relay-panel/openlist:/opt/openlist/data \
    "$OPENLIST_IMAGE"
else
  docker start relay-panel-openlist >/dev/null 2>&1 || true
fi
docker inspect -f '{{.State.Running}}' relay-panel-openlist | grep -Fx true >/dev/null
step_ok

step fallback
if [ ! -f /etc/nginx/relay-panel-certs/fallback.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
    -keyout /etc/nginx/relay-panel-certs/fallback.key \
    -out /etc/nginx/relay-panel-certs/fallback.crt -subj '/CN=relay-panel-bootstrap' >/dev/null 2>&1
  chmod 0600 /etc/nginx/relay-panel-certs/fallback.key
fi
cat > /etc/nginx/conf.d/relay-panel-fallback.conf <<'EOF'
server {
    listen 127.0.0.1:8443 ssl;
    server_name _;
    ssl_certificate /etc/nginx/relay-panel-certs/fallback.crt;
    ssl_certificate_key /etc/nginx/relay-panel-certs/fallback.key;
    location / { proxy_pass http://127.0.0.1:5244; }
}
EOF
step_ok

step nginx
nginx -t
systemctl enable --now nginx
systemctl reload nginx
step_ok

step relay-node-service
systemctl daemon-reload
systemctl enable --now relay-node
systemctl is-active --quiet relay-node
step_ok

step verify-openlist
curl -fsS --max-time 10 http://127.0.0.1:5244/ >/dev/null
step_ok

step verify-fallback
curl -kfsS --max-time 10 https://127.0.0.1:8443/ >/dev/null
step_ok
info "bootstrap complete"
