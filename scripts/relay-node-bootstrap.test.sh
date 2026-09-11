#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/relay-node-bootstrap.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

grep -Fq 'docker.io nginx libnginx-mod-stream openssl apparmor' "$SCRIPT"
grep -Fq 'apt-get install -y -qq kmod || warn' "$SCRIPT"
if grep -Fq 'docker.io nginx libnginx-mod-stream openssl certbot apparmor' "$SCRIPT"; then
  echo "new Node bootstrap must not require local Certbot" >&2
  exit 1
fi
grep -Fq 'command -v apparmor_parser' "$SCRIPT"
grep -Fq 'set -euo pipefail' "$SCRIPT"
grep -Fq '/opt/relay-node/relay-node --prepare-host-runtime' "$SCRIPT"
grep -Fq 'proxy_pass http://127.0.0.1:5245;' "$SCRIPT"
grep -Fq 'if [ "$EFFECTIVE_LITE_MODE" = 0 ]; then' "$SCRIPT"
grep -Fq 'refusing to convert an existing Standard node to Lite mode' "$SCRIPT"
grep -Fq '"openlist": true' "$SCRIPT"
! grep -Fq 'relay-panel-openlist' "$SCRIPT"
! grep -Fq '/var/lib/relay-panel/openlist' "$SCRIPT"
! grep -Fq '127.0.0.1:5244' "$SCRIPT"
standard_host_line="$(grep -nF 'step host-preparation' "$SCRIPT" | head -n1 | cut -d: -f1)"
lite_host_line="$(grep -nF 'step host-preparation' "$SCRIPT" | tail -n1 | cut -d: -f1)"
fallback_line="$(grep -nF 'step fallback' "$SCRIPT" | cut -d: -f1)"
nginx_line="$(grep -nF 'step nginx' "$SCRIPT" | tail -n1 | cut -d: -f1)"
[ "$standard_host_line" -lt "$fallback_line" ] || {
  echo "Standard Xiaoya preparation must complete before fallback configuration" >&2
  exit 1
}
[ "$lite_host_line" -gt "$nginx_line" ] || {
  echo "Lite fallback verification must run after Nginx starts" >&2
  exit 1
}

make_nginx_root() {
  local root="$1"
  mkdir -p "$root/etc/nginx/conf.d" "$root/etc/nginx/sites-enabled" \
    "$root/etc/nginx/sites-available"
  printf 'Debian default fixture\n' > "$root/etc/nginx/sites-available/default"
}

root="$TMP/valid"
make_nginx_root "$root"
ln -s ../sites-available/default "$root/etc/nginx/sites-enabled/default"
bash "$SCRIPT" --test-https-redirect "$root"
test ! -e "$root/etc/nginx/sites-enabled/default"
conf="$root/etc/nginx/conf.d/relay-panel-acme.conf"
grep -Fqx '    listen 80 default_server;' "$conf"
grep -Fqx '    listen [::]:80 default_server;' "$conf"
grep -Fqx '    server_name _;' "$conf"
grep -Fqx '    return 301 https://$host$request_uri;' "$conf"
! grep -Eq 'ssl_preread|listen 443|listen 8443|acme-challenge' "$conf"

conflict="$TMP/conflict"
make_nginx_root "$conflict"
printf 'custom operator config\n' > "$conflict/etc/nginx/sites-enabled/default"
if bash "$SCRIPT" --test-https-redirect "$conflict" >/dev/null 2>&1; then
  printf '[FAIL] non-symlink default site was removed\n' >&2
  exit 1
fi
grep -Fqx 'custom operator config' "$conflict/etc/nginx/sites-enabled/default"

lite="$TMP/lite"
bash "$SCRIPT" --test-lite-fallback "$lite"
test "$(cat "$lite/var/www/fallback/index.html")" != ""
lite_conf="$lite/etc/nginx/conf.d/relay-panel-lite-fallback.conf"
grep -Fqx '# RelayPanel managed Lite fallback' "$lite_conf"
grep -Fqx '    listen 127.0.0.1:5245;' "$lite_conf"
grep -Fq "location = /ping { default_type text/plain; return 200 'pong'; }" "$lite_conf"
! grep -Eq 'listen (0\.0\.0\.0:|\[::\]:)?5245|proxy_pass' "$lite_conf"

lite_conflict="$TMP/lite-conflict"
mkdir -p "$lite_conflict/var/www/fallback" "$lite_conflict/etc/nginx/conf.d"
printf 'operator page\n' > "$lite_conflict/var/www/fallback/index.html"
if bash "$SCRIPT" --test-lite-fallback "$lite_conflict" >/dev/null 2>&1; then
  echo "Lite fallback must not overwrite an unmanaged static page" >&2
  exit 1
fi
grep -Fqx 'operator page' "$lite_conflict/var/www/fallback/index.html"

mode_root="$TMP/mode"
mkdir -p "$mode_root/etc/relay-panel" "$mode_root/opt/relay-node" "$mode_root/etc/systemd/system"
test "$(bash "$SCRIPT" --test-lite-mode "$mode_root" 0)" = 0
test "$(bash "$SCRIPT" --test-lite-mode "$mode_root" 1)" = 1
printf 'legacy binary\n' > "$mode_root/opt/relay-node/relay-node"
if bash "$SCRIPT" --test-lite-mode "$mode_root" 1 >/dev/null 2>&1; then
  echo "existing Standard node must not be converted to Lite" >&2
  exit 1
fi
printf 'lite\n' > "$mode_root/etc/relay-panel/lite-mode"
test "$(bash "$SCRIPT" --test-lite-mode "$mode_root" 0)" = 1

bash -n "$SCRIPT"
printf 'relay-node HTTPS redirect bootstrap contract: PASS\n'
