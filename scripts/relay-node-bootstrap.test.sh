#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/relay-node-bootstrap.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

grep -Fq 'docker.io nginx libnginx-mod-stream openssl apparmor' "$SCRIPT"
if grep -Fq 'docker.io nginx libnginx-mod-stream openssl certbot apparmor' "$SCRIPT"; then
  echo "new Node bootstrap must not require local Certbot" >&2
  exit 1
fi
grep -Fq 'command -v apparmor_parser' "$SCRIPT"

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

bash -n "$SCRIPT"
printf 'relay-node HTTPS redirect bootstrap contract: PASS\n'
