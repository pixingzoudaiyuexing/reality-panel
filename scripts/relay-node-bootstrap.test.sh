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
grep -Fq '"openlist": true' "$SCRIPT"
! grep -Fq 'relay-panel-openlist' "$SCRIPT"
! grep -Fq '/var/lib/relay-panel/openlist' "$SCRIPT"
! grep -Fq '127.0.0.1:5244' "$SCRIPT"
host_line="$(grep -nF 'step host-preparation' "$SCRIPT" | cut -d: -f1)"
fallback_line="$(grep -nF 'step fallback' "$SCRIPT" | cut -d: -f1)"
[ "$host_line" -lt "$fallback_line" ] || {
  echo "Xiaoya host preparation must complete before the 5245 fallback is written" >&2
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

bash -n "$SCRIPT"
printf 'relay-node HTTPS redirect bootstrap contract: PASS\n'
