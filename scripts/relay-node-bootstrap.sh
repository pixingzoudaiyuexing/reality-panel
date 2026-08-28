#!/usr/bin/env bash
# RelayPanel Stage 1 bootstrap. Invoked by the panel over an authenticated SSH
# session with a mode-0600 config file and a verified relay-node artifact.
set -euo pipefail

BOOTSTRAP_STEP="bootstrap"
TRANSACTION_DIR=""
TRANSACTION_ROOT=""
TRANSACTION_CAPTURED=0
TRANSACTION_FINALIZED=0
TRANSACTION_LOCK_HELD=0
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
NGINX_BIN="${NGINX_BIN:-nginx}"

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
warn() { printf 'WARNING: %s\n' "$*" >&2; }

NGINX_ROOT=""
CERTBOT_ROOT=""
PORT_PREFLIGHT_INPUT=""
NGINX_RELOAD_REQUIRED=0
RELAY_NODE_RESTART_REQUIRED=0
SYSTEMD_RELOAD_REQUIRED=0
NGINX_SNI_CONF_PATH=/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf
CAMOUFLAGE_SITES_MANIFEST_PATH=/etc/relay-panel/camouflage-sites.json
CAMOUFLAGE_SITES_STATE_DIR=/opt/relay-node/camouflage-sites
CAMOUFLAGE_WRAPPER_CONF_PATH=/etc/nginx/conf.d/relay-panel-fallback.conf
CERTIFICATE_CHECK_INTERVAL_SECS=43200
CERTBOT_BINARY_PATH=/usr/bin/certbot
CERTBOT_LIVE_DIR=/etc/letsencrypt/live
CERTIFICATE_HTTP01_WEBROOT=/var/www/relay-panel-certbot
CERTIFICATE_HTTP01_CONF_PATH=/etc/nginx/conf.d/relay-panel-acme.conf
CERTIFICATE_STATE_DIR=/opt/relay-node/certificates

managed_path() {
  printf '%s%s\n' "$TRANSACTION_ROOT" "$1"
}

transaction_key_path() {
  printf '%s/files/%s\n' "$TRANSACTION_DIR" "$1"
}

snapshot_file() {
  local key="$1" path="$2" source backup
  source="$(managed_path "$path")"
  backup="$(transaction_key_path "$key")"
  if [ -L "$source" ]; then
    fail "TRANSACTION_INVALID: managed path is a symlink: $path"
  fi
  if [ -e "$source" ]; then
    printf 'present\n' > "$TRANSACTION_DIR/$key.state"
    cp -a -- "$source" "$backup"
  else
    printf 'absent\n' > "$TRANSACTION_DIR/$key.state"
  fi
}

snapshot_symlink() {
  local key="$1" path="$2" source
  source="$(managed_path "$path")"
  if [ -L "$source" ]; then
    printf 'present\n' > "$TRANSACTION_DIR/$key.link-state"
    readlink "$source" > "$TRANSACTION_DIR/$key.link-target"
  elif [ -e "$source" ]; then
    fail "TRANSACTION_INVALID: expected symlink path is not a symlink: $path"
  else
    printf 'absent\n' > "$TRANSACTION_DIR/$key.link-state"
  fi
}

symlink_matches_snapshot() {
  local key="$1" path="$2" target state
  target="$(managed_path "$path")"
  state="$(cat "$TRANSACTION_DIR/$key.link-state")"
  if [ "$state" = present ]; then
    [ -L "$target" ] && [ "$(readlink "$target")" = "$(cat "$TRANSACTION_DIR/$key.link-target")" ]
  else
    [ ! -e "$target" ] && [ ! -L "$target" ]
  fi
}

restore_symlink_if_changed() {
  local key="$1" path="$2" target state
  symlink_matches_snapshot "$key" "$path" && return 0
  target="$(managed_path "$path")"
  state="$(cat "$TRANSACTION_DIR/$key.link-state")"
  rm -f -- "$target"
  if [ "$state" = present ]; then
    install -d -m 0755 "$(dirname "$target")"
    ln -s -- "$(cat "$TRANSACTION_DIR/$key.link-target")" "$target"
  elif [ "$state" != absent ]; then
    return 1
  fi
}

restore_file() {
  local key="$1" path="$2" target backup state staged
  target="$(managed_path "$path")"
  backup="$(transaction_key_path "$key")"
  state="$(cat "$TRANSACTION_DIR/$key.state")"
  staged="$target.rollback"
  rm -f -- "$staged" "$target.new" "$target.tmp"
  if [ "$state" = present ]; then
    install -d -m 0755 "$(dirname "$target")"
    cp -a -- "$backup" "$staged"
    mv -f -- "$staged" "$target"
  elif [ "$state" = absent ]; then
    rm -f -- "$target"
  else
    return 1
  fi
}

file_matches_snapshot() {
  local key="$1" path="$2" target backup state
  target="$(managed_path "$path")"
  backup="$(transaction_key_path "$key")"
  state="$(cat "$TRANSACTION_DIR/$key.state")"
  if [ "$state" = present ]; then
    [ -e "$target" ] && cmp -s -- "$backup" "$target"
  else
    [ ! -e "$target" ]
  fi
}

restore_file_if_changed() {
  local key="$1" path="$2"
  file_matches_snapshot "$key" "$path" && return 0
  restore_file "$key" "$path"
}

snapshot_directory_state() {
  local key="$1" path="$2" target
  target="$(managed_path "$path")"
  if [ -L "$target" ]; then
    fail "TRANSACTION_INVALID: managed directory is a symlink: $path"
  fi
  if [ -d "$target" ]; then
    printf 'present\n' > "$TRANSACTION_DIR/$key.dir-state"
  elif [ -e "$target" ]; then
    fail "TRANSACTION_INVALID: managed directory path is not a directory: $path"
  else
    printf 'absent\n' > "$TRANSACTION_DIR/$key.dir-state"
  fi
}

restore_directory_state() {
  local key="$1" path="$2" target state
  target="$(managed_path "$path")"
  state="$(cat "$TRANSACTION_DIR/$key.dir-state")"
  case "$state" in
    present) [ -d "$target" ] ;;
    absent)
      rmdir -- "$target" 2>/dev/null || true
      [ ! -e "$target" ]
      ;;
    *) return 1 ;;
  esac
}

remove_file_staging() {
  local path="$1" target
  target="$(managed_path "$path")"
  rm -f -- "$target.new" "$target.rollback" "$target.tmp"
}

acquire_transaction_lock() {
  local attempts=0 owner=""
  while ! mkdir -- "$TRANSACTION_DIR/lock" 2>/dev/null; do
    owner="$(cat "$TRANSACTION_DIR/lock/pid" 2>/dev/null || true)"
    case "$owner" in
      ''|*[!0-9]*) ;;
      *)
        if ! kill -0 "$owner" 2>/dev/null; then
          rm -f -- "$TRANSACTION_DIR/lock/pid"
          rmdir -- "$TRANSACTION_DIR/lock" 2>/dev/null || true
          continue
        fi
        ;;
    esac
    attempts=$((attempts + 1))
    [ "$attempts" -lt 50 ] || return 1
    sleep 1
  done
  printf '%s\n' "$$" > "$TRANSACTION_DIR/lock/pid"
  TRANSACTION_LOCK_HELD=1
}

release_transaction_lock() {
  if [ "$TRANSACTION_LOCK_HELD" = 1 ]; then
    rm -f -- "$TRANSACTION_DIR/lock/pid"
    rmdir -- "$TRANSACTION_DIR/lock" 2>/dev/null || true
    TRANSACTION_LOCK_HELD=0
  fi
}

retry_command() {
  local label="$1"
  shift
  if "$@"; then
    return 0
  fi
  warn "$label failed once; retrying rollback recovery"
  "$@"
}

service_state() {
  local action="$1" unit="$2"
  if "$SYSTEMCTL_BIN" "$action" --quiet "$unit" >/dev/null 2>&1; then
    printf 'yes\n'
  else
    printf 'no\n'
  fi
}

capture_transaction() {
  [ -n "$TRANSACTION_DIR" ] || fail "transaction directory is required"
  [ ! -e "$TRANSACTION_DIR/state" ] || fail "transaction already exists"
  install -d -m 0700 "$TRANSACTION_DIR" "$TRANSACTION_DIR/files"
  if [ "$TRANSACTION_LOCK_HELD" = 0 ]; then
    acquire_transaction_lock || fail "TRANSACTION_BUSY: another bootstrap transaction is active"
  fi

  snapshot_file binary /opt/relay-node/relay-node
  snapshot_file env /etc/relay-node/relay-node.env
  snapshot_file unit /etc/systemd/system/relay-node.service
  snapshot_file nginx_conf /etc/nginx/nginx.conf
  snapshot_file stream_root /etc/nginx/relay-panel-stream.conf
  snapshot_file sni_conf "$NGINX_SNI_CONF_PATH"
  snapshot_file wrapper_conf "$CAMOUFLAGE_WRAPPER_CONF_PATH"
  snapshot_file http01_conf "$CERTIFICATE_HTTP01_CONF_PATH"
  snapshot_symlink nginx_default_site /etc/nginx/sites-enabled/default
  snapshot_file fallback_cert /etc/nginx/relay-panel-certs/fallback.crt
  snapshot_file fallback_key /etc/nginx/relay-panel-certs/fallback.key
  snapshot_file capabilities /opt/relay-node/provisioning-capabilities.json
  snapshot_directory_state env_dir /etc/relay-node
  snapshot_directory_state stream_dir /etc/nginx/relay-panel-stream.d
  snapshot_directory_state fallback_cert_dir /etc/nginx/relay-panel-certs

  printf '%s\n' "$NGINX_SNI_CONF_PATH" > "$TRANSACTION_DIR/sni.path"
  printf '%s\n' "$CAMOUFLAGE_WRAPPER_CONF_PATH" > "$TRANSACTION_DIR/wrapper.path"
  printf '%s\n' "$CERTIFICATE_HTTP01_CONF_PATH" > "$TRANSACTION_DIR/http01.path"

  service_state is-active relay-node > "$TRANSACTION_DIR/relay-node.active"
  service_state is-enabled relay-node > "$TRANSACTION_DIR/relay-node.enabled"
  service_state is-active nginx > "$TRANSACTION_DIR/nginx.active"
  service_state is-enabled nginx > "$TRANSACTION_DIR/nginx.enabled"
  if [ -f "$(managed_path /opt/relay-node/relay-node)" ]; then
    sha256sum "$(managed_path /opt/relay-node/relay-node)" | awk '{print $1}' \
      > "$TRANSACTION_DIR/binary.sha256"
  else
    : > "$TRANSACTION_DIR/binary.sha256"
  fi
  printf 'pending\n' > "$TRANSACTION_DIR/state"
  TRANSACTION_CAPTURED=1
}

load_transaction_paths() {
  NGINX_SNI_CONF_PATH="$(cat "$TRANSACTION_DIR/sni.path")"
  CAMOUFLAGE_WRAPPER_CONF_PATH="$(cat "$TRANSACTION_DIR/wrapper.path")"
  CERTIFICATE_HTTP01_CONF_PATH="$(cat "$TRANSACTION_DIR/http01.path")"
  validate_managed_path "$NGINX_SNI_CONF_PATH" "Nginx SNI config path"
  validate_managed_path "$CAMOUFLAGE_WRAPPER_CONF_PATH" "camouflage wrapper path"
  validate_managed_path "$CERTIFICATE_HTTP01_CONF_PATH" "HTTP-01 config path"
}

restore_enablement() {
  local unit="$1" expected="$2" current
  current="$(service_state is-enabled "$unit")"
  if [ "$expected" = yes ] && [ "$current" != yes ]; then
    retry_command "enable $unit" "$SYSTEMCTL_BIN" enable "$unit" >/dev/null
  elif [ "$expected" != yes ] && [ "$current" = yes ]; then
    retry_command "disable $unit" "$SYSTEMCTL_BIN" disable "$unit" >/dev/null
  fi
}

rollback_transaction() {
  local failed=0 relay_was_active relay_was_enabled nginx_was_active nginx_was_enabled
  local relay_files_changed=0 nginx_files_changed=0 unit_changed=0
  local restored_binary_sha pid running_sha relay_is_active nginx_is_active key path item
  [ -f "$TRANSACTION_DIR/state" ] || return 0
  case "$(cat "$TRANSACTION_DIR/state")" in
    rolled_back) return 0 ;;
    committed) return 1 ;;
  esac

  relay_was_active="$(cat "$TRANSACTION_DIR/relay-node.active")"
  relay_was_enabled="$(cat "$TRANSACTION_DIR/relay-node.enabled")"
  nginx_was_active="$(cat "$TRANSACTION_DIR/nginx.active")"
  nginx_was_enabled="$(cat "$TRANSACTION_DIR/nginx.enabled")"

  file_matches_snapshot binary /opt/relay-node/relay-node || relay_files_changed=1
  file_matches_snapshot env /etc/relay-node/relay-node.env || relay_files_changed=1
  if ! file_matches_snapshot unit /etc/systemd/system/relay-node.service; then
    relay_files_changed=1
    unit_changed=1
  fi
  for item in \
    "nginx_conf:/etc/nginx/nginx.conf" \
    "stream_root:/etc/nginx/relay-panel-stream.conf" \
    "sni_conf:$NGINX_SNI_CONF_PATH" \
    "wrapper_conf:$CAMOUFLAGE_WRAPPER_CONF_PATH" \
    "http01_conf:$CERTIFICATE_HTTP01_CONF_PATH" \
    "fallback_cert:/etc/nginx/relay-panel-certs/fallback.crt" \
    "fallback_key:/etc/nginx/relay-panel-certs/fallback.key"
  do
    key="${item%%:*}"
    path="${item#*:}"
    file_matches_snapshot "$key" "$path" || nginx_files_changed=1
  done
  symlink_matches_snapshot nginx_default_site /etc/nginx/sites-enabled/default \
    || nginx_files_changed=1

  restore_file_if_changed binary /opt/relay-node/relay-node || failed=1
  restore_file_if_changed env /etc/relay-node/relay-node.env || failed=1
  restore_file_if_changed unit /etc/systemd/system/relay-node.service || failed=1
  restore_file_if_changed nginx_conf /etc/nginx/nginx.conf || failed=1
  restore_file_if_changed stream_root /etc/nginx/relay-panel-stream.conf || failed=1
  restore_file_if_changed sni_conf "$NGINX_SNI_CONF_PATH" || failed=1
  restore_file_if_changed wrapper_conf "$CAMOUFLAGE_WRAPPER_CONF_PATH" || failed=1
  restore_file_if_changed http01_conf "$CERTIFICATE_HTTP01_CONF_PATH" || failed=1
  restore_symlink_if_changed nginx_default_site /etc/nginx/sites-enabled/default || failed=1
  restore_file_if_changed fallback_cert /etc/nginx/relay-panel-certs/fallback.crt || failed=1
  restore_file_if_changed fallback_key /etc/nginx/relay-panel-certs/fallback.key || failed=1
  restore_file_if_changed capabilities /opt/relay-node/provisioning-capabilities.json || failed=1

  if [ "$unit_changed" = 1 ]; then
    retry_command "systemd daemon-reload" "$SYSTEMCTL_BIN" daemon-reload || failed=1
  fi
  restore_enablement relay-node "$relay_was_enabled" || failed=1
  restore_enablement nginx "$nginx_was_enabled" || failed=1

  nginx_is_active="$(service_state is-active nginx)"
  if [ "$nginx_was_active" = yes ]; then
    if "$NGINX_BIN" -t; then
      if [ "$nginx_is_active" != yes ]; then
        retry_command "Nginx start" "$SYSTEMCTL_BIN" start nginx || failed=1
      elif [ "$nginx_files_changed" = 1 ]; then
        retry_command "Nginx reload" "$SYSTEMCTL_BIN" reload nginx || failed=1
      fi
    else
      failed=1
    fi
    "$SYSTEMCTL_BIN" is-active --quiet nginx || failed=1
  else
    if [ -f "$(managed_path /etc/nginx/nginx.conf)" ]; then
      "$NGINX_BIN" -t || failed=1
    fi
    if [ "$nginx_is_active" = yes ]; then
      retry_command "Nginx stop" "$SYSTEMCTL_BIN" stop nginx || failed=1
    fi
  fi

  restored_binary_sha="$(cat "$TRANSACTION_DIR/binary.sha256")"
  relay_is_active="$(service_state is-active relay-node)"
  if [ "$relay_was_active" = yes ]; then
    pid="$("$SYSTEMCTL_BIN" show -p MainPID --value relay-node 2>/dev/null || true)"
    running_sha=""
    case "$pid" in ''|0|*[!0-9]*) ;;
      *) running_sha="$(sha256sum "$(managed_path "/proc/$pid/exe")" 2>/dev/null | awk '{print $1}')" ;;
    esac
    if [ "$relay_is_active" != yes ]; then
      retry_command "relay-node start" "$SYSTEMCTL_BIN" start relay-node || failed=1
    elif [ "$relay_files_changed" = 1 ] \
      || [ -z "$restored_binary_sha" ] \
      || [ "$running_sha" != "$restored_binary_sha" ]; then
      retry_command "relay-node restart" "$SYSTEMCTL_BIN" restart relay-node || failed=1
    fi
    "$SYSTEMCTL_BIN" is-active --quiet relay-node || failed=1
    pid="$("$SYSTEMCTL_BIN" show -p MainPID --value relay-node 2>/dev/null || true)"
    case "$pid" in ''|0|*[!0-9]*) failed=1 ;;
      *)
        running_sha="$(sha256sum "$(managed_path "/proc/$pid/exe")" 2>/dev/null | awk '{print $1}')"
        [ -n "$restored_binary_sha" ] && [ "$running_sha" = "$restored_binary_sha" ] \
          || failed=1
        ;;
    esac
  else
    if [ "$relay_is_active" = yes ]; then
      retry_command "relay-node stop" "$SYSTEMCTL_BIN" stop relay-node || failed=1
    fi
    if "$SYSTEMCTL_BIN" is-active --quiet relay-node >/dev/null 2>&1; then
      failed=1
    fi
  fi

  file_matches_snapshot binary /opt/relay-node/relay-node || failed=1
  file_matches_snapshot env /etc/relay-node/relay-node.env || failed=1
  file_matches_snapshot unit /etc/systemd/system/relay-node.service || failed=1
  file_matches_snapshot nginx_conf /etc/nginx/nginx.conf || failed=1
  file_matches_snapshot stream_root /etc/nginx/relay-panel-stream.conf || failed=1
  file_matches_snapshot sni_conf "$NGINX_SNI_CONF_PATH" || failed=1
  file_matches_snapshot wrapper_conf "$CAMOUFLAGE_WRAPPER_CONF_PATH" || failed=1
  file_matches_snapshot http01_conf "$CERTIFICATE_HTTP01_CONF_PATH" || failed=1
  symlink_matches_snapshot nginx_default_site /etc/nginx/sites-enabled/default || failed=1
  file_matches_snapshot fallback_cert /etc/nginx/relay-panel-certs/fallback.crt || failed=1
  file_matches_snapshot fallback_key /etc/nginx/relay-panel-certs/fallback.key || failed=1
  file_matches_snapshot capabilities /opt/relay-node/provisioning-capabilities.json || failed=1
  restore_directory_state fallback_cert_dir /etc/nginx/relay-panel-certs || failed=1
  restore_directory_state stream_dir /etc/nginx/relay-panel-stream.d || failed=1
  restore_directory_state env_dir /etc/relay-node || failed=1

  remove_file_staging /opt/relay-node/relay-node
  remove_file_staging /opt/relay-node/provisioning-capabilities.json
  remove_file_staging /etc/relay-node/relay-node.env
  remove_file_staging /etc/systemd/system/relay-node.service
  remove_file_staging /etc/nginx/nginx.conf
  remove_file_staging /etc/nginx/relay-panel-stream.conf
  remove_file_staging "$NGINX_SNI_CONF_PATH"
  remove_file_staging "$CAMOUFLAGE_WRAPPER_CONF_PATH"
  remove_file_staging "$CERTIFICATE_HTTP01_CONF_PATH"
  remove_file_staging /etc/nginx/relay-panel-certs/fallback.crt
  remove_file_staging /etc/nginx/relay-panel-certs/fallback.key
  rm -rf -- "$TRANSACTION_DIR/candidate"

  if [ "$failed" = 0 ]; then
    printf 'rolled_back\n' > "$TRANSACTION_DIR/state"
    rm -rf -- "$TRANSACTION_DIR/files"
    find "$TRANSACTION_DIR" -maxdepth 1 -type f \
      \( -name '*.state' -o -name '*.dir-state' -o -name '*.link-state' \
         -o -name '*.link-target' -o -name '*.sha256' \
         -o -name '*.active' -o -name '*.enabled' \) \
      -delete
    return 0
  fi
  return 1
}

commit_transaction() {
  [ -f "$TRANSACTION_DIR/state" ] || return 1
  if [ "$(cat "$TRANSACTION_DIR/state")" = committed ]; then
    TRANSACTION_FINALIZED=1
    return 0
  fi
  [ "$(cat "$TRANSACTION_DIR/state")" = pending ] || return 1
  printf 'committed\n' > "$TRANSACTION_DIR/state"
  rm -rf -- "$TRANSACTION_DIR/files"
  rm -rf -- "$TRANSACTION_DIR/candidate"
  find "$TRANSACTION_DIR" -maxdepth 1 -type f \
    \( -name '*.state' -o -name '*.dir-state' -o -name '*.link-state' \
       -o -name '*.link-target' -o -name '*.sha256' \
       -o -name '*.active' -o -name '*.enabled' \
       -o -name '*.path' \) \
    -delete
  TRANSACTION_FINALIZED=1
}

on_exit() {
  local status=$?
  trap - EXIT ERR
  if [ -n "${CONFIG_FILE:-}" ]; then rm -f -- "$CONFIG_FILE"; fi
  if [ -n "${ARTIFACT_FILE:-}" ]; then rm -f -- "$ARTIFACT_FILE"; fi
  if [ "$status" -ne 0 ]; then
    printf 'BOOTSTRAP_FAILED_STEP=%s exit=%s\n' "$BOOTSTRAP_STEP" "$status" >&2
    if [ "$TRANSACTION_CAPTURED" = 1 ] && [ "$TRANSACTION_FINALIZED" = 0 ]; then
      if rollback_transaction; then
        printf 'BOOTSTRAP_ROLLBACK=SUCCESS\n' >&2
      else
        printf 'BOOTSTRAP_ROLLBACK=FAILED\n' >&2
      fi
    fi
  fi
  release_transaction_lock
  exit "$status"
}

nginx_path() {
  printf '%s%s\n' "$NGINX_ROOT" "$1"
}

certbot_path() {
  printf '%s%s\n' "$CERTBOT_ROOT" "$1"
}

existing_env_value() {
  local key="$1" fallback="$2" value=""
  if [ -f /etc/relay-node/relay-node.env ]; then
    value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' \
      /etc/relay-node/relay-node.env)"
    case "$value" in
      \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
  fi
  printf '%s\n' "${value:-$fallback}"
}

filter_unmanaged_env() {
  local input="$1" output="$2"
  awk -F= '
    BEGIN {
      split("PANEL_URL NODE_TOKEN NGINX_SNI_ENABLED NGINX_SNI_CONF_PATH NGINX_SNI_DEFAULT_BACKEND NGINX_SNI_TEST_CMD NGINX_SNI_RELOAD_CMD NGINX_SNI_ACCESS_LOG_PATH NGINX_SNI_TRAFFIC_STATE_PATH CAMOUFLAGE_SITES_ENABLED CAMOUFLAGE_SITES_MANIFEST_PATH CAMOUFLAGE_SITES_STATE_DIR CAMOUFLAGE_WRAPPER_CONF_PATH CERTIFICATE_LIFECYCLE_ENABLED CERTIFICATE_LIFECYCLE_CHECK_INTERVAL_SECS CERTBOT_BINARY_PATH CERTBOT_LIVE_DIR CERTIFICATE_HTTP01_WEBROOT CERTIFICATE_HTTP01_CONF_PATH CERTIFICATE_STATE_DIR PROVISIONING_CAPABILITIES_PATH", keys, " ");
      for (key_index in keys) managed[keys[key_index]] = 1;
    }
    !($1 in managed) { print }
  ' "$input" > "$output"
}

validate_managed_path() {
  local value="$1" label="$2"
  case "$value" in
    /*) ;;
    *) fail "$label must be an absolute path" ;;
  esac
  case "$value" in
    *[!A-Za-z0-9_./-]*) fail "$label contains unsupported characters" ;;
  esac
}

load_existing_managed_settings() {
  NGINX_SNI_CONF_PATH="$(existing_env_value NGINX_SNI_CONF_PATH "$NGINX_SNI_CONF_PATH")"
  CAMOUFLAGE_SITES_MANIFEST_PATH="$(existing_env_value CAMOUFLAGE_SITES_MANIFEST_PATH "$CAMOUFLAGE_SITES_MANIFEST_PATH")"
  CAMOUFLAGE_SITES_STATE_DIR="$(existing_env_value CAMOUFLAGE_SITES_STATE_DIR "$CAMOUFLAGE_SITES_STATE_DIR")"
  CAMOUFLAGE_WRAPPER_CONF_PATH="$(existing_env_value CAMOUFLAGE_WRAPPER_CONF_PATH "$CAMOUFLAGE_WRAPPER_CONF_PATH")"
  CERTIFICATE_CHECK_INTERVAL_SECS="$(existing_env_value CERTIFICATE_LIFECYCLE_CHECK_INTERVAL_SECS "$CERTIFICATE_CHECK_INTERVAL_SECS")"
  CERTBOT_BINARY_PATH="$(existing_env_value CERTBOT_BINARY_PATH "$CERTBOT_BINARY_PATH")"
  CERTBOT_LIVE_DIR="$(existing_env_value CERTBOT_LIVE_DIR "$CERTBOT_LIVE_DIR")"
  CERTIFICATE_HTTP01_WEBROOT="$(existing_env_value CERTIFICATE_HTTP01_WEBROOT "$CERTIFICATE_HTTP01_WEBROOT")"
  CERTIFICATE_HTTP01_CONF_PATH="$(existing_env_value CERTIFICATE_HTTP01_CONF_PATH "$CERTIFICATE_HTTP01_CONF_PATH")"
  CERTIFICATE_STATE_DIR="$(existing_env_value CERTIFICATE_STATE_DIR "$CERTIFICATE_STATE_DIR")"

  validate_managed_path "$NGINX_SNI_CONF_PATH" "Nginx SNI config path"
  validate_managed_path "$CAMOUFLAGE_SITES_MANIFEST_PATH" "camouflage manifest path"
  validate_managed_path "$CAMOUFLAGE_SITES_STATE_DIR" "camouflage state path"
  validate_managed_path "$CAMOUFLAGE_WRAPPER_CONF_PATH" "camouflage wrapper path"
  validate_managed_path "$CERTBOT_BINARY_PATH" "Certbot binary path"
  validate_managed_path "$CERTBOT_LIVE_DIR" "Certbot live path"
  validate_managed_path "$CERTIFICATE_HTTP01_WEBROOT" "HTTP-01 webroot"
  validate_managed_path "$CERTIFICATE_HTTP01_CONF_PATH" "HTTP-01 config path"
  validate_managed_path "$CERTIFICATE_STATE_DIR" "certificate state path"
  case "$CERTIFICATE_CHECK_INTERVAL_SECS" in
    ''|*[!0-9]*) fail "certificate lifecycle interval is invalid" ;;
  esac
  [ "$CERTIFICATE_CHECK_INTERVAL_SECS" -ge 60 ] \
    || fail "certificate lifecycle interval must be at least 60 seconds"
}

ensure_certbot_base() {
  mkdir -p \
    "$(certbot_path /var/www/relay-panel-certbot/.well-known/acme-challenge)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/deploy)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/pre)" \
    "$(certbot_path /etc/letsencrypt/renewal-hooks/post)"
}

is_managed_camouflage_config() {
  local path="$1"
  [ -f "$path" ] || return 1
  grep -qE '^# (generated by relay-node; TLS camouflage sites|RelayPanel managed bootstrap camouflage fallback)$' "$path" && return 0
  grep -qF 'listen 127.0.0.1:8443 ssl;' "$path" \
    && grep -qF 'ssl_certificate /etc/nginx/relay-panel-certs/fallback.crt;' "$path" \
    && grep -qF 'proxy_pass http://127.0.0.1:5244;' "$path"
}

ensure_https_redirect() {
  local conf default_site target tmp
  conf="$(nginx_path "$CERTIFICATE_HTTP01_CONF_PATH")"
  default_site="$(nginx_path /etc/nginx/sites-enabled/default)"

  if [ -L "$default_site" ]; then
    target="$(readlink "$default_site")"
    case "$target" in
      ../sites-available/default|/etc/nginx/sites-available/default)
        rm -f -- "$default_site"
        NGINX_RELOAD_REQUIRED=1
        ;;
      *) fail "NGINX_CONFIG_CONFLICT: refusing to remove non-Debian default site link" ;;
    esac
  elif [ -e "$default_site" ]; then
    fail "NGINX_CONFIG_CONFLICT: refusing to remove non-symlink default site"
  fi

  if [ -f "$conf" ] \
    && ! grep -qE '^# generated by relay-node; (ACME HTTP-01 only|global HTTP to HTTPS redirect)$' "$conf"; then
    fail "NGINX_CONFIG_CONFLICT: :80 config is not relay-node-managed"
  fi
  install -d -m 0755 "$(dirname "$conf")"
  tmp="$conf.tmp"
  cat > "$tmp" <<'EOF'
# generated by relay-node; global HTTP to HTTPS redirect
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF
  if [ -f "$conf" ] && cmp -s "$tmp" "$conf"; then
    rm -f -- "$tmp"
  else
    mv -f -- "$tmp" "$conf"
    NGINX_RELOAD_REQUIRED=1
  fi
}

is_managed_listener_config() {
  local port="$1"
  case "$port" in
    443)
      grep -qF '# generated by relay-node; do not edit' \
        "$(nginx_path "$NGINX_SNI_CONF_PATH")" 2>/dev/null
      ;;
    8443)
      is_managed_camouflage_config "$(nginx_path "$CAMOUFLAGE_WRAPPER_CONF_PATH")"
      ;;
    80)
      grep -qE '^# generated by relay-node; (ACME HTTP-01 only|global HTTP to HTTPS redirect)$' \
        "$(nginx_path "$CERTIFICATE_HTTP01_CONF_PATH")" 2>/dev/null
      ;;
    *) return 1 ;;
  esac
}

listener_lines() {
  local port="$1"
  if [ -n "$PORT_PREFLIGHT_INPUT" ]; then
    awk -v suffix=":$port" '$4 ~ suffix "$" { print }' "$PORT_PREFLIGHT_INPUT"
  elif command -v ss >/dev/null 2>&1; then
    ss -H -ltnp | awk -v suffix=":$port" '$4 ~ suffix "$" { print }'
  fi
}

ensure_listener_is_managed_or_free() {
  local port="$1" lines
  lines="$(listener_lines "$port")"
  [ -n "$lines" ] || return 0
  case "$lines" in
    *nginx*) ;;
    *) fail "PORT_CONFLICT: :$port is owned by an unmanaged process" ;;
  esac
  # :80 is an Nginx HTTP listener and can already be active before our managed
  # redirect is installed. Public stream :443 and camouflage :8443 are exclusive
  # data-plane listeners and therefore require Reality Panel ownership.
  if [ "$port" = 80 ]; then
    return 0
  fi
  if ! is_managed_listener_config "$port"; then
    fail "PORT_CONFLICT: :$port is owned by unmanaged Nginx configuration"
  fi
}

preflight_managed_ports() {
  ensure_listener_is_managed_or_free 443
  ensure_listener_is_managed_or_free 8443
  ensure_listener_is_managed_or_free 80
}

ensure_public_camouflage_fallback() {
  local conf cert key tmp
  conf="$(nginx_path "$CAMOUFLAGE_WRAPPER_CONF_PATH")"
  cert="$(nginx_path /etc/nginx/relay-panel-certs/fallback.crt)"
  key="$(nginx_path /etc/nginx/relay-panel-certs/fallback.key)"
  tmp="$conf.tmp"

  if [ -f "$conf" ]; then
    is_managed_camouflage_config "$conf" \
      || fail "NGINX_CONFIG_CONFLICT: camouflage :8443 config is not Reality Panel-managed"
    if grep -qF '# generated by relay-node; TLS camouflage sites' "$conf"; then
      return 0
    fi
    if grep -qF '# RelayPanel managed bootstrap camouflage fallback' "$conf" \
      && grep -qF 'listen 8443 ssl default_server;' "$conf"; then
      return 0
    fi
  fi

  install -d -m 0755 "$(dirname "$conf")" "$(dirname "$cert")"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
      -keyout "$key" -out "$cert" -subj '/CN=relay-panel-bootstrap' >/dev/null 2>&1
  fi
  chmod 0600 "$key"
  cat > "$tmp" <<EOF
# RelayPanel managed bootstrap camouflage fallback
server {
    listen 8443 ssl default_server;
    listen [::]:8443 ssl default_server;
    server_name _;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    location / { proxy_pass http://127.0.0.1:5244; }
}
EOF
  mv -f "$tmp" "$conf"
  NGINX_RELOAD_REQUIRED=1
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
    fail "NGINX_STREAM_CONFLICT: existing non-Reality Panel top-level stream context: $(printf '%s' "$external_streams" | tr '\n' ' ')"
  fi

  include_locations="$(grep -RFlx -- "$include_line" "$nginx_dir" 2>/dev/null || true)"
  if [ -n "$include_locations" ]; then
    include_count="$(printf '%s\n' "$include_locations" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "$include_count" != 1 ] || [ "$include_locations" != "$nginx_conf" ]; then
      fail "NGINX_STREAM_CONFLICT: Reality Panel stream include is duplicated or outside nginx.conf"
    fi
  else
    printf '\n%s\n' "$include_line" >> "$nginx_conf"
    NGINX_RELOAD_REQUIRED=1
  fi

  install -d -m 0755 "$stream_dir"
  printf '%s' "$expected_stream_root" > "$stream_root.tmp"
  if [ -f "$stream_root" ] && cmp -s "$stream_root.tmp" "$stream_root"; then
    rm -f "$stream_root.tmp"
  else
    mv -f "$stream_root.tmp" "$stream_root"
    NGINX_RELOAD_REQUIRED=1
  fi
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

if [ "${1:-}" = "--test-port-preflight" ]; then
  NGINX_ROOT="${2:?test nginx root required}"
  PORT_PREFLIGHT_INPUT="${3:?test ss output required}"
  preflight_managed_ports
  exit 0
fi

if [ "${1:-}" = "--test-public-fallback" ]; then
  NGINX_ROOT="${2:?test nginx root required}"
  ensure_public_camouflage_fallback
  exit 0
fi

if [ "${1:-}" = "--test-https-redirect" ]; then
  NGINX_ROOT="${2:?test nginx root required}"
  ensure_https_redirect
  exit 0
fi

if [ "${1:-}" = "--test-env-filter" ]; then
  filter_unmanaged_env "${2:?input env required}" "${3:?output env required}"
  exit 0
fi

if [ "${1:-}" = "--test-transaction-failure" ]; then
  TRANSACTION_ROOT="${2:?test transaction root required}"
  TRANSACTION_DIR="${3:?test transaction directory required}"
  failure_point="${4:?test failure point required}"
  trap on_exit EXIT
  capture_transaction
  case "$failure_point" in
    binary-activation)
      printf 'new relay-node binary\n' > "$(managed_path /opt/relay-node/relay-node)"
      printf 'staged\n' > "$(managed_path /opt/relay-node/relay-node.new)"
      ;;
    env-mutation)
      printf 'NODE_TOKEN=injected-secret\n' > "$(managed_path /etc/relay-node/relay-node.env)"
      ;;
    unit-mutation)
      printf 'new relay-node unit\n' > "$(managed_path /etc/systemd/system/relay-node.service)"
      ;;
    nginx-validation)
      BOOTSTRAP_STEP=nginx
      printf 'BROKEN nginx config\n' > "$(managed_path /etc/nginx/nginx.conf)"
      "$NGINX_BIN" -t
      ;;
    service-health)
      printf 'new relay-node binary\n' > "$(managed_path /opt/relay-node/relay-node)"
      printf 'new relay-node env\n' > "$(managed_path /etc/relay-node/relay-node.env)"
      printf 'new relay-node unit\n' > "$(managed_path /etc/systemd/system/relay-node.service)"
      "$SYSTEMCTL_BIN" restart relay-node
      ;;
    rollback-retry)
      printf 'new relay-node binary\n' > "$(managed_path /opt/relay-node/relay-node)"
      printf 'new relay-node env\n' > "$(managed_path /etc/relay-node/relay-node.env)"
      printf 'BROKEN nginx config\n' > "$(managed_path /etc/nginx/nginx.conf)"
      ;;
    no-mutation) ;;
    *) fail "unknown transaction failure point" ;;
  esac
  fail "injected bootstrap failure at $failure_point"
fi

if [ "${1:-}" = "--test-transaction-noop" ]; then
  TRANSACTION_ROOT="${2:?test transaction root required}"
  TRANSACTION_DIR="${3:?test transaction directory required}"
  capture_transaction
  commit_transaction
  release_transaction_lock
  exit 0
fi

if [ "${1:-}" = "--rollback" ]; then
  TRANSACTION_DIR="${2:?transaction directory required}"
  TRANSACTION_ROOT="${3:-}"
  [ -d "$TRANSACTION_DIR" ] || exit 0
  acquire_transaction_lock || fail "TRANSACTION_BUSY: bootstrap is still running"
  if [ -f "$TRANSACTION_DIR/state" ]; then
    load_transaction_paths
  fi
  if rollback_transaction; then
    release_transaction_lock
    exit 0
  fi
  release_transaction_lock
  exit 1
fi

if [ "${1:-}" = "--commit" ]; then
  TRANSACTION_DIR="${2:?transaction directory required}"
  acquire_transaction_lock || fail "TRANSACTION_BUSY: bootstrap is still running"
  if commit_transaction; then
    release_transaction_lock
    exit 0
  fi
  release_transaction_lock
  exit 1
fi

CONFIG_FILE="${1:?bootstrap config path required}"
ARTIFACT_FILE="${2:?relay-node artifact path required}"
TRANSACTION_DIR="${3:?bootstrap transaction directory required}"
trap on_exit EXIT
install -d -m 0700 "$TRANSACTION_DIR" "$TRANSACTION_DIR/files"
acquire_transaction_lock || fail "TRANSACTION_BUSY: another bootstrap transaction is active"

# shellcheck disable=SC1090
source "$CONFIG_FILE"
load_existing_managed_settings

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
# Install the read-only socket inspection dependency before anything that can
# claim a managed port. This keeps the conflict check fail-closed on minimal OS
# images without treating a freshly-installed Nginx listener as pre-existing.
apt-get install -y -qq ca-certificates curl iproute2
preflight_managed_ports
apt-get install -y -qq docker.io nginx libnginx-mod-stream openssl certbot
step_ok

step transaction-snapshot
capture_transaction
step_ok

step certbot-base
ensure_certbot_base
install -d -m 0755 "$CERTIFICATE_HTTP01_WEBROOT/.well-known/acme-challenge"
step_ok

step docker
systemctl is-enabled --quiet docker || systemctl enable docker
systemctl is-active --quiet docker || systemctl start docker
docker info >/dev/null
step_ok

step nginx-layout
ensure_relay_panel_stream_layout
ensure_https_redirect
step_ok

step relay-node-files
install -d -m 0755 /opt/relay-node /etc/relay-node /etc/relay-panel \
  /var/lib/relay-panel /etc/nginx/relay-panel-certs
install -d -m 0700 "$CAMOUFLAGE_SITES_STATE_DIR" "$CERTIFICATE_STATE_DIR"
install -d -m 0755 "$(dirname "$CAMOUFLAGE_SITES_MANIFEST_PATH")" \
  "$(dirname "$CERTIFICATE_HTTP01_CONF_PATH")"

actual_sha="$(sha256sum "$ARTIFACT_FILE" | awk '{print $1}')"
[ "$actual_sha" = "$RELAY_NODE_SHA256" ] || fail "relay-node sha256 verification failed"
current_sha=""
if [ -f /opt/relay-node/relay-node ]; then
  current_sha="$(sha256sum /opt/relay-node/relay-node | awk '{print $1}')"
fi
if [ "$current_sha" != "$actual_sha" ]; then
  install -m 0755 "$ARTIFACT_FILE" /opt/relay-node/relay-node.new
  /opt/relay-node/relay-node.new --version >/dev/null
  mv -f /opt/relay-node/relay-node.new /opt/relay-node/relay-node
  RELAY_NODE_RESTART_REQUIRED=1
fi
/opt/relay-node/relay-node --version >/dev/null

# relay-node itself owns initial node-id creation. A pre-existing id (and both
# P0 LKG files) is never replaced during a repair/redeploy.
if [ -f /opt/relay-node/node-id ]; then
  [ "$(stat -c '%a' /opt/relay-node/node-id)" = 600 ] \
    || chmod 0600 /opt/relay-node/node-id
fi

if [ -f /etc/relay-node/relay-node.env ]; then
  filter_unmanaged_env \
    /etc/relay-node/relay-node.env /etc/relay-node/relay-node.env.new
else
  : > /etc/relay-node/relay-node.env.new
fi
cat >> /etc/relay-node/relay-node.env.new <<EOF
PANEL_URL='$PANEL_URL'
NODE_TOKEN='$NODE_TOKEN'
NGINX_SNI_ENABLED=1
NGINX_SNI_CONF_PATH=$NGINX_SNI_CONF_PATH
NGINX_SNI_DEFAULT_BACKEND=127.0.0.1:8443
NGINX_SNI_TEST_CMD='nginx -t'
NGINX_SNI_RELOAD_CMD='systemctl reload nginx'
NGINX_SNI_ACCESS_LOG_PATH=/var/log/nginx/relay-panel-sni.log
NGINX_SNI_TRAFFIC_STATE_PATH=/opt/relay-node/nginx-sni-log.offset
CAMOUFLAGE_SITES_ENABLED=1
CAMOUFLAGE_SITES_MANIFEST_PATH=$CAMOUFLAGE_SITES_MANIFEST_PATH
CAMOUFLAGE_SITES_STATE_DIR=$CAMOUFLAGE_SITES_STATE_DIR
CAMOUFLAGE_WRAPPER_CONF_PATH=$CAMOUFLAGE_WRAPPER_CONF_PATH
CERTIFICATE_LIFECYCLE_ENABLED=1
CERTIFICATE_LIFECYCLE_CHECK_INTERVAL_SECS=$CERTIFICATE_CHECK_INTERVAL_SECS
CERTBOT_BINARY_PATH=$CERTBOT_BINARY_PATH
CERTBOT_LIVE_DIR=$CERTBOT_LIVE_DIR
CERTIFICATE_HTTP01_WEBROOT=$CERTIFICATE_HTTP01_WEBROOT
CERTIFICATE_HTTP01_CONF_PATH=$CERTIFICATE_HTTP01_CONF_PATH
CERTIFICATE_STATE_DIR=$CERTIFICATE_STATE_DIR
PROVISIONING_CAPABILITIES_PATH=/opt/relay-node/provisioning-capabilities.json
EOF
chmod 0600 /etc/relay-node/relay-node.env.new
if [ -f /etc/relay-node/relay-node.env ] \
  && cmp -s /etc/relay-node/relay-node.env.new /etc/relay-node/relay-node.env; then
  rm -f /etc/relay-node/relay-node.env.new
else
  mv -f /etc/relay-node/relay-node.env.new /etc/relay-node/relay-node.env
  RELAY_NODE_RESTART_REQUIRED=1
fi

install -d -m 0700 "$TRANSACTION_DIR/candidate"
cat > "$TRANSACTION_DIR/candidate/relay-node.service" <<'EOF'
[Unit]
Description=Reality Panel relay-node
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
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$TRANSACTION_DIR/candidate/relay-node.service" >/dev/null
fi
if [ -f /etc/systemd/system/relay-node.service ] \
  && cmp -s "$TRANSACTION_DIR/candidate/relay-node.service" /etc/systemd/system/relay-node.service; then
  :
else
  cp -a "$TRANSACTION_DIR/candidate/relay-node.service" \
    /etc/systemd/system/relay-node.service.new
  mv -f /etc/systemd/system/relay-node.service.new /etc/systemd/system/relay-node.service
  SYSTEMD_RELOAD_REQUIRED=1
  RELAY_NODE_RESTART_REQUIRED=1
fi
step_ok

# Pin a versioned image. Existing RelayPanel data is always retained and an
# already-correct container is left untouched. This pinned image runs as UID
# 1001, so the bind mount must be writable by that account.
step openlist
OPENLIST_IMAGE="openlistteam/openlist@sha256:3bfba7ab379594c3f140e61ecc9096d66360cd4654ccea9f6cb8164b679a669d"
install -d -m 0750 -o 1001 -g 1001 /var/lib/relay-panel/openlist
find /var/lib/relay-panel/openlist -xdev \
  \( ! -uid 1001 -o ! -gid 1001 \) -exec chown 1001:1001 -- {} +
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
ensure_public_camouflage_fallback
step_ok

step nginx
nginx -t
systemctl is-enabled --quiet nginx || systemctl enable nginx
systemctl is-active --quiet nginx || systemctl start nginx
if [ "$NGINX_RELOAD_REQUIRED" = 1 ]; then
  systemctl reload nginx
fi
step_ok

step relay-node-service
if [ "$SYSTEMD_RELOAD_REQUIRED" = 1 ]; then
  systemctl daemon-reload
fi
if systemctl is-active --quiet relay-node; then
  if [ "$RELAY_NODE_RESTART_REQUIRED" = 1 ]; then
    systemctl restart relay-node
  fi
else
  systemctl start relay-node
fi
systemctl is-enabled --quiet relay-node || systemctl enable relay-node >/dev/null
systemctl is-active --quiet relay-node
step_ok

step verify-openlist
curl -fsS --max-time 10 http://127.0.0.1:5244/ >/dev/null
step_ok

step verify-fallback
curl -kfsS --max-time 10 https://127.0.0.1:8443/ >/dev/null
step_ok

step capabilities
cat > /opt/relay-node/provisioning-capabilities.json.tmp <<'EOF'
{
  "nginx_stream": true,
  "openlist": true,
  "http01": true,
  "certificate_lifecycle": true,
  "reality_camouflage": true
}
EOF
chmod 0644 /opt/relay-node/provisioning-capabilities.json.tmp
if [ -f /opt/relay-node/provisioning-capabilities.json ] \
  && cmp -s /opt/relay-node/provisioning-capabilities.json.tmp /opt/relay-node/provisioning-capabilities.json; then
  rm -f /opt/relay-node/provisioning-capabilities.json.tmp
else
  mv -f /opt/relay-node/provisioning-capabilities.json.tmp \
    /opt/relay-node/provisioning-capabilities.json
fi
step_ok
info "bootstrap complete"
