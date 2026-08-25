#!/usr/bin/env bash
# RelayPanel Manual Bootstrap transport/orchestration wrapper.
#
# This script intentionally does not mutate Relay services. Every mutation is
# delegated to relay-node-bootstrap.sh, including transaction rollback/commit.
set -euo pipefail
umask 077

PANEL_URL=""
ENROLLMENT_ID=""
STATE_ROOT="${RELAY_PANEL_MANUAL_BOOTSTRAP_STATE_ROOT:-/var/lib/relay-panel/manual-bootstrap}"
STATE_DIR=""
NONCE_FILE=""
SESSION_FILE=""
PHASE_FILE=""
TRANSACTION_DIR=""
BUNDLE_DIR=""
ENGINE_COMMITTED=0
TEMP_FILES=()
VERIFY_INTERVAL_SECS="${RELAY_PANEL_MANUAL_BOOTSTRAP_VERIFY_INTERVAL_SECS:-1}"
VERIFY_TIMEOUT_SECS="${RELAY_PANEL_MANUAL_BOOTSTRAP_VERIFY_TIMEOUT_SECS:-60}"
VERIFY_ERROR_CATEGORY=""
VERIFY_RESULT=""
TEST_VERIFY_SEQUENCE="${RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_VERIFY_SEQUENCE:-}"
TEST_VERIFY_ONLY=0

info() { printf '%s\n' "$*" >&2; }
fail() { info "manual bootstrap failed: $*"; exit 1; }

cleanup_temps() {
  local item
  for item in "${TEMP_FILES[@]:-}"; do rm -f -- "$item"; done
}

phase() { [ -f "$PHASE_FILE" ] && cat "$PHASE_FILE" || true; }
write_phase() { printf '%s\n' "$1" > "$PHASE_FILE"; chmod 0600 "$PHASE_FILE"; }

rollback_precommit() {
  [ "$ENGINE_COMMITTED" = 0 ] || return 0
  [ -x "$BUNDLE_DIR/relay-node-bootstrap.sh" ] || return 0
  [ -d "$TRANSACTION_DIR" ] || return 0
  info "rolling back uncommitted provisioning"
  bash "$BUNDLE_DIR/relay-node-bootstrap.sh" --rollback "$TRANSACTION_DIR" >/dev/null 2>&1 || true
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  cleanup_temps
  if [ "$status" -ne 0 ] && [ "$ENGINE_COMMITTED" = 0 ]; then
    rollback_precommit
  fi
  # Downloaded config contains the permanent group token. Retain only the
  # nonce/session/phase needed for a future claim or post-commit finalization.
  rm -rf -- "$BUNDLE_DIR"
  if [ "$ENGINE_COMMITTED" = 1 ]; then rm -rf -- "$TRANSACTION_DIR"; fi
  exit "$status"
}

on_signal() {
  info "manual bootstrap interrupted"
  exit "${1:?signal status required}"
}

trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --panel-url) PANEL_URL="${2:?panel URL required}"; shift 2 ;;
    --enrollment-id) ENROLLMENT_ID="${2:?enrollment ID required}"; shift 2 ;;
    --test-verify-convergence) TEST_VERIFY_ONLY=1; shift ;;
    *) fail "usage: --panel-url http://panel.example:18888 --enrollment-id UUID" ;;
  esac
done

if [ "$TEST_VERIFY_ONLY" = 0 ]; then
  case "$PANEL_URL" in http://*|https://*) ;; *) fail "Panel URL must use http:// or https://" ;; esac
  case "$ENROLLMENT_ID" in ????????-????-????-????-????????????) ;; *) fail "invalid enrollment ID" ;; esac
fi
case "$VERIFY_INTERVAL_SECS" in ''|*[!0-9]*|0) fail "invalid capability verification interval" ;; esac
case "$VERIFY_TIMEOUT_SECS" in ''|*[!0-9]*|0) fail "invalid capability verification timeout" ;; esac
command -v curl >/dev/null 2>&1 || fail "curl is required for Manual Bootstrap transport"
command -v tar >/dev/null 2>&1 || fail "tar is required for Manual Bootstrap bundle verification"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required for Manual Bootstrap bundle verification"

PANEL_URL="${PANEL_URL%/}"
API_BASE="$PANEL_URL/api/v1"
STATE_DIR="$STATE_ROOT/$ENROLLMENT_ID"
NONCE_FILE="$STATE_DIR/client-nonce"
SESSION_FILE="$STATE_DIR/bootstrap-session"
PHASE_FILE="$STATE_DIR/phase"
TRANSACTION_DIR="$STATE_DIR/transaction"
BUNDLE_DIR="$STATE_DIR/bundle"
install -d -m 0700 "$STATE_DIR"

curl_request() {
  local method="$1" url="$2" output="$3" body_file="${4:-}" auth="${5:-}"
  local config
  config="$(mktemp "$STATE_DIR/curl.XXXXXX")"
  chmod 0600 "$config"
  TEMP_FILES+=("$config")
  {
    printf 'url = "%s"\nrequest = "%s"\noutput = "%s"\nfail-with-body\nsilent\nshow-error\nproto = "=http,https"\n' "$url" "$method" "$output"
    [ -z "$body_file" ] || printf 'header = "Content-Type: application/json"\ndata-binary = "@%s"\n' "$body_file"
    [ -z "$auth" ] || printf 'header = "Authorization: Bearer %s"\n' "$auth"
  } > "$config"
  curl --config "$config"
}

json_value() {
  local key="$1" file="$2"
  sed -nE "s/.*\\\"${key}\\\":\\\"([A-Za-z0-9_-]+)\\\".*/\\1/p" "$file" | head -n 1
}

api_ok() { grep -q '"code":0' "$1"; }

read_secret() {
  local tty=/dev/tty
  if [ "${RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_MODE:-}" = 1 ]; then tty="${RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_TTY:-/dev/tty}"; fi
  [ -r "$tty" ] || fail "an interactive terminal is required to read the enrollment secret"
  info "enter enrollment secret:"
  IFS= read -r -s ENROLLMENT_SECRET < "$tty" || fail "could not read enrollment secret"
  printf '\n' >&2
  [ -n "$ENROLLMENT_SECRET" ] || fail "enrollment secret is empty"
}

ensure_nonce() {
  if [ -f "$NONCE_FILE" ]; then
    CLIENT_NONCE="$(cat "$NONCE_FILE")"
  else
    CLIENT_NONCE="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s\n' "$CLIENT_NONCE" > "$NONCE_FILE"
    chmod 0600 "$NONCE_FILE"
  fi
  case "$CLIENT_NONCE" in [a-f0-9][a-f0-9]*) ;; *) fail "invalid persisted client nonce" ;; esac
}

claim() {
  local request response architecture
  case "$(uname -m)" in x86_64|amd64) architecture=amd64 ;; aarch64|arm64) architecture=arm64 ;; *) fail "unsupported architecture" ;; esac
  REQUESTED_ARCH="$architecture"
  request="$(mktemp "$STATE_DIR/claim.XXXXXX")"
  response="$(mktemp "$STATE_DIR/claim-response.XXXXXX")"
  chmod 0600 "$request" "$response"
  TEMP_FILES+=("$request" "$response")
  printf '{"secret":"%s","architecture":"%s","client_nonce":"%s","profile":"reality_camouflage"}' \
    "$ENROLLMENT_SECRET" "$REQUESTED_ARCH" "$CLIENT_NONCE" > "$request"
  curl_request POST "$API_BASE/node-enrollments/$ENROLLMENT_ID/claim" "$response" "$request"
  api_ok "$response" || fail "enrollment claim rejected"
  BOOTSTRAP_SESSION="$(json_value bootstrap_session "$response")"
  case "$BOOTSTRAP_SESSION" in ???????????????????????????????????????????) ;; *) fail "Panel returned an invalid bootstrap session" ;; esac
  printf '%s\n' "$BOOTSTRAP_SESSION" > "$SESSION_FILE"
  chmod 0600 "$SESSION_FILE"
  unset ENROLLMENT_SECRET
  info "enrollment claimed"
}

load_session() {
  [ -f "$SESSION_FILE" ] || fail "missing persisted bootstrap session"
  BOOTSTRAP_SESSION="$(cat "$SESSION_FILE")"
  case "$BOOTSTRAP_SESSION" in ???????????????????????????????????????????) ;; *) fail "invalid persisted bootstrap session" ;; esac
}

post_node_id() {
  local action="$1" request response node_id
  if [ "$TEST_VERIFY_ONLY" = 1 ] && [ "$action" = verify ]; then
    local category="${TEST_VERIFY_SEQUENCE%%,*}"
    if [ "$TEST_VERIFY_SEQUENCE" = "$category" ]; then
      TEST_VERIFY_SEQUENCE=""
    else
      TEST_VERIFY_SEQUENCE="${TEST_VERIFY_SEQUENCE#*,}"
    fi
    if [ "$category" = OK ]; then
      VERIFY_RESULT="success"
      VERIFY_ERROR_CATEGORY=""
      return 0
    fi
    VERIFY_ERROR_CATEGORY="$category"
    VERIFY_RESULT="terminal"
    case "$category" in
      NODE_OFFLINE|NODE_NOT_FOUND|STALE_OBSERVED_STATE|CAPABILITY_NOT_REPORTED|TRANSPORT_UNAVAILABLE)
        VERIFY_RESULT="transient"
        ;;
    esac
    return 1
  fi
  node_id="$(cat /opt/relay-node/node-id 2>/dev/null || true)"
  [ -n "$node_id" ] || fail "relay-node did not create a persistent Node ID"
  request="$(mktemp "$STATE_DIR/node.XXXXXX")"
  response="$(mktemp "$STATE_DIR/node-response.XXXXXX")"
  chmod 0600 "$request" "$response"
  TEMP_FILES+=("$request" "$response")
  printf '{"node_id":"%s"}' "$node_id" > "$request"
  if ! curl_request POST "$API_BASE/node-enrollments/$ENROLLMENT_ID/$action" "$response" "$request" "$BOOTSTRAP_SESSION"; then
    if [ "$action" = verify ]; then
      VERIFY_RESULT="transient"
      VERIFY_ERROR_CATEGORY="TRANSPORT_UNAVAILABLE"
      return 1
    fi
    return 1
  fi
  if api_ok "$response"; then
    VERIFY_RESULT="success"
    VERIFY_ERROR_CATEGORY=""
    return 0
  fi
  VERIFY_ERROR_CATEGORY="$(json_value error_category "$response")"
  VERIFY_RESULT="terminal"
  if [ "$action" = verify ]; then
    case "$VERIFY_ERROR_CATEGORY" in
      NODE_OFFLINE|NODE_NOT_FOUND|STALE_OBSERVED_STATE|CAPABILITY_NOT_REPORTED)
        VERIFY_RESULT="transient"
        ;;
    esac
  fi
  return 1
}

verify_capabilities() {
  local deadline now
  deadline=$(( $(date +%s) + VERIFY_TIMEOUT_SECS ))
  while :; do
    if post_node_id verify; then
      return 0
    fi
    if [ "$VERIFY_RESULT" != transient ]; then
      fail "Panel capability verification failed${VERIFY_ERROR_CATEGORY:+ [$VERIFY_ERROR_CATEGORY]}"
    fi
    now="$(date +%s)"
    [ "$now" -ge "$deadline" ] && fail "Panel capability verification timed out [$VERIFY_ERROR_CATEGORY]"
    sleep "$VERIFY_INTERVAL_SECS"
  done
}

if [ "$TEST_VERIFY_ONLY" = 1 ]; then
  [ "${RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_MODE:-}" = 1 ] \
    || fail "test verifier mode is disabled"
  [ -n "$TEST_VERIFY_SEQUENCE" ] || fail "test verifier sequence is empty"
  verify_capabilities
  info "test verifier convergence succeeded"
  exit 0
fi

finalize() {
  local response
  response="$(mktemp "$STATE_DIR/complete-response.XXXXXX")"
  chmod 0600 "$response"
  TEMP_FILES+=("$response")
  if curl_request POST "$API_BASE/node-enrollments/$ENROLLMENT_ID/complete" "$response" "" "$BOOTSTRAP_SESSION" && api_ok "$response"; then
    rm -rf -- "$STATE_DIR"
    info "SUCCESS"
    return 0
  fi
  info "local provisioning committed; Panel finalization remains pending"
  return 2
}

# A prior local commit only needs idempotent Panel finalization. Never rerun the
# provisioning engine merely because the completion request was interrupted.
if [ "$(phase)" = local_committed ]; then
  load_session
  finalize
  exit $?
fi

# The provisioning engine may have committed before the wrapper could
# acknowledge that boundary to Panel. Resume acknowledgement without
# downloading the bundle or replaying any mutations.
if [ "$(phase)" = engine_committed ]; then
  ENGINE_COMMITTED=1
  load_session
  info "recording local provisioning commit"
  post_node_id local-commit || fail "could not record locally committed enrollment"
  write_phase local_committed
  rm -rf -- "$BUNDLE_DIR" "$TRANSACTION_DIR"
  finalize
  exit $?
fi

# A crash after engine commit but before the local API acknowledgement must not
# replay provisioning. Re-verify the durable Node ID, then record local commit.
if [ -f "$TRANSACTION_DIR/state" ] && [ "$(cat "$TRANSACTION_DIR/state")" = committed ]; then
  ENGINE_COMMITTED=1
  load_session
  info "verifying Node capabilities"
  verify_capabilities
  post_node_id local-commit || fail "could not record locally committed enrollment"
  write_phase local_committed
  rm -rf -- "$BUNDLE_DIR" "$TRANSACTION_DIR"
  finalize
  exit $?
fi

# Any abandoned pre-commit transaction is rolled back before the same nonce
# retries the claim. This preserves the engine's normal rollback semantics.
if [ -d "$TRANSACTION_DIR" ]; then
  [ -x "$BUNDLE_DIR/relay-node-bootstrap.sh" ] && bash "$BUNDLE_DIR/relay-node-bootstrap.sh" --rollback "$TRANSACTION_DIR" || true
  rm -rf -- "$TRANSACTION_DIR" "$BUNDLE_DIR"
fi

read_secret
ensure_nonce
claim

info "downloading verified bootstrap bundle"
mkdir -p "$BUNDLE_DIR"
chmod 0700 "$BUNDLE_DIR"
BUNDLE_TAR="$(mktemp "$STATE_DIR/bundle.XXXXXX")"
chmod 0600 "$BUNDLE_TAR"
TEMP_FILES+=("$BUNDLE_TAR")
curl_request GET "$API_BASE/node-enrollments/$ENROLLMENT_ID/bundle/$REQUESTED_ARCH" "$BUNDLE_TAR" "" "$BOOTSTRAP_SESSION"
tar -tf "$BUNDLE_TAR" | sort > "$STATE_DIR/bundle-list"
printf '%s\n' config.env manifest.env relay-node-bootstrap.sh "relay-node-linux-$REQUESTED_ARCH" | sort > "$STATE_DIR/bundle-expected"
cmp -s "$STATE_DIR/bundle-list" "$STATE_DIR/bundle-expected" || fail "bootstrap bundle layout is invalid"
rm -f -- "$STATE_DIR/bundle-list" "$STATE_DIR/bundle-expected"
tar -xf "$BUNDLE_TAR" -C "$BUNDLE_DIR"
chmod 0700 "$BUNDLE_DIR/relay-node-bootstrap.sh" "$BUNDLE_DIR/relay-node-linux-$REQUESTED_ARCH"
chmod 0600 "$BUNDLE_DIR/manifest.env" "$BUNDLE_DIR/config.env"
# The manifest is generated by the authenticated Panel and contains only fixed
# scalar values. Validate before sourcing it to keep bundle parsing fail-closed.
grep -Eq '^BUNDLE_VERSION=1$' "$BUNDLE_DIR/manifest.env" || fail "bundle manifest version is invalid"
grep -Eq "^ENROLLMENT_ID=$ENROLLMENT_ID$" "$BUNDLE_DIR/manifest.env" || fail "bundle enrollment binding is invalid"
grep -Eq "^ARCHITECTURE=$REQUESTED_ARCH$" "$BUNDLE_DIR/manifest.env" || fail "bundle architecture binding is invalid"
# shellcheck disable=SC1090
. "$BUNDLE_DIR/manifest.env"
[ "$PROFILE" = reality_camouflage ] || fail "bundle profile is invalid"
[ "$(sha256sum "$BUNDLE_DIR/relay-node-bootstrap.sh" | awk '{print $1}')" = "$BOOTSTRAP_SCRIPT_SHA256" ] || fail "bootstrap script integrity verification failed"
[ "$(sha256sum "$BUNDLE_DIR/config.env" | awk '{print $1}')" = "$BOOTSTRAP_CONFIG_SHA256" ] || fail "bootstrap config integrity verification failed"
[ "$(sha256sum "$BUNDLE_DIR/relay-node-linux-$REQUESTED_ARCH" | awk '{print $1}')" = "$ARTIFACT_SHA256" ] || fail "relay-node artifact integrity verification failed"
info "bundle verified"

info "provisioning"
bash "$BUNDLE_DIR/relay-node-bootstrap.sh" "$BUNDLE_DIR/config.env" "$BUNDLE_DIR/relay-node-linux-$REQUESTED_ARCH" "$TRANSACTION_DIR"
info "verifying Node capabilities"
verify_capabilities

info "local provisioning committed"
bash "$BUNDLE_DIR/relay-node-bootstrap.sh" --commit "$TRANSACTION_DIR"
ENGINE_COMMITTED=1
write_phase engine_committed
post_node_id local-commit || fail "could not record locally committed enrollment"
write_phase local_committed
rm -rf -- "$BUNDLE_DIR" "$TRANSACTION_DIR"
finalize
