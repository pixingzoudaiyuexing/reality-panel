#!/usr/bin/env bash
# B2-02B first-time permanent Node Credential establishment helper.
# This establishes a credential only; runtime HTTP/WS auth and Node Reuse remain disabled.
set -euo pipefail
umask 077
export LC_ALL=C

set +u
ENV_FILE="$RELAY_NODE_CREDENTIAL_ENV_FILE"
NODE_ID_FILE="$RELAY_NODE_CREDENTIAL_NODE_ID_FILE"
STATE_ROOT="$RELAY_NODE_CREDENTIAL_STATE_ROOT"
set -u
[ -n "$ENV_FILE" ] || ENV_FILE=/etc/relay-node/relay-node.env
[ -n "$NODE_ID_FILE" ] || NODE_ID_FILE=/opt/relay-node/node-id
[ -n "$STATE_ROOT" ] || STATE_ROOT=/var/lib/relay-panel/node-claims

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd)"
STATE_TOOL="$SCRIPT_DIR/relay-node-credential-state.py"
CLAIM_ID=""
HOME_GROUP_ID=""
STATE_DIR=""
TTY_ECHO_DISABLED=0
tty=/dev/tty

info() { printf '%s\n' "$*" >&2; }
fail() { info "node credential setup failed: $*"; exit 1; }

restore_tty_echo() {
  if [ "$TTY_ECHO_DISABLED" -eq 1 ]; then
    stty echo < "$tty" 9>&- 2>/dev/null || true
    TTY_ECHO_DISABLED=0
  fi
}

cleanup() {
  restore_tty_echo
  if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ]; then
    rm -f -- \
      "$STATE_DIR"/.credential-request.* \
      "$STATE_DIR"/.credential-response.* \
      "$STATE_DIR"/.credential-curl.* \
      "$STATE_DIR"/.credential-http-code.* 9>&- 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

usage() {
  fail "usage: relay-node-credential.sh --claim-id UUID --home-group-id ID"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --claim-id)
      [ "$#" -ge 2 ] || usage
      CLAIM_ID="$2"
      shift 2
      ;;
    --home-group-id)
      [ "$#" -ge 2 ] || usage
      HOME_GROUP_ID="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[ "$(id -u)" = 0 ] || fail "must run as root"
case "$CLAIM_ID" in
  ????????-????-????-????-????????????) ;;
  *) fail "invalid Claim id" ;;
esac
case "$CLAIM_ID" in *[!0-9a-f-]*) fail "invalid Claim id" ;; esac
case "$HOME_GROUP_ID" in ''|0|*[!0-9]*) fail "invalid Home Group id" ;; esac

for cmd in cat curl flock grep install mktemp python3 stat stty tr wc; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd is required"
done
[ -f "$STATE_TOOL" ] && [ ! -L "$STATE_TOOL" ] || fail "Credential state helper is unavailable"

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || true
}

private_file_mode() {
  [ "$(file_mode "$1")" = 600 ]
}

safe_node_id_file_mode() {
  local mode bits
  mode="$(file_mode "$1")"
  case "$mode" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
  bits=$((8#$mode))
  (( (bits & 0400) != 0 && (bits & 0022) == 0 ))
}

safe_root_helper_mode() {
  local mode bits
  mode="$(file_mode "$1")"
  case "$mode" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
  bits=$((8#$mode))
  (( (bits & 0400) != 0 && (bits & 0022) == 0 ))
}

[ -O "$STATE_TOOL" ] || fail "Credential state helper is not owned by the current root user"
safe_root_helper_mode "$STATE_TOOL"   || fail "Credential state helper must be owner-readable and not group/world-writable"

[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail "trusted Node config is unavailable"
[ -O "$ENV_FILE" ] || fail "trusted Node config is not owned by the current root user"
private_file_mode "$ENV_FILE" || fail "trusted Node config must be mode 0600"
[ -f "$NODE_ID_FILE" ] && [ ! -L "$NODE_ID_FILE" ] || fail "persistent Node ID is unavailable"
[ -O "$NODE_ID_FILE" ] || fail "persistent Node ID is not owned by the current root user"
safe_node_id_file_mode "$NODE_ID_FILE" \
  || fail "persistent Node ID must be owner-readable and not group/world-writable"

read_env_value() {
  local key="$1" line value first last
  line="$(grep -m1 "^$key=" "$ENV_FILE" || true)"
  [ -n "$line" ] || return 1
  value="${line#*=}"
  [ -n "$value" ] || return 1
  first="${value:0:1}"
  last="${value: -1}"
  if [ "$first" = "'" ] || [ "$first" = '"' ]; then
    [ "$last" = "$first" ] || return 1
    value="${value:1:${#value}-2}"
  fi
  case "$value" in *$'\r'*|*$'\n'*) return 1 ;; esac
  printf '%s' "$value"
}

PANEL_URL="$(read_env_value PANEL_URL)" || fail "trusted Node config has no PANEL_URL"
NODE_TOKEN="$(read_env_value NODE_TOKEN)" || fail "trusted Node config has no NODE_TOKEN"
PANEL_URL="${PANEL_URL%/}"
panel_authority="${PANEL_URL#https://}"
case "$PANEL_URL" in https://*) ;; *) fail "Panel URL must use HTTPS" ;; esac
case "$panel_authority" in
  ''|*'/'*|*'?'*|*'#'*|*'@'*|*'"'*|*'\\'*|*[[:space:]]*)
    fail "Panel URL must be a plain HTTPS origin"
    ;;
esac
case "$NODE_TOKEN" in ''|*[[:space:]]*) fail "trusted Node token is invalid" ;; esac

node_bytes="$(wc -c < "$NODE_ID_FILE" | tr -d '[:space:]')"
NODE_ID="$(cat "$NODE_ID_FILE")"
case "$node_bytes" in ''|*[!0-9]*) fail "could not measure persistent Node ID" ;; esac
[ "$node_bytes" -ge 1 ] && [ "$node_bytes" -le 128 ] \
  || fail "persistent Node ID is not Reuse-eligible"
[ "$(printf '%s' "$NODE_ID" | wc -c | tr -d '[:space:]')" = "$node_bytes" ] \
  || fail "persistent Node ID contains a trailing newline or unsupported bytes"
case "$NODE_ID" in *[!A-Za-z0-9_-]*) fail "persistent Node ID is not Reuse-eligible" ;; esac

secure_dir() {
  local path="$1"
  [ ! -L "$path" ] || fail "private state path is a symlink"
  if [ -e "$path" ]; then
    [ -d "$path" ] || fail "private state path is not a directory"
    [ -O "$path" ] || fail "private state path is not owned by the current root user"
  else
    install -d -m 0700 "$path"
  fi
  chmod 0700 "$path"
}

secure_dir "$STATE_ROOT"
STATE_DIR="$STATE_ROOT/$CLAIM_ID"
secure_dir "$STATE_DIR"
LOCK_FILE="$STATE_DIR/lock"
CLAIM_PENDING_FILE="$STATE_DIR/pending"
CREDENTIAL_STATE_FILE="$STATE_DIR/credential-pending.json"
CREDENTIAL_SECRET_FILE="$STATE_DIR/node-credential.secret"

[ ! -L "$LOCK_FILE" ] || fail "Claim lock file is a symlink"
if [ ! -e "$LOCK_FILE" ]; then
  ( set -o noclobber; : > "$LOCK_FILE" ) 2>/dev/null || true
fi
[ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] || fail "Claim lock file is unsafe"
[ -O "$LOCK_FILE" ] || fail "Claim lock file is not root-owned"
private_file_mode "$LOCK_FILE" || fail "Claim lock file must be mode 0600"
exec 9<>"$LOCK_FILE" || fail "could not open Claim lock file"
flock -n 9 || fail "another helper is already processing this Claim"

[ -f "$CLAIM_PENDING_FILE" ] && [ ! -L "$CLAIM_PENDING_FILE" ] \
  || fail "existing Claim pending state is required"
[ -O "$CLAIM_PENDING_FILE" ] || fail "Claim pending state is not root-owned"
private_file_mode "$CLAIM_PENDING_FILE" || fail "Claim pending state must be mode 0600"
{
  IFS= read -r saved_claim || fail "Claim pending state is malformed"
  IFS= read -r saved_group || fail "Claim pending state is malformed"
  IFS= read -r saved_node || fail "Claim pending state is malformed"
  IFS= read -r CLAIMANT_NONCE || fail "Claim pending state is malformed"
  if IFS= read -r extra; then fail "Claim pending state is malformed"; fi
} < "$CLAIM_PENDING_FILE"
[ "$saved_claim" = "$CLAIM_ID" ] || fail "Claim pending id does not match"
[ "$saved_group" = "$HOME_GROUP_ID" ] || fail "Claim pending Home Group does not match"
[ "$saved_node" = "$NODE_ID" ] || fail "Claim pending Node ID does not match"
case "$CLAIMANT_NONCE" in rpcn1_*) ;; *) fail "persisted claimant nonce is invalid" ;; esac
nonce_payload="${CLAIMANT_NONCE#rpcn1_}"
[ "$(printf '%s' "$nonce_payload" | wc -c | tr -d '[:space:]')" -eq 43 ] \
  || fail "persisted claimant nonce is invalid"
case "$nonce_payload" in *[!A-Za-z0-9_-]*) fail "persisted claimant nonce is invalid" ;; esac

STATE_INFO="$(python3 "$STATE_TOOL" ensure \
  --state-dir "$STATE_DIR" \
  --claim-id "$CLAIM_ID" \
  --group-id "$HOME_GROUP_ID" \
  --node-id "$NODE_ID" 9>&-)" \
  || fail "could not initialize or load durable permanent Credential state"
IFS=$'\t' read -r CREDENTIAL_ID DELIVERY_NONCE PHASE VERIFIER_DATA <<< "$STATE_INFO"
[ -n "$CREDENTIAL_ID" ] && [ -n "$DELIVERY_NONCE" ] && [ -n "$PHASE" ] && [ -n "$VERIFIER_DATA" ] \
  || fail "local permanent Credential state is incomplete"

set_phase() {
  python3 "$STATE_TOOL" phase \
    --state "$CREDENTIAL_STATE_FILE" \
    --expected "$1" \
    --next "$2" 9>&-
}

prompt_claim_secret() {
  [ -r "$tty" ] || fail "an interactive terminal is required to read the Claim Secret"
  stty -echo < "$tty" 9>&- || fail "could not disable terminal echo"
  TTY_ECHO_DISABLED=1
  info "enter one-time Claim Secret:"
  if ! IFS= read -r CLAIM_SECRET < "$tty"; then
    restore_tty_echo
    fail "could not read Claim Secret"
  fi
  restore_tty_echo
  printf '\n' >&2
  case "$CLAIM_SECRET" in rpc1_*) ;; *) fail "Claim Secret has invalid format" ;; esac
  payload="${CLAIM_SECRET#rpc1_}"
  [ "$(printf '%s' "$payload" | wc -c | tr -d '[:space:]')" -eq 43 ] \
    || fail "Claim Secret has invalid format"
  case "$payload" in *[!A-Za-z0-9_-]*) fail "Claim Secret has invalid format" ;; esac
}

curl_config_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

perform_request() {
  local phase="$1" endpoint="$2" request_file="$3"
  local response_file curl_config http_code_file curl_status http_code

  response_file="$(mktemp "$STATE_DIR/.credential-response.XXXXXX" 9>&-)"
  curl_config="$(mktemp "$STATE_DIR/.credential-curl.XXXXXX" 9>&-)"
  http_code_file="$(mktemp "$STATE_DIR/.credential-http-code.XXXXXX" 9>&-)"
  chmod 0600 "$response_file" "$curl_config" "$http_code_file" 9>&-

  panel_cfg="$(curl_config_escape "$PANEL_URL")"
  token_cfg="$(curl_config_escape "$NODE_TOKEN")"
  response_cfg="$(curl_config_escape "$response_file")"
  request_cfg="$(curl_config_escape "$request_file")"
  {
    printf 'url = "%s/api/v1/node-credential-claims/%s/credential/%s"\n' \
      "$panel_cfg" "$CLAIM_ID" "$endpoint"
    printf 'request = "POST"\n'
    printf 'output = "%s"\n' "$response_cfg"
    printf 'silent\nshow-error\nproto = "=https"\nproto-redir = "=https"\nmax-redirs = 0\n'
    printf 'max-filesize = 65536\n'
    printf 'header = "Content-Type: application/json"\n'
    printf 'header = "Authorization: Bearer %s"\n' "$token_cfg"
    printf 'data-binary = "@%s"\n' "$request_cfg"
    printf 'write-out = "%%{http_code}"\n'
  } > "$curl_config"

  set +e
  curl --config "$curl_config" > "$http_code_file" 9>&-
  curl_status=$?
  set -e
  rm -f -- "$request_file" 9>&-
  if [ "$curl_status" -ne 0 ]; then
    fail "HTTPS Credential request failed; durable local state retained for safe retry"
  fi
  http_code="$(cat "$http_code_file")"
  REQUEST_RESULT="$(python3 "$STATE_TOOL" parse-response \
    --phase "$phase" \
    --http-code "$http_code" \
    --response "$response_file" \
    --claim-id "$CLAIM_ID" \
    --group-id "$HOME_GROUP_ID" \
    --node-id "$NODE_ID" \
    --credential-id "$CREDENTIAL_ID" 9>&-)" \
    || fail "Panel returned an invalid Credential response"
  rm -f -- "$response_file" "$curl_config" "$http_code_file" 9>&-
}

handle_error_result() {
  case "$1" in
    ERROR:EXPIRED) fail "Credential delivery authorization expired; durable local state retained" ;;
    ERROR:CANCELLED) fail "Credential delivery authorization was cancelled" ;;
    ERROR:REPLAY) fail "stored Credential delivery material conflicts with Panel state" ;;
    ERROR:RATE_LIMITED) fail "too many Credential delivery attempts; retry later with the same local state" ;;
    ERROR:ALREADY_ACTIVE) fail "this Node already has an active permanent Credential; refusing overwrite" ;;
    ERROR:RECOVERY_REQUIRED) fail "this Node requires a separately authorized Credential recovery flow" ;;
    ERROR:CREDENTIAL_REVOKED) fail "the linked permanent Credential was revoked" ;;
    ERROR:INVALID) fail "Credential delivery authentication or proof was rejected" ;;
    ERROR:SERVER) fail "Panel Credential endpoint failed; durable local state retained for safe retry" ;;
    *) fail "Panel rejected the Credential request" ;;
  esac
}

if [ "$PHASE" = ACTIVE_CONFIRMED ]; then
  info "Permanent Node Credential was previously confirmed locally; current Panel ACTIVE state and runtime authority are not implied"
  exit 0
fi

if [ "$PHASE" = PREPARE_READY ]; then
  prompt_claim_secret
  request_file="$(mktemp "$STATE_DIR/.credential-request.XXXXXX" 9>&-)"
  chmod 0600 "$request_file" 9>&-
  printf '{"home_group_id":%s,"node_id":"%s","claim_secret":"%s","claimant_nonce":"%s","delivery_nonce":"%s","credential_id":"%s","verifier_format":"rp-node-sha256","verifier_version":1,"verifier_data":"%s"}' \
    "$HOME_GROUP_ID" "$NODE_ID" "$CLAIM_SECRET" "$CLAIMANT_NONCE" "$DELIVERY_NONCE" \
    "$CREDENTIAL_ID" "$VERIFIER_DATA" > "$request_file"
  perform_request PREPARE prepare "$request_file"
  unset CLAIM_SECRET
  case "$REQUEST_RESULT" in
    SUCCESS:PREPARED|SUCCESS:EXISTING)
      set_phase PREPARE_READY ACTIVATE_READY \
        || fail "PREPARE succeeded but local recovery state could not be durably advanced"
      PHASE=ACTIVATE_READY
      ;;
    *) handle_error_result "$REQUEST_RESULT" ;;
  esac
fi

[ "$PHASE" = ACTIVATE_READY ] || fail "local Credential state has an unsupported phase"
[ -f "$CREDENTIAL_SECRET_FILE" ] && [ ! -L "$CREDENTIAL_SECRET_FILE" ] \
  || fail "permanent Credential Secret is unavailable"
[ -O "$CREDENTIAL_SECRET_FILE" ] || fail "permanent Credential Secret is not root-owned"
private_file_mode "$CREDENTIAL_SECRET_FILE" || fail "permanent Credential Secret must be mode 0600"
CREDENTIAL_SECRET="$(<"$CREDENTIAL_SECRET_FILE")"
case "$CREDENTIAL_SECRET" in rpn1_*) ;; *) fail "permanent Credential Secret is invalid" ;; esac
secret_payload="${CREDENTIAL_SECRET#rpn1_}"
[ "$(printf '%s' "$secret_payload" | wc -c | tr -d '[:space:]')" -eq 43 ] \
  || fail "permanent Credential Secret is invalid"
case "$secret_payload" in *[!A-Za-z0-9_-]*) fail "permanent Credential Secret is invalid" ;; esac

request_file="$(mktemp "$STATE_DIR/.credential-request.XXXXXX" 9>&-)"
chmod 0600 "$request_file" 9>&-
printf '{"home_group_id":%s,"node_id":"%s","credential_id":"%s","delivery_nonce":"%s","credential_secret":"%s"}' \
  "$HOME_GROUP_ID" "$NODE_ID" "$CREDENTIAL_ID" "$DELIVERY_NONCE" "$CREDENTIAL_SECRET" \
  > "$request_file"
perform_request ACTIVATE activate "$request_file"
unset CREDENTIAL_SECRET

case "$REQUEST_RESULT" in
  SUCCESS:ACTIVATED|SUCCESS:EXISTING)
    set_phase ACTIVATE_READY ACTIVE_CONFIRMED \
      || fail "activation succeeded but ACTIVE_CONFIRMED could not be durably persisted"
    info "Permanent Node Credential activation confirmed [${REQUEST_RESULT#SUCCESS:}]"
    exit 0
    ;;
  *) handle_error_result "$REQUEST_RESULT" ;;
esac
