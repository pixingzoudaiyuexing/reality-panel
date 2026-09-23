#!/usr/bin/env bash
# Reality Panel Node Reuse V1 S2-A2B2 one-time Concrete Node Claim helper.
#
# This helper proves possession of the separately-delivered Claim Secret from a
# specific target machine. It does NOT issue, store, activate, or authenticate a
# permanent Node Credential and it never changes Relay runtime state.
set -euo pipefail
umask 077
export LC_ALL=C

ENV_FILE="${RELAY_NODE_CLAIM_ENV_FILE:-/etc/relay-node/relay-node.env}"
NODE_ID_FILE="${RELAY_NODE_CLAIM_NODE_ID_FILE:-/opt/relay-node/node-id}"
STATE_ROOT="${RELAY_NODE_CLAIM_STATE_ROOT:-/var/lib/relay-panel/node-claims}"
CLAIM_ID=""
HOME_GROUP_ID=""
TEMP_FILES=()
tty=/dev/tty
TTY_ECHO_DISABLED=0

info() { printf '%s\n' "$*" >&2; }
fail() { info "node claim failed: $*"; exit 1; }

restore_tty_echo() {
  if [ "$TTY_ECHO_DISABLED" -eq 1 ]; then
    stty echo < "$tty" 2>/dev/null || true
    TTY_ECHO_DISABLED=0
  fi
}

cleanup() {
  local item
  restore_tty_echo
  for item in "${TEMP_FILES[@]:-}"; do
    rm -f -- "$item"
  done
}
trap cleanup EXIT INT TERM

usage() {
  fail "usage: relay-node-claim.sh --claim-id UUID --home-group-id ID"
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
  *) fail "invalid claim id" ;;
esac
case "$CLAIM_ID" in
  *[!0-9a-f-]*) fail "invalid claim id" ;;
esac
case "$HOME_GROUP_ID" in
  ''|0|*[!0-9]*) fail "invalid Home Group id" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v base64 >/dev/null 2>&1 || fail "base64 is required"
command -v head >/dev/null 2>&1 || fail "head is required"
command -v sync >/dev/null 2>&1 || fail "sync is required"
command -v stty >/dev/null 2>&1 || fail "stty is required"

[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail "trusted Node config is unavailable"
[ -O "$ENV_FILE" ] || fail "trusted Node config is not owned by the current root user"
[ -f "$NODE_ID_FILE" ] && [ ! -L "$NODE_ID_FILE" ] || fail "persistent Node ID is unavailable"
[ -O "$NODE_ID_FILE" ] || fail "persistent Node ID is not owned by the current root user"

private_file_mode() {
  local path="$1" mode
  mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || true)"
  [ "$mode" = 600 ]
}

private_file_mode "$ENV_FILE" || fail "trusted Node config must be mode 0600"
private_file_mode "$NODE_ID_FILE" || fail "persistent Node ID must be mode 0600"

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
  case "$value" in
    *$'\r'*|*$'\n'*) return 1 ;;
  esac
  printf '%s' "$value"
}

PANEL_URL="$(read_env_value PANEL_URL)" || fail "trusted Node config has no PANEL_URL"
NODE_TOKEN="$(read_env_value NODE_TOKEN)" || fail "trusted Node config has no NODE_TOKEN"
PANEL_URL="${PANEL_URL%/}"
case "$PANEL_URL" in
  https://*) ;;
  *) fail "Panel URL must use HTTPS" ;;
esac
panel_authority="${PANEL_URL#https://}"
case "$panel_authority" in
  ''|*'/'*|*'?'*|*'#'*|*'@'*|*'"'*|*'\\'*|*[[:space:]]*) fail "Panel URL must be a plain HTTPS origin" ;;
esac
case "$NODE_TOKEN" in
  ''|*[[:space:]]*) fail "trusted Node token is invalid" ;;
esac

curl_config_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

node_id_bytes="$(wc -c < "$NODE_ID_FILE" | tr -d '[:space:]')"
NODE_ID="$(cat "$NODE_ID_FILE")"
case "$node_id_bytes" in
  ''|*[!0-9]*) fail "could not measure persistent Node ID" ;;
esac
[ "${#NODE_ID}" -eq "$node_id_bytes" ]   || fail "persistent Node ID contains a trailing newline or unsupported bytes"
[ "${#NODE_ID}" -ge 1 ] && [ "${#NODE_ID}" -le 128 ]   || fail "persistent Node ID is not Reuse-eligible"
case "$NODE_ID" in
  *[!A-Za-z0-9_-]*) fail "persistent Node ID is not Reuse-eligible" ;;
esac

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
PENDING_FILE="$STATE_DIR/pending"

valid_nonce() {
  local value="$1" payload
  case "$value" in
    rpcn1_*) ;;
    *) return 1 ;;
  esac
  payload="${value#rpcn1_}"
  [ "${#payload}" -eq 43 ] || return 1
  case "$payload" in
    *[!A-Za-z0-9_-]*) return 1 ;;
  esac
  return 0
}

persist_new_nonce() {
  local payload tmp
  payload="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\r\n')"
  [ "${#payload}" -eq 43 ] || fail "could not generate claimant nonce"
  CLAIMANT_NONCE="rpcn1_$payload"
  valid_nonce "$CLAIMANT_NONCE" || fail "generated claimant nonce is invalid"

  tmp="$(mktemp "$STATE_DIR/.pending.XXXXXX")"
  TEMP_FILES+=("$tmp")
  chmod 0600 "$tmp"
  printf '%s\n%s\n%s\n%s\n'     "$CLAIM_ID" "$HOME_GROUP_ID" "$NODE_ID" "$CLAIMANT_NONCE" > "$tmp"
  sync -f "$tmp" || fail "could not durably persist claimant nonce"
  mv -f -- "$tmp" "$PENDING_FILE"
  sync -f "$STATE_DIR" || fail "could not durably commit claimant nonce"
}

load_or_create_nonce() {
  local saved_claim saved_group saved_node saved_nonce extra
  [ ! -L "$PENDING_FILE" ] || fail "pending Claim state is a symlink"
  if [ -e "$PENDING_FILE" ]; then
    [ -f "$PENDING_FILE" ] && [ ! -L "$PENDING_FILE" ] \
      || fail "pending Claim state is not a regular private file"
    [ -O "$PENDING_FILE" ] || fail "pending Claim state is not root-owned"
    chmod 0600 "$PENDING_FILE"
    {
      IFS= read -r saved_claim || fail "pending Claim state is malformed"
      IFS= read -r saved_group || fail "pending Claim state is malformed"
      IFS= read -r saved_node || fail "pending Claim state is malformed"
      IFS= read -r saved_nonce || fail "pending Claim state is malformed"
      if IFS= read -r extra; then
        fail "pending Claim state is malformed"
      fi
    } < "$PENDING_FILE"
    [ "$saved_claim" = "$CLAIM_ID" ] || fail "pending Claim id does not match"
    [ "$saved_group" = "$HOME_GROUP_ID" ] || fail "pending Home Group does not match"
    [ "$saved_node" = "$NODE_ID" ] || fail "pending Node ID does not match"
    CLAIMANT_NONCE="$saved_nonce"
    valid_nonce "$CLAIMANT_NONCE" || fail "persisted claimant nonce is invalid"
  else
    persist_new_nonce
  fi
}

# The nonce MUST be durably persisted before the operator is asked for the
# one-time Claim Secret and before any network request can occur.
load_or_create_nonce

[ -r "$tty" ] || fail "an interactive terminal is required to read the Claim Secret"
stty -echo < "$tty" || fail "could not disable terminal echo"
TTY_ECHO_DISABLED=1
info "enter one-time Claim Secret:"
if ! IFS= read -r CLAIM_SECRET < "$tty"; then
  restore_tty_echo
  fail "could not read Claim Secret"
fi
restore_tty_echo
printf '\n' >&2
case "$CLAIM_SECRET" in
  rpc1_*) ;;
  *) fail "Claim Secret has invalid format" ;;
esac
secret_payload="${CLAIM_SECRET#rpc1_}"
[ "${#secret_payload}" -eq 43 ] || fail "Claim Secret has invalid format"
case "$secret_payload" in
  *[!A-Za-z0-9_-]*) fail "Claim Secret has invalid format" ;;
esac

REQUEST_FILE="$(mktemp "$STATE_DIR/.request.XXXXXX")"
RESPONSE_FILE="$(mktemp "$STATE_DIR/.response.XXXXXX")"
CURL_CONFIG="$(mktemp "$STATE_DIR/.curl.XXXXXX")"
chmod 0600 "$REQUEST_FILE" "$RESPONSE_FILE" "$CURL_CONFIG"
TEMP_FILES+=("$REQUEST_FILE" "$RESPONSE_FILE" "$CURL_CONFIG")

printf '{"home_group_id":%s,"node_id":"%s","secret":"%s","claimant_nonce":"%s"}'   "$HOME_GROUP_ID" "$NODE_ID" "$CLAIM_SECRET" "$CLAIMANT_NONCE" > "$REQUEST_FILE"

PANEL_URL_CFG="$(curl_config_escape "$PANEL_URL")"
NODE_TOKEN_CFG="$(curl_config_escape "$NODE_TOKEN")"
RESPONSE_FILE_CFG="$(curl_config_escape "$RESPONSE_FILE")"
REQUEST_FILE_CFG="$(curl_config_escape "$REQUEST_FILE")"
{
  printf 'url = "%s/api/v1/node-credential-claims/%s/claim"\n' "$PANEL_URL_CFG" "$CLAIM_ID"
  printf 'request = "POST"\n'
  printf 'output = "%s"\n' "$RESPONSE_FILE_CFG"
  printf 'silent\nshow-error\n'
  printf 'proto = "=https"\nproto-redir = "=https"\nmax-redirs = 0\n'
  printf 'header = "Content-Type: application/json"\n'
  printf 'header = "Authorization: Bearer %s"\n' "$NODE_TOKEN_CFG"
  printf 'data-binary = "@%s"\n' "$REQUEST_FILE_CFG"
  printf 'write-out = "%%{http_code}"\n'
} > "$CURL_CONFIG"

set +e
HTTP_CODE="$(curl --config "$CURL_CONFIG")"
curl_status=$?
set -e
# Raw Claim Secret has now served its only purpose in this process. The request
# file is removed immediately rather than waiting for the exit trap.
unset CLAIM_SECRET
rm -f -- "$REQUEST_FILE"
if [ "$curl_status" -ne 0 ]; then
  fail "HTTPS Claim request failed; persisted nonce retained for safe retry"
fi
case "$HTTP_CODE" in
  2??|4??|5??) ;;
  *) fail "Panel returned an invalid HTTP response" ;;
esac

api_code="$(sed -nE 's/.*"code":[[:space:]]*([0-9]+).*/\1/p' "$RESPONSE_FILE" | head -n 1)"
outcome="$(sed -nE 's/.*"outcome":[[:space:]]*"([A-Z_]+)".*/\1/p' "$RESPONSE_FILE" | head -n 1)"
if [ "$api_code" = 0 ] && { [ "$outcome" = CLAIMED ] || [ "$outcome" = EXISTING ]; }; then
  info "Concrete Node Claim accepted [$outcome]"
  info "pending claimant nonce retained for idempotent retry; no permanent credential was issued"
  exit 0
fi

case "$outcome" in
  REPLAY) fail "Claim was already bound to a different claimant nonce" ;;
  EXPIRED) fail "Claim has expired; administrator must create a new Claim" ;;
  CANCELLED) fail "Claim has been cancelled; administrator must create a new Claim" ;;
  RATE_LIMITED) fail "too many Claim attempts; retry later with the same pending nonce" ;;
  INVALID|'') fail "Claim authentication was rejected" ;;
  *) fail "Claim request was rejected" ;;
esac
