#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAIM_SCRIPT="$SCRIPT_DIR/relay-node-claim.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

FAKE_BIN="$TMP_ROOT/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/id" <<'SH'
#!/usr/bin/env sh
if [ "$1" = "-u" ]; then
  printf '0\n'
  exit 0
fi
exec /usr/bin/id "$@"
SH
cat > "$FAKE_BIN/sync" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat > "$FAKE_BIN/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$FAKE_CURL_ARGS"
[ "$#" -eq 2 ] && [ "$1" = "--config" ] || exit 90
config="$2"
cp "$config" "$FAKE_CURL_CONFIG_COPY"
output="$(sed -n 's/^output = "\(.*\)"$/\1/p' "$config" | head -n 1)"
request_file="$(sed -n 's/^data-binary = "@\(.*\)"$/\1/p' "$config" | head -n 1)"
[ -n "$output" ] && [ -n "$request_file" ] || exit 91
cp "$request_file" "$FAKE_CURL_BODY_COPY"
printf '%s\n' "$request_file" > "$FAKE_CURL_REQUEST_PATH"
printf '%s\n' "$config" > "$FAKE_CURL_CONFIG_PATH"
case "${FAKE_CURL_MODE:-claimed}" in
  fail)
    exit 7
    ;;
  claimed)
    printf '{"code":0,"message":"ok","data":{"outcome":"CLAIMED"}}' > "$output"
    printf '200'
    ;;
  existing)
    printf '{"code":0,"message":"ok","data":{"outcome":"EXISTING"}}' > "$output"
    printf '200'
    ;;
  replay)
    printf '{"code":409,"message":"conflict","data":{"outcome":"REPLAY"}}' > "$output"
    printf '409'
    ;;
  *)
    exit 92
    ;;
esac
SH
chmod +x "$FAKE_BIN/id" "$FAKE_BIN/sync" "$FAKE_BIN/curl"

ENV_FILE="$TMP_ROOT/relay-node.env"
NODE_ID_FILE="$TMP_ROOT/node-id"
STATE_ROOT="$TMP_ROOT/state"
OUTPUT_FILE="$TMP_ROOT/helper-output"
FAKE_CURL_ARGS="$TMP_ROOT/curl-args"
FAKE_CURL_CONFIG_COPY="$TMP_ROOT/curl-config-copy"
FAKE_CURL_BODY_COPY="$TMP_ROOT/curl-body-copy"
FAKE_CURL_REQUEST_PATH="$TMP_ROOT/request-path"
FAKE_CURL_CONFIG_PATH="$TMP_ROOT/config-path"
export ENV_FILE NODE_ID_FILE STATE_ROOT OUTPUT_FILE
export FAKE_CURL_ARGS FAKE_CURL_CONFIG_COPY FAKE_CURL_BODY_COPY
export FAKE_CURL_REQUEST_PATH FAKE_CURL_CONFIG_PATH

TOKEN='group-token-private-test'
SECRET='rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
GROUP_ID=7
CLAIM_ID='11111111-1111-4111-8111-111111111111'

write_env() {
  local panel_url="$1"
  cat > "$ENV_FILE" <<EOF
PANEL_URL='$panel_url'
NODE_TOKEN='$TOKEN'
EOF
  chmod 0600 "$ENV_FILE"
}

run_helper() {
  local claim_id="$1" secret="$2"
  TEST_SECRET="$secret" TEST_OUTPUT="$OUTPUT_FILE"   PATH="$FAKE_BIN:$PATH"   RELAY_NODE_CLAIM_ENV_FILE="$ENV_FILE"   RELAY_NODE_CLAIM_NODE_ID_FILE="$NODE_ID_FILE"   RELAY_NODE_CLAIM_STATE_ROOT="$STATE_ROOT"   CLAIM_SCRIPT="$CLAIM_SCRIPT" CLAIM_ID="$claim_id" HOME_GROUP_ID="$GROUP_ID"   python3 - <<'PY'
import errno
import os
import pty
import select
import sys
import time

secret = os.environ.pop("TEST_SECRET").encode()
output_path = os.environ.pop("TEST_OUTPUT")
script = os.environ["CLAIM_SCRIPT"]
claim_id = os.environ["CLAIM_ID"]
group_id = os.environ["HOME_GROUP_ID"]
env = os.environ.copy()

pid, fd = pty.fork()
if pid == 0:
    os.execve(
        "/bin/bash",
        ["bash", script, "--claim-id", claim_id, "--home-group-id", group_id],
        env,
    )

captured = bytearray()
sent = False
status = None
deadline = time.time() + 15
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.1)
    if ready:
        try:
            data = os.read(fd, 4096)
        except OSError as exc:
            if exc.errno == errno.EIO:
                data = b""
            else:
                raise
        if data:
            captured.extend(data)
            if (b"enter one-time Claim Secret:" in captured) and not sent:
                os.write(fd, secret + b"\n")
                sent = True
    waited, raw = os.waitpid(pid, os.WNOHANG)
    if waited == pid:
        status = os.waitstatus_to_exitcode(raw)
        break

if status is None:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    status = 124

with open(output_path, "wb") as handle:
    handle.write(captured)
sys.exit(status)
PY
}

json_nonce() {
  python3 - "$1" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["claimant_nonce"])
PY
}

file_mode() {
  python3 - "$1" <<'PY'
import os
import stat
import sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])
PY
}

write_env 'https://panel.example'
printf '%s' 'Node_A' > "$NODE_ID_FILE"
chmod 0600 "$NODE_ID_FILE"
before_env="$(cksum "$ENV_FILE")"
before_node="$(cksum "$NODE_ID_FILE")"

export FAKE_CURL_MODE=claimed
if ! run_helper "$CLAIM_ID" "$SECRET"; then
  sed -e "s/$SECRET/<redacted-test-secret>/g" -e "s/$TOKEN/<redacted-test-token>/g" \
    "$OUTPUT_FILE" >&2 || true
  fail "helper success flow failed"
fi
grep -q 'Concrete Node Claim accepted \[CLAIMED\]' "$OUTPUT_FILE"   || fail "helper did not report successful Claim"
! grep -Fq "$SECRET" "$OUTPUT_FILE" || fail "Claim Secret leaked to terminal output"
! grep -Fq "$TOKEN" "$OUTPUT_FILE" || fail "Group token leaked to terminal output"
! grep -Fq "$SECRET" "$FAKE_CURL_ARGS" || fail "Claim Secret leaked to curl argv"
! grep -Fq "$TOKEN" "$FAKE_CURL_ARGS" || fail "Group token leaked to curl argv"
grep -Fq 'proto = "=https"' "$FAKE_CURL_CONFIG_COPY"   || fail "curl config does not pin HTTPS"
grep -Fq 'max-redirs = 0' "$FAKE_CURL_CONFIG_COPY"   || fail "curl config does not disable redirects"
! grep -Eq '(^|[[:space:]])(-k|--insecure)([[:space:]]|$)' "$CLAIM_SCRIPT"   || fail "helper contains an insecure TLS bypass"

PENDING_FILE="$STATE_ROOT/$CLAIM_ID/pending"
[ -f "$PENDING_FILE" ] && [ ! -L "$PENDING_FILE" ] || fail "pending nonce state missing"
[ "$(file_mode "$PENDING_FILE")" = 600 ] || fail "pending nonce state is not mode 0600"
pending_text="$(cat "$PENDING_FILE")"
! grep -Fq "$SECRET" "$PENDING_FILE" || fail "pending state persisted Claim Secret"
! grep -Fq "$TOKEN" "$PENDING_FILE" || fail "pending state persisted Group token"
nonce_one="$(json_nonce "$FAKE_CURL_BODY_COPY")"
case "$nonce_one" in
  rpcn1_*) ;;
  *) fail "request did not contain a canonical claimant nonce" ;;
esac
[ "${#nonce_one}" -eq 49 ] || fail "claimant nonce has wrong wire length"

first_request_path="$(cat "$FAKE_CURL_REQUEST_PATH")"
first_config_path="$(cat "$FAKE_CURL_CONFIG_PATH")"
[ ! -e "$first_request_path" ] || fail "private request temp file was not cleaned"
[ ! -e "$first_config_path" ] || fail "private curl config was not cleaned"

export FAKE_CURL_MODE=existing
run_helper "$CLAIM_ID" "$SECRET"
nonce_two="$(json_nonce "$FAKE_CURL_BODY_COPY")"
[ "$nonce_one" = "$nonce_two" ] || fail "retry silently generated a new claimant nonce"
grep -q 'Concrete Node Claim accepted \[EXISTING\]' "$OUTPUT_FILE"   || fail "idempotent retry was not accepted"

# Response-loss / transport failure: nonce must already exist and survive for retry.
LOSS_CLAIM='22222222-2222-4222-8222-222222222222'
export FAKE_CURL_MODE=fail
if run_helper "$LOSS_CLAIM" "$SECRET"; then
  fail "network failure unexpectedly succeeded"
fi
LOSS_PENDING="$STATE_ROOT/$LOSS_CLAIM/pending"
[ -f "$LOSS_PENDING" ] || fail "nonce was not persisted before failed network request"
loss_nonce_before="$(sed -n '4p' "$LOSS_PENDING")"
[ -n "$loss_nonce_before" ] || fail "failed request did not retain claimant nonce"

export FAKE_CURL_MODE=claimed
run_helper "$LOSS_CLAIM" "$SECRET"
loss_nonce_after="$(json_nonce "$FAKE_CURL_BODY_COPY")"
[ "$loss_nonce_before" = "$loss_nonce_after" ]   || fail "restart after response loss did not reuse persisted nonce"

# Symlinked pending state must fail before curl can receive any request.
LINK_CLAIM='33333333-3333-4333-8333-333333333333'
mkdir -p "$STATE_ROOT/$LINK_CLAIM"
ln -s "$TMP_ROOT/attacker-target" "$STATE_ROOT/$LINK_CLAIM/pending"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$LINK_CLAIM" "$SECRET"; then
  fail "symlinked pending state unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "helper sent network request after unsafe persistence state"

# Exact Node ID is a byte boundary. A trailing newline must be rejected, not trimmed.
NEWLINE_CLAIM='44444444-4444-4444-8444-444444444444'
printf 'Node_A\n' > "$NODE_ID_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$NEWLINE_CLAIM" "$SECRET"; then
  fail "Node ID with trailing newline was silently normalized"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "invalid local Node ID reached the network"
printf '%s' 'Node_A' > "$NODE_ID_FILE"

# HTTP is never accepted by the target helper.
HTTP_CLAIM='55555555-5555-4555-8555-555555555555'
write_env 'http://panel.example'
rm -f "$FAKE_CURL_ARGS"
if run_helper "$HTTP_CLAIM" "$SECRET"; then
  fail "HTTP Panel URL unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "HTTP Panel URL reached curl"

# Root ownership alone is not a sufficient trust boundary: reject local config
# or identity files that another user could modify.
PERMISSIVE_ENV_CLAIM='88888888-8888-4888-8888-888888888888'
write_env 'https://panel.example'
chmod 0666 "$ENV_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$PERMISSIVE_ENV_CLAIM" "$SECRET"; then
  fail "world-writable Node config unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "world-writable Node config reached curl"
chmod 0600 "$ENV_FILE"

PERMISSIVE_NODE_CLAIM='99999999-9999-4999-8999-999999999999'
chmod 0666 "$NODE_ID_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$PERMISSIVE_NODE_CLAIM" "$SECRET"; then
  fail "world-writable Node ID unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "world-writable Node ID reached curl"
chmod 0600 "$NODE_ID_FILE"


# Values loaded from trusted local config must not be able to inject extra curl
# configuration directives. Historical/custom tokens are escaped rather than
# silently rewritten into a new token grammar.
CONFIG_CLAIM='66666666-6666-4666-8666-666666666666'
SAFE_TOKEN="$TOKEN"
TOKEN='token"with\backslash'
write_env 'https://panel.example'
export FAKE_CURL_MODE=claimed
run_helper "$CONFIG_CLAIM" "$SECRET"
[ "$(grep -c '^header = ' "$FAKE_CURL_CONFIG_COPY")" -eq 2 ]   || fail "Node token injected an extra curl header directive"
grep -Fq 'header = "Authorization: Bearer token\"with\\backslash"' "$FAKE_CURL_CONFIG_COPY"   || fail "Node token was not safely escaped in curl config"
TOKEN="$SAFE_TOKEN"

URL_INJECTION_CLAIM='77777777-7777-4777-8777-777777777777'
write_env 'https://panel.example"bad'
rm -f "$FAKE_CURL_ARGS"
if run_helper "$URL_INJECTION_CLAIM" "$SECRET"; then
  fail "malformed Panel URL unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "malformed Panel URL reached curl"

write_env 'https://panel.example'
[ "$(cksum "$NODE_ID_FILE")" = "$before_node" ] || fail "helper modified persistent Node ID"
# The env file content is expected to be restored to its original secure HTTPS form.
[ "$(cksum "$ENV_FILE")" = "$before_env" ] || fail "helper modified trusted Node config"

printf 'OK: relay-node Claim helper security and retry contract\n'
