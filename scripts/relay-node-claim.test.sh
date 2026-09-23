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
if ! command -v flock >/dev/null 2>&1; then
  cat > "$FAKE_BIN/flock" <<'PY'
#!/usr/bin/env python3
import errno
import fcntl
import sys

args = sys.argv[1:]
if len(args) != 2 or args[0] != "-n":
    raise SystemExit(64)
try:
    fd = int(args[1])
except ValueError:
    raise SystemExit(64)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as exc:
    if exc.errno in (errno.EACCES, errno.EAGAIN):
        raise SystemExit(1)
    raise
PY
  chmod +x "$FAKE_BIN/flock"
fi
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
claim_id="$(sed -n 's#^url = ".*node-credential-claims/\([^/"]*\)/claim"$#\1#p' "$config" | head -n 1)"
[ -n "$claim_id" ] || exit 93
cp "$request_file" "$FAKE_CURL_BODY_COPY"
printf '%s\n' "$request_file" > "$FAKE_CURL_REQUEST_PATH"
printf '%s\n' "$config" > "$FAKE_CURL_CONFIG_PATH"
mode="${FAKE_CURL_MODE:-claimed}"
case "$mode" in
  fail)
    exit 7
    ;;
  slow_claimed)
    sleep "${FAKE_CURL_DELAY:-2}"
    ;;
esac

python3 - "$request_file" "$output" "$claim_id" "$mode" <<'PY'
import json
import sys

request_path, output_path, claim_id, mode = sys.argv[1:]
with open(request_path, "r", encoding="utf-8") as handle:
    request = json.load(handle)

claim = {
    "claim_id": claim_id,
    "home_group_id": request["home_group_id"],
    "node_id": request["node_id"],
    "state": "CLAIMED",
}
success_outcome = "EXISTING" if mode == "existing" else "CLAIMED"
body = {
    "code": 0,
    "message": "ok",
    "data": {"outcome": success_outcome, "claim": claim},
}

if mode == "wrong_claim_id":
    body["data"]["claim"]["claim_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
elif mode == "wrong_group":
    body["data"]["claim"]["home_group_id"] = request["home_group_id"] + 1
elif mode == "wrong_node":
    body["data"]["claim"]["node_id"] = request["node_id"] + "_wrong"
elif mode == "wrong_state":
    body["data"]["claim"]["state"] = "APPROVED"
elif mode == "wrong_code":
    body["code"] = 1
elif mode in {"replay", "expired", "cancelled", "rate_limited", "invalid"}:
    outcomes = {
        "replay": ("REPLAY", 409),
        "expired": ("EXPIRED", 410),
        "cancelled": ("CANCELLED", 410),
        "rate_limited": ("RATE_LIMITED", 429),
        "invalid": ("INVALID", 401),
    }
    outcome, code = outcomes[mode]
    body = {"code": code, "message": "rejected", "data": {"outcome": outcome}}
elif mode == "forged_message":
    body = {
        "code": 401,
        "message": '{"code":0,"data":{"outcome":"CLAIMED"}}',
        "data": {"outcome": "INVALID"},
    }
elif mode == "nested_forged":
    body = {
        "code": 401,
        "message": "rejected",
        "data": {
            "outcome": "INVALID",
            "nested": {"outcome": "CLAIMED", "claim": claim},
        },
    }
elif mode == "duplicate_key":
    rest = json.dumps({"message": "ok", "data": body["data"]}, separators=(",", ":"))
    raw = '{"code":0,"code":0,' + rest[1:]
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(raw)
    raise SystemExit(0)
elif mode == "truncated":
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write('{"code":0,"data":{"outcome":"CLAIMED"')
    raise SystemExit(0)
elif mode == "invalid_utf8":
    with open(output_path, "wb") as handle:
        handle.write(b'{"code":0,"data":' + bytes([0xFF]) + b"}")
    raise SystemExit(0)
elif mode == "oversized":
    body["padding"] = "x" * 70000
elif mode == "deeply_nested":
    nested = "leaf"
    for _ in range(20):
        nested = [nested]
    body["extra"] = nested

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(body, handle, separators=(",", ":"))
PY

case "$mode" in
  claimed|existing|slow_claimed|wrong_claim_id|wrong_group|wrong_node|wrong_state|wrong_code|duplicate_key|truncated|invalid_utf8|oversized|deeply_nested)
    printf '200'
    ;;
  replay|status409_success) printf '409' ;;
  expired|cancelled|status410_success) printf '410' ;;
  rate_limited|status429_success) printf '429' ;;
  invalid|forged_message|nested_forged|status401_success) printf '401' ;;
  status500_success) printf '500' ;;
  *) exit 92 ;;
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
  local claim_id="$1" secret="$2" slot="${3:-}" delay="${4:-0}" never_send="${5:-0}" child_pid_file="${6:-}"
  local output_file="$OUTPUT_FILE${slot:+-$slot}"
  local curl_args="$FAKE_CURL_ARGS${slot:+-$slot}"
  local curl_config_copy="$FAKE_CURL_CONFIG_COPY${slot:+-$slot}"
  local curl_body_copy="$FAKE_CURL_BODY_COPY${slot:+-$slot}"
  local curl_request_path="$FAKE_CURL_REQUEST_PATH${slot:+-$slot}"
  local curl_config_path="$FAKE_CURL_CONFIG_PATH${slot:+-$slot}"
  TEST_SECRET="$secret" TEST_OUTPUT="$output_file" TEST_SECRET_DELAY="$delay" TEST_NEVER_SEND="$never_send" TEST_CHILD_PID_FILE="$child_pid_file" FAKE_CURL_ARGS="$curl_args" FAKE_CURL_CONFIG_COPY="$curl_config_copy" FAKE_CURL_BODY_COPY="$curl_body_copy" FAKE_CURL_REQUEST_PATH="$curl_request_path" FAKE_CURL_CONFIG_PATH="$curl_config_path" PATH="$FAKE_BIN:$PATH" RELAY_NODE_CLAIM_ENV_FILE="$ENV_FILE" RELAY_NODE_CLAIM_NODE_ID_FILE="$NODE_ID_FILE" RELAY_NODE_CLAIM_STATE_ROOT="$STATE_ROOT" CLAIM_SCRIPT="$CLAIM_SCRIPT" CLAIM_ID="$claim_id" HOME_GROUP_ID="$GROUP_ID" python3 - <<'PY'
import errno
import os
import pty
import select
import sys
import time

secret = os.environ.pop("TEST_SECRET").encode()
output_path = os.environ.pop("TEST_OUTPUT")
secret_delay = float(os.environ.pop("TEST_SECRET_DELAY", "0"))
never_send = os.environ.pop("TEST_NEVER_SEND", "0") == "1"
child_pid_file = os.environ.pop("TEST_CHILD_PID_FILE", "")
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
if child_pid_file:
    with open(child_pid_file, "w", encoding="ascii") as handle:
        handle.write(str(pid))

captured = bytearray()
sent = False
prompt_seen_at = None
status = None
deadline = time.time() + 20
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
            if b"enter one-time Claim Secret:" in captured and prompt_seen_at is None:
                prompt_seen_at = time.time()
    if (
        prompt_seen_at is not None
        and not sent
        and not never_send
        and time.time() - prompt_seen_at >= secret_delay
    ):
        try:
            os.write(fd, secret + b"\n")
            sent = True
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
    waited, raw = os.waitpid(pid, os.WNOHANG)
    if waited == pid:
        status = os.waitstatus_to_exitcode(raw)
        break

if status is None:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    status = 124
else:
    # The child can exit between select() calls after writing its final status
    # lines. Drain the PTY so assertions observe all terminal output instead of
    # racing waitpid().
    while True:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            break
        try:
            data = os.read(fd, 4096)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not data:
            break
        captured.extend(data)

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

wait_for_file() {
  local path="$1" attempts="${2:-100}"
  local i
  for ((i=0; i<attempts; i++)); do
    [ -s "$path" ] && return 0
    sleep 0.05
  done
  return 1
}

assert_helper_rejects_mode() {
  local mode="$1" claim_id="$2"
  export FAKE_CURL_MODE="$mode"
  rm -f "$OUTPUT_FILE" "$FAKE_CURL_ARGS"
  if run_helper "$claim_id" "$SECRET"; then
    fail "response mode $mode unexpectedly succeeded"
  fi
  [ -f "$OUTPUT_FILE" ] || fail "response mode $mode produced no helper output"
  ! grep -Fq "$SECRET" "$OUTPUT_FILE" || fail "response mode $mode leaked Claim Secret"
  ! grep -Fq "$TOKEN" "$OUTPUT_FILE" || fail "response mode $mode leaked Group token"
  local pending="$STATE_ROOT/$claim_id/pending" nonce_value=""
  if [ -f "$pending" ]; then
    nonce_value="$(sed -n '4p' "$pending")"
  fi
  if [ -n "$nonce_value" ]; then
    ! grep -Fq "$nonce_value" "$OUTPUT_FILE" || fail "response mode $mode leaked claimant nonce"
  fi
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
if ! grep -q 'Concrete Node Claim accepted \[CLAIMED\]' "$OUTPUT_FILE"; then
  sed -e "s/$SECRET/<redacted-test-secret>/g" -e "s/$TOKEN/<redacted-test-token>/g" "$OUTPUT_FILE" >&2 || true
  fail "helper did not report successful Claim"
fi
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



# Historical Node IDs are stable identifiers, not secrets. Safe read-only 0644
# must remain compatible, and the helper must not rewrite content or mode.
HISTORICAL_NODE_CLAIM='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
printf '%s' 'Node_A' > "$NODE_ID_FILE"
chmod 0644 "$NODE_ID_FILE"
historical_node_checksum="$(cksum "$NODE_ID_FILE")"
historical_node_mode="$(file_mode "$NODE_ID_FILE")"
export FAKE_CURL_MODE=claimed
run_helper "$HISTORICAL_NODE_CLAIM" "$SECRET"
[ "$(cksum "$NODE_ID_FILE")" = "$historical_node_checksum" ]   || fail "helper modified historical 0644 Node ID content"
[ "$(file_mode "$NODE_ID_FILE")" = "$historical_node_mode" ]   || fail "helper changed historical 0644 Node ID mode"
chmod 0600 "$NODE_ID_FILE"

# The sensitive relay-node.env remains strictly private.
CONFIG_0644_CLAIM='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'
write_env 'https://panel.example'
chmod 0644 "$ENV_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$CONFIG_0644_CLAIM" "$SECRET"; then
  fail "mode 0644 trusted Node config unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "mode 0644 trusted Node config reached curl"
chmod 0600 "$ENV_FILE"

# Node ID symlinks remain forbidden.
NODE_SYMLINK_CLAIM='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3'
node_id_target="$TMP_ROOT/node-id-real"
mv "$NODE_ID_FILE" "$node_id_target"
ln -s "$node_id_target" "$NODE_ID_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$NODE_SYMLINK_CLAIM" "$SECRET"; then
  fail "symlinked persistent Node ID unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "symlinked persistent Node ID reached curl"
rm -f "$NODE_ID_FILE"
mv "$node_id_target" "$NODE_ID_FILE"

# Invalid non-ASCII bytes are rejected without normalization.
INVALID_BYTE_CLAIM='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4'
printf 'Node_A\377' > "$NODE_ID_FILE"
chmod 0600 "$NODE_ID_FILE"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$INVALID_BYTE_CLAIM" "$SECRET"; then
  fail "persistent Node ID with invalid byte unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "invalid-byte Node ID reached curl"
printf '%s' 'Node_A' > "$NODE_ID_FILE"
chmod 0600 "$NODE_ID_FILE"

# A true non-owner check needs the test process itself to be root; do not fake
# this with the id(1) shim used only to exercise the helper's root gate.
NON_OWNER_CLAIM='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5'
real_uid="$(/usr/bin/id -u)"
real_gid="$(/usr/bin/id -g)"
if [ "$real_uid" = 0 ]; then
  chown 65534:65534 "$NODE_ID_FILE"
  restore_owner=direct
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo chown 65534:65534 "$NODE_ID_FILE"
  restore_owner=sudo
else
  restore_owner=unavailable
fi
if [ "$restore_owner" != unavailable ]; then
  rm -f "$FAKE_CURL_ARGS"
  if run_helper "$NON_OWNER_CLAIM" "$SECRET"; then
    fail "non-root-owned persistent Node ID unexpectedly succeeded"
  fi
  [ ! -e "$FAKE_CURL_ARGS" ] || fail "non-root-owned Node ID reached curl"
  if [ "$restore_owner" = sudo ]; then
    sudo chown "$real_uid:$real_gid" "$NODE_ID_FILE"
  else
    chown "$real_uid:$real_gid" "$NODE_ID_FILE"
  fi
  chmod 0600 "$NODE_ID_FILE"
else
  printf 'NOT RUN: non-root-owned node-id ownership check requires root or passwordless sudo\n' >&2
fi

# Structured response validation: only a complete exact 200 response may report
# success. Fake success fields in errors or nested/untrusted text are rejected.
response_modes=(
  wrong_claim_id wrong_group wrong_node wrong_state wrong_code
  forged_message nested_forged duplicate_key truncated invalid_utf8
  oversized deeply_nested status401_success status409_success
  status410_success status429_success status500_success
)
response_index=0
for mode in "${response_modes[@]}"; do
  printf -v response_claim 'bbbbbbbb-bbbb-4bbb-8bbb-%012d' "$response_index"
  assert_helper_rejects_mode "$mode" "$response_claim"
  response_index=$((response_index + 1))
done

# Known terminal/rejection outcomes keep fixed operator hints and never echo the
# untrusted response body.
rejection_index=100
for mode in replay expired cancelled rate_limited invalid; do
  case "$mode" in
    replay) expected_hint='already bound to a different claimant nonce' ;;
    expired) expected_hint='Claim has expired' ;;
    cancelled) expected_hint='Claim has been cancelled' ;;
    rate_limited) expected_hint='too many Claim attempts' ;;
    invalid) expected_hint='Claim authentication was rejected' ;;
  esac
  printf -v rejection_claim 'bbbbbbbb-bbbb-4bbb-8bbb-%012d' "$rejection_index"
  assert_helper_rejects_mode "$mode" "$rejection_claim"
  grep -Fq "$expected_hint" "$OUTPUT_FILE"     || fail "response mode $mode did not use the fixed operator hint"
  rejection_index=$((rejection_index + 1))
done

# Real per-Claim flock concurrency: while the first helper holds the lock across
# TTY entry, a second helper for the same Claim must fail before nonce/network
# mutation. After completion, retry reuses the original nonce.
CONCURRENT_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc1'
export FAKE_CURL_MODE=claimed
rm -f "$FAKE_CURL_ARGS-a" "$FAKE_CURL_ARGS-b" "$FAKE_CURL_ARGS-c"
run_helper "$CONCURRENT_CLAIM" "$SECRET" a 2 &
concurrent_pid=$!
concurrent_pending="$STATE_ROOT/$CONCURRENT_CLAIM/pending"
wait_for_file "$concurrent_pending" || fail "first concurrent helper did not persist nonce"
concurrent_before="$(cat "$concurrent_pending")"
if run_helper "$CONCURRENT_CLAIM" "$SECRET" b; then
  fail "second concurrent helper for the same Claim unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS-b" ] || fail "second same-Claim helper reached the network"
[ "$(cat "$concurrent_pending")" = "$concurrent_before" ]   || fail "second same-Claim helper overwrote pending nonce"
wait "$concurrent_pid"
[ -e "$FAKE_CURL_ARGS-a" ] || fail "first same-Claim helper never reached the network"
nonce_concurrent="$(json_nonce "$FAKE_CURL_BODY_COPY-a")"
[ "$(sed -n '4p' "$concurrent_pending")" = "$nonce_concurrent" ]   || fail "first same-Claim helper did not preserve its nonce"
[ "$(file_mode "$STATE_ROOT/$CONCURRENT_CLAIM/lock")" = 600 ]   || fail "Claim lock file is not mode 0600"

export FAKE_CURL_MODE=existing
run_helper "$CONCURRENT_CLAIM" "$SECRET" c
nonce_concurrent_retry="$(json_nonce "$FAKE_CURL_BODY_COPY-c")"
[ "$nonce_concurrent_retry" = "$nonce_concurrent" ]   || fail "same-Claim retry after lock release did not reuse nonce"



# The lock must still be held after TTY input while curl is in flight.
NETWORK_LOCK_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc7'
export FAKE_CURL_MODE=slow_claimed
export FAKE_CURL_DELAY=2
rm -f "$FAKE_CURL_ARGS-neta" "$FAKE_CURL_ARGS-netb"
run_helper "$NETWORK_LOCK_CLAIM" "$SECRET" neta &
network_lock_pid=$!
wait_for_file "$FAKE_CURL_ARGS-neta" || fail "network-phase helper never entered curl"
if run_helper "$NETWORK_LOCK_CLAIM" "$SECRET" netb; then
  fail "second same-Claim helper acquired lock during network request"
fi
[ ! -e "$FAKE_CURL_ARGS-netb" ] || fail "second same-Claim helper reached curl during network lock"
wait "$network_lock_pid"
unset FAKE_CURL_DELAY

# Killing the helper while curl is still alive must release the kernel lock; curl
# is explicitly prevented from inheriting FD 9. The retry must reuse the nonce.
NETWORK_KILL_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc8'
network_kill_pid_file="$TMP_ROOT/network-kill-helper-child.pid"
export FAKE_CURL_MODE=slow_claimed
export FAKE_CURL_DELAY=2
rm -f "$FAKE_CURL_ARGS-nkill-a" "$FAKE_CURL_ARGS-nkill-b"
run_helper "$NETWORK_KILL_CLAIM" "$SECRET" nkill-a 0 0 "$network_kill_pid_file" &
network_kill_wrapper=$!
wait_for_file "$STATE_ROOT/$NETWORK_KILL_CLAIM/pending"   || fail "network-kill helper did not persist nonce"
wait_for_file "$network_kill_pid_file" || fail "network-kill helper child pid missing"
wait_for_file "$FAKE_CURL_ARGS-nkill-a" || fail "network-kill helper never entered curl"
network_kill_nonce="$(sed -n '4p' "$STATE_ROOT/$NETWORK_KILL_CLAIM/pending")"
kill -9 "$(cat "$network_kill_pid_file")"
wait "$network_kill_wrapper" 2>/dev/null || true
unset FAKE_CURL_DELAY
export FAKE_CURL_MODE=claimed
run_helper "$NETWORK_KILL_CLAIM" "$SECRET" nkill-b
[ "$(json_nonce "$FAKE_CURL_BODY_COPY-nkill-b")" = "$network_kill_nonce" ]   || fail "network-stage SIGKILL retry did not reuse persisted nonce"
# Locks are per Claim. A helper waiting at the TTY for one Claim must not block a
# different Claim from completing.
DIFF_LOCK_A='cccccccc-cccc-4ccc-8ccc-ccccccccccc2'
DIFF_LOCK_B='cccccccc-cccc-4ccc-8ccc-ccccccccccc3'
export FAKE_CURL_MODE=claimed
run_helper "$DIFF_LOCK_A" "$SECRET" da 3 &
different_pid=$!
wait_for_file "$STATE_ROOT/$DIFF_LOCK_A/pending"   || fail "different-Claim lock holder did not start"
run_helper "$DIFF_LOCK_B" "$SECRET" db
kill -0 "$different_pid" 2>/dev/null   || fail "different Claim was blocked until the first helper finished"
wait "$different_pid"
[ -e "$FAKE_CURL_ARGS-da" ] && [ -e "$FAKE_CURL_ARGS-db" ]   || fail "different Claims did not independently reach the network"

# SIGKILL cannot run shell cleanup, but the kernel must release flock. The
# persisted nonce remains and is reused after restart.
KILLED_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc4'
killed_child_pid_file="$TMP_ROOT/killed-helper-child.pid"
export FAKE_CURL_MODE=claimed
run_helper "$KILLED_CLAIM" "$SECRET" killed 0 1 "$killed_child_pid_file" &
killed_wrapper_pid=$!
wait_for_file "$STATE_ROOT/$KILLED_CLAIM/pending"   || fail "killed helper did not persist nonce before waiting for Secret"
wait_for_file "$killed_child_pid_file" || fail "killed helper child pid was not recorded"
killed_nonce_before="$(sed -n '4p' "$STATE_ROOT/$KILLED_CLAIM/pending")"
killed_child_pid="$(cat "$killed_child_pid_file")"
kill -9 "$killed_child_pid"
wait "$killed_wrapper_pid" 2>/dev/null || true

run_helper "$KILLED_CLAIM" "$SECRET" killed-retry
killed_nonce_after="$(json_nonce "$FAKE_CURL_BODY_COPY-killed-retry")"
[ "$killed_nonce_after" = "$killed_nonce_before" ]   || fail "helper restart after SIGKILL did not reuse persisted nonce"

# Lock path hardening: symlink and unsafe mode are rejected before network I/O.
LOCK_SYMLINK_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc5'
mkdir -p "$STATE_ROOT/$LOCK_SYMLINK_CLAIM"
chmod 0700 "$STATE_ROOT/$LOCK_SYMLINK_CLAIM"
ln -s "$TMP_ROOT/lock-attacker-target" "$STATE_ROOT/$LOCK_SYMLINK_CLAIM/lock"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$LOCK_SYMLINK_CLAIM" "$SECRET"; then
  fail "symlinked Claim lock unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "symlinked Claim lock reached curl"

LOCK_MODE_CLAIM='cccccccc-cccc-4ccc-8ccc-ccccccccccc6'
mkdir -p "$STATE_ROOT/$LOCK_MODE_CLAIM"
chmod 0700 "$STATE_ROOT/$LOCK_MODE_CLAIM"
: > "$STATE_ROOT/$LOCK_MODE_CLAIM/lock"
chmod 0666 "$STATE_ROOT/$LOCK_MODE_CLAIM/lock"
rm -f "$FAKE_CURL_ARGS"
if run_helper "$LOCK_MODE_CLAIM" "$SECRET"; then
  fail "unsafe-mode Claim lock unexpectedly succeeded"
fi
[ ! -e "$FAKE_CURL_ARGS" ] || fail "unsafe-mode Claim lock reached curl"
[ "$(file_mode "$STATE_ROOT/$LOCK_MODE_CLAIM/lock")" = 666 ]   || fail "helper silently changed unsafe lock file mode"

# Restore the canonical secure local inputs before legacy config-injection checks.
write_env 'https://panel.example'
printf '%s' 'Node_A' > "$NODE_ID_FILE"
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
