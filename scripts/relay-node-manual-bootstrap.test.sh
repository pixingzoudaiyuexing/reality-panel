#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
WRAPPER="$SCRIPT_DIR/relay-node-manual-bootstrap.sh"
STATE_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$STATE_ROOT"' EXIT

run_verify_test() {
  local sequence="$1" timeout="$2" expected_status="$3" expected_text="$4"
  local output status=0
  output="$({
    RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_MODE=1 \
    RELAY_PANEL_MANUAL_BOOTSTRAP_TEST_VERIFY_SEQUENCE="$sequence" \
    RELAY_PANEL_MANUAL_BOOTSTRAP_STATE_ROOT="$STATE_ROOT" \
    RELAY_PANEL_MANUAL_BOOTSTRAP_VERIFY_INTERVAL_SECS=1 \
    RELAY_PANEL_MANUAL_BOOTSTRAP_VERIFY_TIMEOUT_SECS="$timeout" \
    bash "$WRAPPER" \
      --panel-url http://panel.test:19088 \
      --enrollment-id 11111111-1111-1111-1111-111111111111 \
      --test-verify-convergence
  } 2>&1)" || status=$?
  [ "$status" -eq "$expected_status" ]
  grep -F "$expected_text" <<<"$output" >/dev/null
}

bash -n "$WRAPPER"
run_verify_test "NODE_NOT_FOUND,OK" 5 0 "test verifier convergence succeeded"
run_verify_test "STALE_OBSERVED_STATE,CAPABILITY_NOT_REPORTED,OK" 5 0 "test verifier convergence succeeded"
run_verify_test "NODE_NOT_FOUND,NODE_NOT_FOUND,NODE_NOT_FOUND" 2 1 "Panel capability verification timed out"
run_verify_test "ARCHITECTURE_MISMATCH,OK" 5 1 "ARCHITECTURE_MISMATCH"

printf '%s\n' "manual bootstrap verifier convergence tests passed"
