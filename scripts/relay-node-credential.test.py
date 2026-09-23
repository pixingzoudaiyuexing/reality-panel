#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import pty
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent
HELPER = ROOT / "relay-node-credential.sh"
STATE_TOOL = ROOT / "relay-node-credential-state.py"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="relay-node-credential-test-"))
FAKE_BIN = TMP / "bin"
FAKE_BIN.mkdir()
ENV_FILE = TMP / "relay-node.env"
NODE_ID_FILE = TMP / "node-id"
STATE_ROOT = TMP / "state"
OUTPUT_ROOT = TMP / "output"
CAPTURE_ROOT = TMP / "capture"
CAPTURE_ROOT.mkdir()
TOKEN = "group-token-private-test"
CLAIM_SECRET = "rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CLAIMANT_NONCE = "rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
NODE_ID = "Node_A"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def write_executable(path, content):
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


write_executable(
    FAKE_BIN / "id",
    """#!/usr/bin/env sh
if [ "$1" = "-u" ]; then
  printf '0\\n'
  exit 0
fi
exec /usr/bin/id "$@"
""",
)

if shutil.which("flock") is None:
    write_executable(
        FAKE_BIN / "flock",
        """#!/usr/bin/env python3
import errno, fcntl, sys
if len(sys.argv) != 3 or sys.argv[1] != "-n":
    raise SystemExit(64)
try:
    fcntl.flock(int(sys.argv[2]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as exc:
    if exc.errno in (errno.EACCES, errno.EAGAIN):
        raise SystemExit(1)
    raise
""",
    )

fake_curl = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import re
import stat
import sys
import time

if len(sys.argv) != 3 or sys.argv[1] != "--config":
    raise SystemExit(90)
config = pathlib.Path(sys.argv[2])
text = config.read_text(encoding="utf-8")
def extract(pattern):
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(91)
    return match.group(1).replace(r"\\\"", '"').replace(r"\\\\", "\\")

url = extract(r'^url = "(.*)"$')
output = pathlib.Path(extract(r'^output = "(.*)"$'))
request_path = pathlib.Path(extract(r'^data-binary = "@(.*)"$'))
match = re.search(r"/node-credential-claims/([^/]+)/credential/(prepare|activate)$", url)
if not match:
    raise SystemExit(92)
claim_id, endpoint = match.groups()
phase = "PREPARE" if endpoint == "prepare" else "ACTIVATE"
capture = pathlib.Path(os.environ["FAKE_CAPTURE_DIR"])
capture.mkdir(parents=True, exist_ok=True)
shutil_path = capture / f"{endpoint}.json"
shutil_path.write_bytes(request_path.read_bytes())
(capture / f"{endpoint}.argv").write_text(" ".join(sys.argv[1:]), encoding="utf-8")
(capture / f"{endpoint}.config").write_text(text, encoding="utf-8")

state_dir = pathlib.Path(os.environ["CREDENTIAL_TEST_STATE_ROOT"]) / claim_id
state_file = state_dir / "credential-pending.json"
secret_file = state_dir / "node-credential.secret"
if not state_file.is_file() or state_file.is_symlink():
    raise SystemExit(93)
if not secret_file.is_file() or secret_file.is_symlink():
    raise SystemExit(94)
if stat.S_IMODE(state_file.stat().st_mode) != 0o600 or stat.S_IMODE(secret_file.stat().st_mode) != 0o600:
    raise SystemExit(95)
state = json.loads(state_file.read_text(encoding="utf-8"))
expected_phase = "PREPARE_READY" if phase == "PREPARE" else "ACTIVATE_READY"
if state.get("phase") != expected_phase:
    raise SystemExit(96)

request = json.loads(request_path.read_text(encoding="utf-8"))
mode_name = os.environ.get(
    "FAKE_PREPARE_MODE" if phase == "PREPARE" else "FAKE_ACTIVATE_MODE",
    "prepared" if phase == "PREPARE" else "activated",
)
if mode_name.startswith("slow_"):
    time.sleep(float(os.environ.get("FAKE_DELAY", "2")))
    mode_name = mode_name[5:]
if mode_name == "fail":
    raise SystemExit(7)

delivery = {
    "claim_id": claim_id,
    "home_group_id": request["home_group_id"],
    "node_id": request["node_id"],
    "credential_id": request["credential_id"],
    "state": "PREPARED" if phase == "PREPARE" else "COMPLETED",
    "authorized_at": "2026-09-23T00:00:00Z",
    "expires_at": "2026-09-23T00:10:00Z",
    "updated_at": "2026-09-23T00:01:00Z",
    "credential_generation": None if phase == "PREPARE" else 1,
    "proof_verified_at": None if phase == "PREPARE" else "2026-09-23T00:01:00Z",
    "completed_at": None if phase == "PREPARE" else "2026-09-23T00:01:00Z",
    "cancelled_at": None,
    "expired_at": None,
}
credential = {
    "credential_id": request["credential_id"],
    "home_group_id": request["home_group_id"],
    "node_id": request["node_id"],
    "generation": 1,
    "state": "ACTIVE",
    "activated_at": "2026-09-23T00:01:00Z",
    "revoked_at": None,
}
success = "PREPARED" if phase == "PREPARE" else "ACTIVATED"
if mode_name == "existing":
    success = "EXISTING"
body = {
    "code": 0,
    "message": "ok",
    "data": {"outcome": success, "delivery": delivery},
}
if phase == "ACTIVATE":
    body["data"]["credential"] = credential
http = "200"

errors = {
    "invalid": ("INVALID", "401"),
    "replay": ("REPLAY", "409"),
    "expired": ("EXPIRED", "410"),
    "cancelled": ("CANCELLED", "410"),
    "rate_limited": ("RATE_LIMITED", "429"),
    "already_active": ("ALREADY_ACTIVE", "409"),
    "recovery_required": ("RECOVERY_REQUIRED", "409"),
    "credential_revoked": ("CREDENTIAL_REVOKED", "409"),
}
if mode_name in errors:
    outcome, http = errors[mode_name]
    body = {"code": int(http), "message": "rejected", "data": {"outcome": outcome}}
elif mode_name == "server":
    http = "500"
    body = {"code": 500, "message": "error", "data": None}
elif mode_name == "wrong_identity":
    body["data"]["delivery"]["node_id"] = request["node_id"] + "_wrong"
elif mode_name == "forbidden_secret":
    body["data"]["credential_secret"] = "rpn1_SHOULD_NOT_BE_ACCEPTED"
elif mode_name == "duplicate":
    raw = '{"code":0,"code":0,"message":"ok","data":' + json.dumps(body["data"], separators=(",", ":")) + "}"
    output.write_text(raw, encoding="utf-8")
    print("200", end="")
    raise SystemExit(0)
elif mode_name == "malformed":
    output.write_text('{"code":0,"data":', encoding="utf-8")
    print("200", end="")
    raise SystemExit(0)
elif mode_name == "oversized":
    body["padding"] = "x" * 70000
elif mode_name == "status401_success":
    http = "401"

output.write_text(json.dumps(body, separators=(",", ":")), encoding="utf-8")
print(http, end="")
'''
write_executable(FAKE_BIN / "curl", fake_curl)


def write_env(panel_url="https://panel.example", token=TOKEN):
    ENV_FILE.write_text(f"PANEL_URL='{panel_url}'\nNODE_TOKEN='{token}'\n", encoding="utf-8")
    ENV_FILE.chmod(0o600)


def write_node(content=NODE_ID, file_mode=0o600):
    NODE_ID_FILE.write_bytes(content.encode("ascii"))
    NODE_ID_FILE.chmod(file_mode)


def write_claim_pending(claim_id, group=7, node=NODE_ID, nonce=CLAIMANT_NONCE):
    path = STATE_ROOT / claim_id
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    pending = path / "pending"
    pending.write_text(f"{claim_id}\n{group}\n{node}\n{nonce}\n", encoding="ascii")
    pending.chmod(0o600)
    return path


def base_env(slot, prepare="prepared", activate="activated", delay=2):
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(FAKE_BIN) + os.pathsep + env.get("PATH", ""),
            "RELAY_NODE_CREDENTIAL_ENV_FILE": str(ENV_FILE),
            "RELAY_NODE_CREDENTIAL_NODE_ID_FILE": str(NODE_ID_FILE),
            "RELAY_NODE_CREDENTIAL_STATE_ROOT": str(STATE_ROOT),
            "CREDENTIAL_TEST_STATE_ROOT": str(STATE_ROOT),
            "FAKE_CAPTURE_DIR": str(CAPTURE_ROOT / slot),
            "FAKE_PREPARE_MODE": prepare,
            "FAKE_ACTIVATE_MODE": activate,
            "FAKE_DELAY": str(delay),
        }
    )
    return env


def run_helper(claim_id, secret=CLAIM_SECRET, group=7, slot="run", prepare="prepared",
               activate="activated", secret_delay=0.0, never_send=False, pid_file=None):
    env = base_env(slot, prepare, activate)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(
            "/bin/bash",
            ["bash", str(HELPER), "--claim-id", claim_id, "--home-group-id", str(group)],
            env,
        )
    if pid_file:
        pathlib.Path(pid_file).write_text(str(pid), encoding="ascii")
    captured = bytearray()
    sent = False
    prompt_at = None
    status = None
    deadline = time.time() + 30
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                data = os.read(fd, 4096)
            except OSError:
                data = b""
            if data:
                captured.extend(data)
                if b"enter one-time Claim Secret:" in captured and prompt_at is None:
                    prompt_at = time.time()
        if (
            prompt_at is not None
            and not sent
            and not never_send
            and time.time() - prompt_at >= secret_delay
        ):
            try:
                os.write(fd, secret.encode() + b"\n")
                sent = True
            except OSError:
                pass
        waited, raw = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            status = os.waitstatus_to_exitcode(raw)
            break
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        status = 124
    else:
        while True:
            ready, _, _ = select.select([fd], [], [], 0.03)
            if not ready:
                break
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            captured.extend(data)
    out = OUTPUT_ROOT.with_name(OUTPUT_ROOT.name + "-" + slot)
    out.write_bytes(captured)
    return status, bytes(captured), pid


def wait_for(path, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pathlib.Path(path).exists():
            return True
        time.sleep(0.05)
    return False


def load_state(claim_id):
    return json.loads((STATE_ROOT / claim_id / "credential-pending.json").read_text())


def captured(slot, phase):
    return json.loads((CAPTURE_ROOT / slot / f"{phase}.json").read_text())


def assert_no_leak(output, *values):
    text = output.decode("utf-8", "replace")
    for value in values:
        if value and value in text:
            fail("sensitive value leaked to helper terminal output")


try:
    write_env()
    write_node()
    env_before = ENV_FILE.read_bytes()
    node_before = NODE_ID_FILE.read_bytes()
    node_mode_before = mode(NODE_ID_FILE)

    # End-to-end success. The fake network verifies durable state+Secret exist
    # with mode 0600 before either request is accepted.
    claim = "11111111-1111-4111-8111-111111111111"
    write_claim_pending(claim)
    status, output, _ = run_helper(claim, slot="success")
    if status != 0:
        sys.stderr.buffer.write(output)
        fail("successful helper flow failed")
    state = load_state(claim)
    secret_path = STATE_ROOT / claim / "node-credential.secret"
    if state["phase"] != "ACTIVE_CONFIRMED":
        fail("success did not durably reach ACTIVE_CONFIRMED")
    if mode(secret_path) != 0o600 or mode(STATE_ROOT / claim / "credential-pending.json") != 0o600:
        fail("Credential state files are not mode 0600")
    if mode(STATE_ROOT / claim) != 0o700 or mode(STATE_ROOT / claim / "lock") != 0o600:
        fail("Credential state directory/lock permissions are unsafe")
    secret_wire = secret_path.read_text(encoding="ascii")
    if not secret_wire.startswith("rpn1_") or len(secret_wire) != 48 or "=" in secret_wire:
        fail("permanent Credential Secret is not canonical")
    raw_secret = base64.urlsafe_b64decode(secret_wire[5:] + "=")
    if len(raw_secret) != 32:
        fail("permanent Credential Secret is not 32 bytes")
    prep = captured("success", "prepare")
    act = captured("success", "activate")
    if "credential_secret" in prep or "claim_secret" not in prep or "claimant_nonce" not in prep:
        fail("PREPARE request has the wrong proof material")
    if "claim_secret" in act or "claimant_nonce" in act or act["credential_secret"] != secret_wire:
        fail("ACTIVATE request has the wrong proof material")
    if prep["credential_id"] != act["credential_id"] or prep["delivery_nonce"] != act["delivery_nonce"]:
        fail("PREPARE/ACTIVATE did not use stable material")
    if CLAIM_SECRET in (STATE_ROOT / claim / "credential-pending.json").read_text():
        fail("raw Claim Secret was persisted in Credential state")
    assert_no_leak(output, CLAIM_SECRET, TOKEN, secret_wire, prep["delivery_nonce"])
    if ENV_FILE.read_bytes() != env_before or NODE_ID_FILE.read_bytes() != node_before:
        fail("helper modified Home-only env or persistent node-id")
    if mode(NODE_ID_FILE) != node_mode_before:
        fail("helper changed persistent node-id mode")

    # Existing Rust fixed vector, executed through the production Python helper.
    vector_dir = TMP / "vector"
    vector_dir.mkdir()
    vector_dir.chmod(0o700)
    vector_secret = vector_dir / "secret"
    vector_secret.write_text(
        "rpn1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", encoding="ascii"
    )
    vector_secret.chmod(0o600)
    vector = subprocess.check_output(
        [
            "python3", str(STATE_TOOL), "verifier",
            "--credential-id", "cred-vector-1",
            "--group-id", "42",
            "--node-id", "Node_A",
            "--secret-file", str(vector_secret),
        ],
        text=True,
    ).strip()
    if vector != "fUg0hUYogwpLIa4D53rSl34gLgrJTVFMhzLhYPmgYYY":
        fail("Helper verifier does not match the Rust fixed vector")

    # PREPARE response loss: stable state and Secret must be reused.
    claim = "22222222-2222-4222-8222-222222222222"
    write_claim_pending(claim)
    status, output, _ = run_helper(claim, slot="prepare-loss-a", prepare="fail")
    if status == 0:
        fail("PREPARE transport loss unexpectedly succeeded")
    before_state = (STATE_ROOT / claim / "credential-pending.json").read_bytes()
    before_secret = (STATE_ROOT / claim / "node-credential.secret").read_bytes()
    if load_state(claim)["phase"] != "PREPARE_READY":
        fail("PREPARE loss did not retain PREPARE_READY")
    status, output, _ = run_helper(claim, slot="prepare-loss-b")
    if status != 0:
        fail("PREPARE response-loss retry failed")
    after = load_state(claim)
    if after["credential_id"] != json.loads(before_state)["credential_id"]:
        fail("PREPARE retry generated a new credential_id")
    if (STATE_ROOT / claim / "node-credential.secret").read_bytes() != before_secret:
        fail("PREPARE retry generated a new permanent Secret")
    p2 = captured("prepare-loss-b", "prepare")
    if p2["delivery_nonce"] != json.loads(before_state)["delivery_nonce"]:
        fail("PREPARE retry generated a new Delivery nonce")

    # ACTIVATE response loss: retry skips PREPARE and reuses exact activation material.
    claim = "33333333-3333-4333-8333-333333333333"
    write_claim_pending(claim)
    status, output, _ = run_helper(claim, slot="activate-loss-a", activate="fail")
    if status == 0 or load_state(claim)["phase"] != "ACTIVATE_READY":
        fail("ACTIVATE transport loss did not retain ACTIVATE_READY")
    first_act = captured("activate-loss-a", "activate")
    status, output, _ = run_helper(
        claim, slot="activate-loss-b", prepare="fail", activate="existing"
    )
    if status != 0 or load_state(claim)["phase"] != "ACTIVE_CONFIRMED":
        fail("ACTIVATE response-loss Existing retry failed")
    if (CAPTURE_ROOT / "activate-loss-b" / "prepare.json").exists():
        fail("ACTIVATE retry incorrectly restarted PREPARE")
    if captured("activate-loss-b", "activate") != first_act:
        fail("ACTIVATE retry did not reuse exact permanent proof material")

    # Same-Claim lock spans TTY and request; different Claims remain independent.
    claim = "44444444-4444-4444-8444-444444444444"
    write_claim_pending(claim)
    result = {}
    thread = threading.Thread(
        target=lambda: result.setdefault(
            "first", run_helper(claim, slot="lock-a", secret_delay=2)
        )
    )
    thread.start()
    if not wait_for(STATE_ROOT / claim / "credential-pending.json"):
        fail("first same-Claim helper did not persist state")
    second = run_helper(claim, slot="lock-b")
    if second[0] == 0 or (CAPTURE_ROOT / "lock-b" / "prepare.json").exists():
        fail("second same-Claim helper bypassed the flock")
    other = "55555555-5555-4555-8555-555555555555"
    write_claim_pending(other)
    other_result = run_helper(other, slot="lock-other")
    if other_result[0] != 0:
        fail("different Claim was blocked by unrelated Claim lock")
    thread.join(timeout=10)
    if thread.is_alive() or result["first"][0] != 0:
        fail("first same-Claim helper did not complete")

    # SIGKILL releases the kernel lock and keeps stable local material.
    claim = "66666666-6666-4666-8666-666666666666"
    write_claim_pending(claim)
    killed = {}
    pid_file = TMP / "killed.pid"
    thread = threading.Thread(
        target=lambda: killed.setdefault(
            "run", run_helper(claim, slot="killed-a", never_send=True, pid_file=pid_file)
        )
    )
    thread.start()
    if not wait_for(STATE_ROOT / claim / "credential-pending.json") or not wait_for(pid_file):
        fail("SIGKILL helper did not reach durable pre-PREPARE state")
    before_state = (STATE_ROOT / claim / "credential-pending.json").read_bytes()
    before_secret = (STATE_ROOT / claim / "node-credential.secret").read_bytes()
    os.kill(int(pid_file.read_text()), signal.SIGKILL)
    thread.join(timeout=10)
    status, output, _ = run_helper(claim, slot="killed-b")
    if status != 0:
        fail("retry after SIGKILL did not reacquire lock")
    if json.loads(before_state)["credential_id"] != load_state(claim)["credential_id"]:
        fail("SIGKILL retry replaced credential_id")
    if before_secret != (STATE_ROOT / claim / "node-credential.secret").read_bytes():
        fail("SIGKILL retry replaced durable Secret")

    # Historical 0644 node-id remains compatible and unchanged.
    write_node(file_mode=0o644)
    historical_claim = "77777777-7777-4777-8777-777777777777"
    write_claim_pending(historical_claim)
    before = NODE_ID_FILE.read_bytes()
    status, _, _ = run_helper(historical_claim, slot="node-0644")
    if status != 0 or NODE_ID_FILE.read_bytes() != before or mode(NODE_ID_FILE) != 0o644:
        fail("historical 0644 node-id was rejected or modified")
    write_node()

    # Unsafe local paths/modes fail before network.
    bad_claim = "88888888-8888-4888-8888-888888888888"
    write_claim_pending(bad_claim)
    NODE_ID_FILE.chmod(0o666)
    status, _, _ = run_helper(bad_claim, slot="node-0666")
    if status == 0 or (CAPTURE_ROOT / "node-0666" / "prepare.json").exists():
        fail("world-writable node-id reached network")
    write_node()
    ENV_FILE.chmod(0o644)
    status, _, _ = run_helper(bad_claim, slot="env-0644")
    if status == 0:
        fail("mode 0644 sensitive config unexpectedly succeeded")
    ENV_FILE.chmod(0o600)

    symlink_claim = "99999999-9999-4999-8999-999999999999"
    symlink_dir = write_claim_pending(symlink_claim)
    (symlink_dir / "lock").symlink_to(TMP / "attacker-lock")
    status, _, _ = run_helper(symlink_claim, slot="lock-symlink")
    if status == 0:
        fail("symlinked lock unexpectedly succeeded")

    # Malicious/forged response shapes never report success or leak secrets.
    attacks = ["wrong_identity", "forbidden_secret", "duplicate", "malformed", "oversized", "status401_success"]
    for index, attack in enumerate(attacks):
        claim = f"aaaaaaa{index}-aaaa-4aaa-8aaa-{index:012d}"
        write_claim_pending(claim)
        status, output, _ = run_helper(claim, slot=f"attack-{attack}", prepare=attack)
        if status == 0:
            fail(f"malicious response {attack} unexpectedly succeeded")
        local_secret = (STATE_ROOT / claim / "node-credential.secret").read_text()
        assert_no_leak(output, CLAIM_SECRET, TOKEN, local_secret)

    # Controlled HTTP failures also keep fixed local hints and durable material.
    for index, rejection in enumerate(
        ["invalid", "replay", "expired", "cancelled", "rate_limited", "server"]
    ):
        claim = f"bbbbbbb{index}-bbbb-4bbb-8bbb-{index:012d}"
        write_claim_pending(claim)
        status, output, _ = run_helper(claim, slot=f"reject-{rejection}", prepare=rejection)
        if status == 0:
            fail(f"rejection {rejection} unexpectedly succeeded")
        local_secret = (STATE_ROOT / claim / "node-credential.secret").read_text()
        assert_no_leak(output, CLAIM_SECRET, TOKEN, local_secret)
        if load_state(claim)["phase"] != "PREPARE_READY":
            fail(f"rejection {rejection} corrupted retry phase")

    # Non-owner validation is real when root/passwordless sudo is available.
    real_uid = os.getuid()
    real_gid = os.getgid()
    chown_prefix = None
    if real_uid == 0:
        chown_prefix = []
    elif shutil.which("sudo") and subprocess.run(
        ["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0:
        chown_prefix = ["sudo"]
    if chown_prefix is not None:
        write_node()
        subprocess.check_call(chown_prefix + ["chown", "65534:65534", str(NODE_ID_FILE)])
        claim = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        write_claim_pending(claim)
        status, _, _ = run_helper(claim, slot="non-owner")
        if status == 0:
            fail("non-owned node-id unexpectedly succeeded")
        subprocess.check_call(
            chown_prefix + ["chown", f"{real_uid}:{real_gid}", str(NODE_ID_FILE)]
        )
        NODE_ID_FILE.chmod(0o600)
    else:
        print("NOT RUN: non-owner node-id check requires root or passwordless sudo", file=sys.stderr)

    # Symlinked Credential state and Secret are rejected.
    write_node()
    state_claim = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    state_dir = write_claim_pending(state_claim)
    (state_dir / "credential-pending.json").symlink_to(TMP / "attacker-state")
    status, _, _ = run_helper(state_claim, slot="state-symlink")
    if status == 0:
        fail("symlinked Credential state unexpectedly succeeded")

    if ENV_FILE.read_bytes() != env_before or NODE_ID_FILE.read_bytes() != node_before:
        fail("final helper run modified existing Home-only config or node-id")

    print("relay-node-credential helper security/recovery tests: PASS")
finally:
    shutil.rmtree(TMP, ignore_errors=True)
