#!/usr/bin/env python3
import base64
import http.server
import json
import os
import pathlib
import pty
import select
import shutil
import signal
import ssl
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
request_path = pathlib.Path(extract(r'^data-binary = "@(.*)"$'))
authorization = extract(r'^header = "Authorization: (.*)"$')
if authorization != "Bearer group-token-private-test":
    raise SystemExit(97)
match = re.search(r"/node-credential-claims/([^/]+)/credential/(prepare|activate)$", url)
if not match:
    raise SystemExit(92)
claim_id, endpoint = match.groups()
phase = "PREPARE" if endpoint == "prepare" else "ACTIVATE"
capture = pathlib.Path(os.environ["FAKE_CAPTURE_DIR"])
capture.mkdir(parents=True, exist_ok=True)
request_bytes = request_path.read_bytes()
(capture / f"{endpoint}.json").write_bytes(request_bytes)
(capture / f"{endpoint}.argv").write_text(" ".join(sys.argv[1:]), encoding="utf-8")
(capture / f"{endpoint}.started").write_text("started\n", encoding="ascii")

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

request = json.loads(request_bytes.decode("utf-8"))
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
elif mode_name == "server_echo_secret":
    http = "500"
    body = {
        "code": 500,
        "message": request.get("claim_secret") or request.get("credential_secret") or "error",
        "data": None,
    }
elif mode_name == "wrong_identity":
    body["data"]["delivery"]["node_id"] = request["node_id"] + "_wrong"
elif mode_name == "forbidden_secret":
    body["data"]["credential_secret"] = "rpn1_SHOULD_NOT_BE_ACCEPTED"
elif mode_name == "duplicate":
    raw = '{"code":0,"code":0,"message":"ok","data":' + json.dumps(body["data"], separators=(",", ":")) + "}"
    sys.stdout.write(raw + "\n__RP_HTTP_STATUS__:200")
    raise SystemExit(0)
elif mode_name == "malformed":
    sys.stdout.write('{"code":0,"data":\n__RP_HTTP_STATUS__:200')
    raise SystemExit(0)
elif mode_name == "oversized":
    body["padding"] = "x" * 70000
elif mode_name == "status401_success":
    http = "401"

sys.stdout.write(json.dumps(body, separators=(",", ":")))
sys.stdout.write("\n__RP_HTTP_STATUS__:" + http)
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
            "NODE_TOKEN": "ENV_NODE_TOKEN_SHOULD_NOT_REACH_CHILD",
            "CLAIM_SECRET": "ENV_CLAIM_SECRET_SHOULD_NOT_REACH_CHILD",
            "CREDENTIAL_SECRET": "ENV_CREDENTIAL_SECRET_SHOULD_NOT_REACH_CHILD",
        }
    )
    return env


def run_helper(
    claim_id,
    secret=CLAIM_SECRET,
    group=7,
    slot="run",
    prepare="prepared",
    activate="activated",
    secret_delay=0.0,
    never_send=False,
    pid_file=None,
    delay=2,
    bash_args=None,
    extra_env=None,
):
    env = base_env(slot, prepare, activate, delay)
    if extra_env:
        env.update(extra_env)
    argv = ["bash"]
    if bash_args:
        argv.extend(bash_args)
    argv.extend([str(HELPER), "--claim-id", claim_id, "--home-group-id", str(group)])
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/bash", argv, env)
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


def ensure_local_state(claim_id):
    output = subprocess.check_output(
        [
            "python3",
            str(STATE_TOOL),
            "ensure",
            "--state-dir",
            str(STATE_ROOT / claim_id),
            "--claim-id",
            claim_id,
            "--group-id",
            "7",
            "--node-id",
            NODE_ID,
        ],
        text=True,
    ).strip()
    fields = output.split("\t")
    if len(fields) != 4:
        fail("test setup could not initialize durable Credential state")
    return fields


def assert_no_sensitive_transients(claim_id, permanent_secret=None):
    state_dir = STATE_ROOT / claim_id
    forbidden_prefixes = (
        ".credential-request.",
        ".credential-response.",
        ".credential-curl.",
        ".credential-http-code.",
    )
    for path in state_dir.iterdir():
        if path.name.startswith(forbidden_prefixes):
            fail(f"persistent sensitive transient remains after interruption: {path.name}")
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if CLAIM_SECRET.encode() in data or TOKEN.encode() in data:
            fail(f"Claim Secret or Group Token persisted in {path.name}")
        if (
            permanent_secret
            and permanent_secret.encode() in data
            and path.name != "node-credential.secret"
        ):
            fail(f"duplicate permanent Credential Secret persisted in {path.name}")


def run_real_curl_fd_test():
    if not sys.platform.startswith("linux"):
        print("NOT RUN: real curl FD wiring test requires Linux", file=sys.stderr)
        return
    real_curl = shutil.which("curl")
    openssl = shutil.which("openssl")
    if not real_curl or not openssl:
        fail("Linux real curl FD wiring test requires curl and openssl")

    test_dir = TMP / "real-curl"
    test_dir.mkdir()
    cert = test_dir / "cert.pem"
    key = test_dir / "key.pem"
    subprocess.check_call(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    claim_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    credential_id = "real-curl-credential"
    captured_http = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            request = json.loads(body.decode("utf-8"))
            captured_http["path"] = self.path
            captured_http["authorization"] = self.headers.get("Authorization")
            captured_http["content_type"] = self.headers.get("Content-Type")
            captured_http["body"] = request
            delivery = {
                "claim_id": claim_id,
                "home_group_id": 7,
                "node_id": NODE_ID,
                "credential_id": credential_id,
                "state": "PREPARED",
                "authorized_at": "2026-09-23T00:00:00Z",
                "expires_at": "2026-09-23T00:10:00Z",
                "updated_at": "2026-09-23T00:01:00Z",
                "credential_generation": None,
                "proof_verified_at": None,
                "completed_at": None,
                "cancelled_at": None,
                "expired_at": None,
            }
            response = json.dumps(
                {
                    "code": 0,
                    "message": "ok",
                    "data": {"outcome": "PREPARED", "delivery": delivery},
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format, *_args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    wrapper_dir = test_dir / "bin"
    wrapper_dir.mkdir()
    argv_file = test_dir / "curl.argv"
    wrapper = f'''#!/usr/bin/env python3
import os
import sys
with open(os.environ["REAL_CURL_ARGV_FILE"], "w", encoding="utf-8") as handle:
    handle.write("\\n".join(sys.argv[1:]))
os.execv({real_curl!r}, [{real_curl!r}] + sys.argv[1:])
'''
    write_executable(wrapper_dir / "curl", wrapper)
    env = os.environ.copy()
    env["PATH"] = str(wrapper_dir) + os.pathsep + env.get("PATH", "")
    env["CURL_CA_BUNDLE"] = str(cert)
    env["REAL_CURL_ARGV_FILE"] = str(argv_file)
    env.pop("NODE_TOKEN", None)
    env.pop("CLAIM_SECRET", None)
    env.pop("CREDENTIAL_SECRET", None)

    request = {
        "home_group_id": 7,
        "node_id": NODE_ID,
        "claim_secret": CLAIM_SECRET,
        "claimant_nonce": CLAIMANT_NONCE,
        "delivery_nonce": "rpdn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "credential_id": credential_id,
        "verifier_format": "rp-node-sha256",
        "verifier_version": 1,
        "verifier_data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }
    input_text = TOKEN + "\n" + json.dumps(request, separators=(",", ":"))
    try:
        result = subprocess.run(
            [
                "python3",
                str(STATE_TOOL),
                "request",
                "--phase",
                "PREPARE",
                "--url",
                f"https://127.0.0.1:{server.server_port}/api/v1/node-credential-claims/{claim_id}/credential/prepare",
                "--claim-id",
                claim_id,
                "--group-id",
                "7",
                "--node-id",
                NODE_ID,
                "--credential-id",
                credential_id,
            ],
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            timeout=20,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    if result.returncode != 0 or result.stdout.strip() != "SUCCESS:PREPARED":
        sys.stderr.write(result.stderr)
        fail("real curl FD wiring request failed")
    if captured_http.get("authorization") != f"Bearer {TOKEN}":
        fail("real curl did not receive the Bearer Token through config FD")
    if captured_http.get("content_type") != "application/json":
        fail("real curl did not send the expected Content-Type")
    if captured_http.get("path") != (
        f"/api/v1/node-credential-claims/{claim_id}/credential/prepare"
    ):
        fail("real curl used the wrong Credential endpoint")
    if captured_http.get("body") != request:
        fail("real curl did not read the independent JSON body FD exactly")
    argv = argv_file.read_text(encoding="utf-8")
    if "--config" not in argv or "/dev/fd/" not in argv:
        fail("real curl was not invoked through the anonymous config FD")
    for sensitive in (TOKEN, CLAIM_SECRET, CLAIMANT_NONCE, request["delivery_nonce"]):
        if sensitive in argv or sensitive in result.stdout or sensitive in result.stderr:
            fail("real curl FD test exposed sensitive material in argv/output")
    print("REAL CURL FD TEST: PASS")


try:
    write_env()
    write_node()
    env_before = ENV_FILE.read_bytes()
    node_before = NODE_ID_FILE.read_bytes()
    node_mode_before = mode(NODE_ID_FILE)

    # xtrace must fail closed before trusted config, Claim Secret, or durable
    # permanent Credential material is read or mutated.
    xtrace_claim = "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f"
    write_claim_pending(xtrace_claim)
    ensure_local_state(xtrace_claim)
    xtrace_state_before = (STATE_ROOT / xtrace_claim / "credential-pending.json").read_bytes()
    xtrace_secret_before = (STATE_ROOT / xtrace_claim / "node-credential.secret").read_bytes()
    xtrace_secret_wire = xtrace_secret_before.decode("ascii")
    status, output, _ = run_helper(
        xtrace_claim,
        slot="xtrace-direct",
        never_send=True,
        bash_args=["-x"],
    )
    if status == 0:
        fail("bash -x unexpectedly entered the sensitive Credential helper")
    assert_no_leak(output, TOKEN, CLAIM_SECRET, xtrace_secret_wire, CLAIMANT_NONCE)
    if (CAPTURE_ROOT / "xtrace-direct").exists():
        fail("bash -x reached the network transport")
    if (
        (STATE_ROOT / xtrace_claim / "credential-pending.json").read_bytes()
        != xtrace_state_before
        or (STATE_ROOT / xtrace_claim / "node-credential.secret").read_bytes()
        != xtrace_secret_before
    ):
        fail("bash -x mutated durable Credential state before rejection")

    status, output, _ = run_helper(
        xtrace_claim,
        slot="xtrace-option",
        never_send=True,
        bash_args=["-o", "xtrace"],
    )
    if status == 0:
        fail("bash -o xtrace unexpectedly entered the sensitive Credential helper")
    assert_no_leak(output, TOKEN, CLAIM_SECRET, xtrace_secret_wire, CLAIMANT_NONCE)
    if (CAPTURE_ROOT / "xtrace-option").exists():
        fail("bash -o xtrace reached the network transport")
    if (
        (STATE_ROOT / xtrace_claim / "credential-pending.json").read_bytes()
        != xtrace_state_before
        or (STATE_ROOT / xtrace_claim / "node-credential.secret").read_bytes()
        != xtrace_secret_before
    ):
        fail("bash -o xtrace mutated durable Credential state before rejection")

    bash_env = TMP / "enable-xtrace.bash"
    bash_env.write_text("set -x\n", encoding="ascii")
    status, output, _ = run_helper(
        xtrace_claim,
        slot="xtrace-inherited",
        never_send=True,
        extra_env={"BASH_ENV": str(bash_env)},
    )
    if status == 0:
        fail("BASH_ENV-enabled inherited xtrace unexpectedly entered the helper")
    assert_no_leak(output, TOKEN, CLAIM_SECRET, xtrace_secret_wire, CLAIMANT_NONCE)
    if (CAPTURE_ROOT / "xtrace-inherited").exists():
        fail("inherited xtrace reached the network transport")
    if (
        (STATE_ROOT / xtrace_claim / "credential-pending.json").read_bytes()
        != xtrace_state_before
        or (STATE_ROOT / xtrace_claim / "node-credential.secret").read_bytes()
        != xtrace_secret_before
    ):
        fail("inherited xtrace mutated durable Credential state before rejection")
    print("XTRACE NEGATIVE TESTS: PASS")

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

    # PREPARE in-flight SIGKILL: the fake transport has already read both
    # anonymous FDs before the shell is killed. No sensitive named transient
    # may remain, the flock must be immediately recoverable, and retry must
    # preserve the exact durable Credential material.
    claim = "66666666-6666-4666-8666-666666666666"
    write_claim_pending(claim)
    killed = {}
    pid_file = TMP / "prepare-killed.pid"
    thread = threading.Thread(
        target=lambda: killed.setdefault(
            "run",
            run_helper(
                claim,
                slot="prepare-killed-a",
                prepare="slow_prepared",
                pid_file=pid_file,
                delay=4,
            ),
        )
    )
    thread.start()
    started = CAPTURE_ROOT / "prepare-killed-a" / "prepare.started"
    if not wait_for(started) or not wait_for(pid_file):
        fail("PREPARE SIGKILL test never reached the in-flight transport")
    before_state = (STATE_ROOT / claim / "credential-pending.json").read_bytes()
    before_secret = (STATE_ROOT / claim / "node-credential.secret").read_bytes()
    before_doc = json.loads(before_state)
    before_secret_wire = before_secret.decode("ascii")
    first_prepare = captured("prepare-killed-a", "prepare")
    assert_no_sensitive_transients(claim, before_secret_wire)
    os.kill(int(pid_file.read_text()), signal.SIGKILL)
    thread.join(timeout=10)
    if thread.is_alive():
        fail("PREPARE SIGKILL helper did not terminate")
    assert_no_sensitive_transients(claim, before_secret_wire)
    if (STATE_ROOT / claim / "credential-pending.json").read_bytes() != before_state:
        fail("PREPARE SIGKILL changed durable pending state")
    if (STATE_ROOT / claim / "node-credential.secret").read_bytes() != before_secret:
        fail("PREPARE SIGKILL replaced durable permanent Secret")
    status, output, _ = run_helper(claim, slot="prepare-killed-b")
    if status != 0:
        fail("PREPARE retry after SIGKILL did not reacquire the Claim lock")
    retry_prepare = captured("prepare-killed-b", "prepare")
    if (
        retry_prepare["credential_id"] != before_doc["credential_id"]
        or retry_prepare["delivery_nonce"] != before_doc["delivery_nonce"]
        or retry_prepare["credential_id"] != first_prepare["credential_id"]
        or retry_prepare["delivery_nonce"] != first_prepare["delivery_nonce"]
    ):
        fail("PREPARE SIGKILL retry replaced stable delivery material")
    if (STATE_ROOT / claim / "node-credential.secret").read_bytes() != before_secret:
        fail("PREPARE SIGKILL retry generated a second permanent Secret")
    assert_no_sensitive_transients(claim, before_secret_wire)
    print("PREPARE IN-FLIGHT SIGKILL TEST: PASS")

    # ACTIVATE in-flight SIGKILL: PREPARE has already advanced durable state
    # to ACTIVATE_READY and the fake transport has read the activation body.
    # Restart must skip PREPARE and reuse the exact permanent proof material.
    claim = "67676767-6767-4767-8767-676767676767"
    write_claim_pending(claim)
    killed = {}
    pid_file = TMP / "activate-killed.pid"
    thread = threading.Thread(
        target=lambda: killed.setdefault(
            "run",
            run_helper(
                claim,
                slot="activate-killed-a",
                activate="slow_activated",
                pid_file=pid_file,
                delay=4,
            ),
        )
    )
    thread.start()
    started = CAPTURE_ROOT / "activate-killed-a" / "activate.started"
    if not wait_for(started) or not wait_for(pid_file):
        fail("ACTIVATE SIGKILL test never reached the in-flight transport")
    before_state = (STATE_ROOT / claim / "credential-pending.json").read_bytes()
    before_secret = (STATE_ROOT / claim / "node-credential.secret").read_bytes()
    before_doc = json.loads(before_state)
    before_secret_wire = before_secret.decode("ascii")
    first_activate = captured("activate-killed-a", "activate")
    if before_doc["phase"] != "ACTIVATE_READY":
        fail("ACTIVATE SIGKILL did not reach durable ACTIVATE_READY")
    assert_no_sensitive_transients(claim, before_secret_wire)
    os.kill(int(pid_file.read_text()), signal.SIGKILL)
    thread.join(timeout=10)
    if thread.is_alive():
        fail("ACTIVATE SIGKILL helper did not terminate")
    assert_no_sensitive_transients(claim, before_secret_wire)
    if (STATE_ROOT / claim / "credential-pending.json").read_bytes() != before_state:
        fail("ACTIVATE SIGKILL changed durable pending state")
    if (STATE_ROOT / claim / "node-credential.secret").read_bytes() != before_secret:
        fail("ACTIVATE SIGKILL replaced durable permanent Secret")
    status, output, _ = run_helper(
        claim,
        slot="activate-killed-b",
        prepare="fail",
        activate="existing",
    )
    if status != 0 or load_state(claim)["phase"] != "ACTIVE_CONFIRMED":
        fail("ACTIVATE retry after SIGKILL did not recover")
    if (CAPTURE_ROOT / "activate-killed-b" / "prepare.json").exists():
        fail("ACTIVATE retry after SIGKILL incorrectly restarted PREPARE")
    retry_activate = captured("activate-killed-b", "activate")
    if retry_activate != first_activate:
        fail("ACTIVATE retry after SIGKILL changed permanent proof material")
    if (
        retry_activate["credential_id"] != before_doc["credential_id"]
        or retry_activate["delivery_nonce"] != before_doc["delivery_nonce"]
        or retry_activate["credential_secret"] != before_secret_wire
    ):
        fail("ACTIVATE SIGKILL retry did not reuse stable durable material")
    assert_no_sensitive_transients(claim, before_secret_wire)
    print("ACTIVATE IN-FLIGHT SIGKILL TEST: PASS")

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
        assert_no_sensitive_transients(claim, local_secret)

    # Controlled HTTP failures also keep fixed local hints and durable material.
    for index, rejection in enumerate(
        [
            "invalid",
            "replay",
            "expired",
            "cancelled",
            "rate_limited",
            "server",
            "server_echo_secret",
        ]
    ):
        claim = f"bbbbbbb{index}-bbbb-4bbb-8bbb-{index:012d}"
        write_claim_pending(claim)
        status, output, _ = run_helper(claim, slot=f"reject-{rejection}", prepare=rejection)
        if status == 0:
            fail(f"rejection {rejection} unexpectedly succeeded")
        local_secret = (STATE_ROOT / claim / "node-credential.secret").read_text()
        assert_no_leak(output, CLAIM_SECRET, TOKEN, local_secret)
        assert_no_sensitive_transients(claim, local_secret)
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

    run_real_curl_fd_test()

    if ENV_FILE.read_bytes() != env_before or NODE_ID_FILE.read_bytes() != node_before:
        fail("final helper run modified existing Home-only config or node-id")

    print("relay-node-credential helper security/recovery tests: PASS")
finally:
    shutil.rmtree(TMP, ignore_errors=True)