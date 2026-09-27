#!/usr/bin/env python3
"""One-time exact-node migration. Never restarts forwarding or edits rules/LKG."""
import argparse
import contextlib
import fcntl
import getpass
import hashlib
import io
import json
import os
import re
import stat
import urllib.request
import urllib.parse

ROOT = "/var/lib/relay-panel/node-claims"
HELPER_SHA256 = "__STATE_HELPER_SHA256__"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("redirect refused")


def credential_identity_matches(request, secret, credential_id, group_id, node_id):
    try:
        return request("node/identity", None, "RelayNodeCredential " + secret, credential_id) == {
            "identity_group_id": group_id, "node_id": node_id}
    except Exception:
        return False


def activate_or_verify(request, endpoint, identity, state, secret):
    try:
        request(endpoint, dict(identity, credential_id=state["credential_id"],
            delivery_nonce=state["delivery_nonce"], credential_secret=secret))
    except Exception:
        if not credential_identity_matches(request, secret, state["credential_id"],
                identity["home_group_id"], identity["node_id"]):
            raise


def commit_migration_descriptor(atomic_write, path, descriptor, request, claim_id, secret, credential_id, bootstrap=False):
    atomic_write(path, json.dumps(descriptor).encode())
    if not bootstrap:
        request("node-pool/migrations/" + claim_id + "/complete", {},
            "RelayNodeCredential " + secret, credential_id)


def private_read(path, secret=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError("unsafe local file permissions")
        if secret and stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("unsafe secret permissions")
        data = source.read(65537)
        if len(data) > 65536:
            raise RuntimeError("local file exceeds limit")
        return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim-id", required=True)
    parser.add_argument("--identity-group-id", required=True, type=int)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--secret-file")
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or args.identity_group_id <= 0:
        raise RuntimeError("root and valid identity required")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", args.claim_id):
        raise RuntimeError("invalid migration locator")
    node_id = private_read("/opt/relay-node/node-id").decode("ascii").strip()
    if node_id != args.node_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", node_id):
        raise RuntimeError("persistent node identity does not match migration")
    config = {}
    for line in private_read("/etc/relay-node/relay-node.env").decode().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            config[key] = value.strip().strip("'").strip('"')
    origin = config.get("PANEL_URL", "").rstrip("/")
    url = urllib.parse.urlsplit(origin)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path:
        raise RuntimeError("trusted HTTPS Panel origin required")
    token = config.get("NODE_TOKEN", "")
    if not token or any(c.isspace() for c in token):
        raise RuntimeError("trusted legacy authentication unavailable")
    os.umask(0o077)
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    for directory in [ROOT, os.path.join(ROOT, args.claim_id)]:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("unsafe credential directory")
    parent = os.path.dirname(ROOT)
    while parent != "/":
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("unsafe credential parent")
        parent = os.path.dirname(parent)
    state_dir = os.path.join(ROOT, args.claim_id)
    lock_fd = os.open(os.path.join(ROOT, "migration.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("unsafe migration lock")
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    opener = urllib.request.build_opener(NoRedirect())
    helper_bytes = opener.open(origin + "/api/v1/node-pool/credential-state.py", timeout=15).read(100000)
    if hashlib.sha256(helper_bytes).hexdigest() != HELPER_SHA256:
        raise RuntimeError("credential helper integrity mismatch")
    namespace = {"__name__": "credential_state", "__file__": "credential_state"}
    exec(compile(helper_bytes, "credential_state", "exec"), namespace)
    with contextlib.redirect_stdout(io.StringIO()):
        namespace["ensure"](argparse.Namespace(state_dir=state_dir, claim_id=args.claim_id,
            group_id=args.identity_group_id, node_id=node_id))
    state_path = os.path.join(state_dir, "credential-pending.json")
    state = namespace["load_json"](state_path)
    secret = namespace["read_all_no_follow"](os.path.join(state_dir, state["secret_file"])).decode("ascii")
    nonce_path = os.path.join(state_dir, "pool-claimant-nonce")
    if not os.path.exists(nonce_path):
        namespace["atomic_write"](nonce_path, ("rpcn1_" + namespace["b64url"](os.urandom(32))).encode())
    nonce = namespace["read_all_no_follow"](nonce_path).decode("ascii")

    def request(endpoint, body, authorization=None, credential_id=None):
        headers = {"Authorization": authorization or "Bearer " + token, "Content-Type": "application/json", "X-Node-ID": node_id}
        if credential_id:
            headers["X-Node-Credential-ID"] = credential_id
        req = urllib.request.Request(origin + "/api/v1/" + endpoint,
            data=None if body is None else json.dumps(body).encode(), headers=headers)
        with opener.open(req, timeout=15) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("migration response exceeds limit")
        value = json.loads(raw, object_pairs_hook=namespace["reject_duplicates"])
        if not isinstance(value, dict):
            raise RuntimeError("invalid migration response")
        if body is not None and value.get("code") != 0:
            raise RuntimeError("migration authorization rejected; retry with the same local state")
        return value

    identity = {"home_group_id": args.identity_group_id, "node_id": node_id}
    prefix = "node-credential-claims/" + args.claim_id
    if state["phase"] == "PREPARE_READY":
        claim_secret = private_read(args.secret_file, secret=True).decode().strip() if args.secret_file else getpass.getpass("一次性安全迁移密钥: ")
        namespace["decode_wire"](claim_secret, "rpc1_")
        request(prefix + "/claim", dict(identity, secret=claim_secret, claimant_nonce=nonce))
        verifier = namespace["b64url"](namespace["derive_verifier"](state["credential_id"],
            args.identity_group_id, node_id, namespace["decode_wire"](secret, "rpn1_")))
        request(prefix + "/credential/prepare", dict(identity, claim_secret=claim_secret,
            claimant_nonce=nonce, delivery_nonce=state["delivery_nonce"], credential_id=state["credential_id"],
            verifier_format="rp-node-sha256", verifier_version=1, verifier_data=verifier))
        state["phase"] = "ACTIVATE_READY"
        namespace["atomic_write"](state_path, namespace["encode_state"](state))
    if state["phase"] == "ACTIVATE_READY":
        activate_or_verify(request, prefix + "/credential/activate", identity, state, secret)
        state["phase"] = "ACTIVE_CONFIRMED"
        namespace["atomic_write"](state_path, namespace["encode_state"](state))
    if not credential_identity_matches(request, secret, state["credential_id"], args.identity_group_id, node_id):
        raise RuntimeError("activated credential identity mismatch")
    descriptor = {"identity_group_id": args.identity_group_id, "node_id": node_id,
        "credential_id": state["credential_id"], "secret_file": os.path.join(state_dir, state["secret_file"])}
    commit_migration_descriptor(namespace["atomic_write"], os.path.join(ROOT, "runtime-auth.json"),
        descriptor, request, args.claim_id, secret, state["credential_id"], args.bootstrap)
    print("身份已安全持久化，等待节点控制连接确认。原有转发进程保持运行。")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("安全迁移未完成；原有认证和转发保留。请检查连接与授权后使用同一命令重试。")
