#!/usr/bin/env python3
"""B2-02B local state/crypto/response helper for relay-node-credential.sh.

No raw Claim Secret or permanent Credential Secret is printed. The only crypto
output is the non-bearer rp-node-sha256 verifier.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys
import uuid

MAX_RESPONSE_BYTES = 65536
MAX_DEPTH = 16
STATE_KEYS = {
    "version",
    "claim_id",
    "home_group_id",
    "node_id",
    "credential_id",
    "delivery_nonce",
    "secret_file",
    "phase",
}
PHASES = {"SECRET_PENDING", "PREPARE_READY", "ACTIVATE_READY", "ACTIVE_CONFIRMED"}
FORBIDDEN_RESPONSE_KEYS = {
    "claim_secret",
    "credential_secret",
    "claimant_nonce",
    "delivery_nonce",
    "secret",
    "verifier_data",
    "credential_verifier_data",
    "delivery_nonce_verifier_data",
    "node_token",
}
DELIVERY_KEYS = {
    "claim_id",
    "home_group_id",
    "node_id",
    "credential_id",
    "state",
    "authorized_at",
    "expires_at",
    "updated_at",
    "credential_generation",
    "proof_verified_at",
    "completed_at",
    "cancelled_at",
    "expired_at",
}
CREDENTIAL_KEYS = {
    "credential_id",
    "home_group_id",
    "node_id",
    "generation",
    "state",
    "activated_at",
    "revoked_at",
}
CONTROLLED_ERRORS = {
    "REPLAY",
    "EXPIRED",
    "CANCELLED",
    "RATE_LIMITED",
    "INVALID",
    "ALREADY_ACTIVE",
    "RECOVERY_REQUIRED",
    "CREDENTIAL_REVOKED",
}


class StateError(Exception):
    pass


def fail(message: str) -> "None":
    raise StateError(message)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_wire(value: str, prefix: str) -> bytes:
    if not value.startswith(prefix):
        fail("invalid local credential wire value")
    encoded = value[len(prefix) :]
    if len(encoded) != 43 or "=" in encoded:
        fail("invalid local credential wire value")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=")
    except Exception as exc:
        raise StateError("invalid local credential wire value") from exc
    if len(raw) != 32 or b64url(raw) != encoded:
        fail("invalid local credential wire value")
    return raw


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result


def secure_regular(path: str) -> None:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        fail("local credential state is not a regular file")
    if st.st_uid != os.geteuid():
        fail("local credential state has an unexpected owner")
    if stat.S_IMODE(st.st_mode) != 0o600:
        fail("local credential state must be mode 0600")


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_all_no_follow(path: str) -> bytes:
    secure_regular(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes) -> None:
    state_dir = os.path.dirname(path)
    if os.path.lexists(path):
        secure_regular(path)
    name = os.path.basename(path)
    tmp = os.path.join(state_dir, f".{name}.{os.getpid()}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    fsync_dir(state_dir)
    persisted = read_all_no_follow(path)
    if persisted != data:
        fail("durable local credential state verification failed")


def load_json(path: str):
    try:
        return json.loads(
            read_all_no_follow(path).decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateError("local credential state is malformed") from exc


def validate_credential_id(value) -> None:
    if not isinstance(value, str):
        fail("local credential id is invalid")
    raw = value.encode("utf-8")
    if not 1 <= len(raw) <= 128:
        fail("local credential id is invalid")
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    if any(ch not in allowed for ch in value):
        fail("local credential id is invalid")


def validate_state(state, claim_id: str, group_id: int, node_id: str) -> None:
    if not isinstance(state, dict) or set(state) != STATE_KEYS:
        fail("local credential state shape is invalid")
    if state["version"] != 1:
        fail("local credential state version is invalid")
    if state["claim_id"] != claim_id or state["home_group_id"] != group_id:
        fail("local credential state identity does not match")
    if state["node_id"] != node_id:
        fail("local credential state Node ID does not match")
    validate_credential_id(state["credential_id"])
    if not isinstance(state["delivery_nonce"], str):
        fail("local delivery nonce is invalid")
    decode_wire(state["delivery_nonce"], "rpdn1_")
    if state["secret_file"] != "node-credential.secret":
        fail("local Credential Secret reference is invalid")
    if state["phase"] not in PHASES:
        fail("local Credential phase is invalid")


def encode_state(state) -> bytes:
    return (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()


def derive_verifier(
    credential_id: str,
    group_id: int,
    node_id: str,
    secret: bytes,
) -> bytes:
    credential_bytes = credential_id.encode("utf-8")
    node_bytes = node_id.encode("ascii")
    digest = hashlib.sha256()
    digest.update(b"relay-panel/node-credential/v1\0")
    digest.update(len(credential_bytes).to_bytes(8, "big"))
    digest.update(credential_bytes)
    digest.update(group_id.to_bytes(8, "big", signed=True))
    digest.update(len(node_bytes).to_bytes(8, "big"))
    digest.update(node_bytes)
    digest.update(secret)
    return digest.digest()


def ensure(args) -> None:
    os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
    st = os.lstat(args.state_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        fail("private state directory is unsafe")
    if stat.S_IMODE(st.st_mode) != 0o700:
        fail("private state directory must be mode 0700")

    state_path = os.path.join(args.state_dir, "credential-pending.json")
    secret_path = os.path.join(args.state_dir, "node-credential.secret")
    if not os.path.lexists(state_path):
        if os.path.lexists(secret_path):
            fail("orphaned permanent Credential Secret requires operator review")
        state = {
            "version": 1,
            "claim_id": args.claim_id,
            "home_group_id": args.group_id,
            "node_id": args.node_id,
            "credential_id": str(uuid.uuid4()),
            "delivery_nonce": "rpdn1_" + b64url(os.urandom(32)),
            "secret_file": "node-credential.secret",
            "phase": "SECRET_PENDING",
        }
        validate_state(state, args.claim_id, args.group_id, args.node_id)
        atomic_write(state_path, encode_state(state))
    else:
        state = load_json(state_path)
        validate_state(state, args.claim_id, args.group_id, args.node_id)

    if state["phase"] == "SECRET_PENDING":
        if os.path.lexists(secret_path):
            secret_wire = read_all_no_follow(secret_path).decode("ascii", "strict")
            decode_wire(secret_wire, "rpn1_")
        else:
            secret_wire = "rpn1_" + b64url(os.urandom(32))
            atomic_write(secret_path, secret_wire.encode("ascii"))
        state["phase"] = "PREPARE_READY"
        atomic_write(state_path, encode_state(state))
    else:
        if not os.path.lexists(secret_path):
            fail("permanent Credential Secret is missing")
        secret_wire = read_all_no_follow(secret_path).decode("ascii", "strict")
        decode_wire(secret_wire, "rpn1_")

    secret_wire = read_all_no_follow(secret_path).decode("ascii", "strict")
    secret = decode_wire(secret_wire, "rpn1_")
    verifier = b64url(
        derive_verifier(state["credential_id"], args.group_id, args.node_id, secret)
    )
    print(
        state["credential_id"],
        state["delivery_nonce"],
        state["phase"],
        verifier,
        sep="\t",
    )


def set_phase(args) -> None:
    state = load_json(args.state)
    current = state.get("phase") if isinstance(state, dict) else None
    if current != args.expected or args.next not in PHASES:
        fail("local Credential phase transition rejected")
    state["phase"] = args.next
    atomic_write(args.state, encode_state(state))


def verifier(args) -> None:
    validate_credential_id(args.credential_id)
    raw = read_all_no_follow(args.secret_file).decode("ascii", "strict")
    secret = decode_wire(raw, "rpn1_")
    print(b64url(derive_verifier(args.credential_id, args.group_id, args.node_id, secret)))


def walk_response(value, depth=0) -> None:
    if depth > MAX_DEPTH:
        fail("response nesting too deep")
    if isinstance(value, dict):
        if any(key in FORBIDDEN_RESPONSE_KEYS for key in value):
            fail("response contains forbidden sensitive fields")
        for child in value.values():
            walk_response(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            walk_response(child, depth + 1)


def parse_response(args) -> None:
    with open(args.response, "rb") as handle:
        raw = handle.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        fail("response too large")
    try:
        doc = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(StateError("invalid number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateError("invalid response JSON") from exc
    if not isinstance(doc, dict) or set(doc) != {"code", "message", "data"}:
        fail("invalid response envelope")
    if type(doc["code"]) is not int or not isinstance(doc["message"], str):
        fail("invalid response envelope")
    walk_response(doc)

    data = doc["data"]
    outcome = data.get("outcome") if isinstance(data, dict) else None
    successes = {
        "PREPARE": {"PREPARED", "EXISTING"},
        "ACTIVATE": {"ACTIVATED", "EXISTING"},
    }
    if args.http_code == "200" and doc["code"] == 0 and outcome in successes[args.phase]:
        expected_data = (
            {"outcome", "delivery"}
            if args.phase == "PREPARE"
            else {"outcome", "delivery", "credential"}
        )
        if set(data) != expected_data:
            fail("invalid success response shape")
        delivery = data["delivery"]
        if not isinstance(delivery, dict) or set(delivery) != DELIVERY_KEYS:
            fail("invalid delivery response shape")
        if (
            delivery["claim_id"] != args.claim_id
            or type(delivery["home_group_id"]) is not int
            or delivery["home_group_id"] != args.group_id
            or delivery["node_id"] != args.node_id
            or delivery["credential_id"] != args.credential_id
        ):
            fail("response identity mismatch")
        if args.phase == "PREPARE":
            if delivery["state"] != "PREPARED" or delivery["credential_generation"] is not None:
                fail("invalid PREPARE state")
        else:
            generation = delivery["credential_generation"]
            credential = data["credential"]
            if delivery["state"] != "COMPLETED" or type(generation) is not int or generation < 1:
                fail("invalid ACTIVATE delivery state")
            if not isinstance(credential, dict) or set(credential) != CREDENTIAL_KEYS:
                fail("invalid credential response shape")
            if (
                credential["credential_id"] != args.credential_id
                or type(credential["home_group_id"]) is not int
                or credential["home_group_id"] != args.group_id
                or credential["node_id"] != args.node_id
                or credential["generation"] != generation
                or credential["state"] != "ACTIVE"
                or not isinstance(credential["activated_at"], str)
                or credential["revoked_at"] is not None
            ):
                fail("invalid activated Credential response")
        print(f"SUCCESS:{outcome}")
        return

    if (
        args.http_code in {"401", "409", "410", "429"}
        and isinstance(data, dict)
        and outcome in CONTROLLED_ERRORS
    ):
        print(f"ERROR:{outcome}")
        return
    if args.http_code.startswith("5"):
        print("ERROR:SERVER")
        return
    fail("response is not an allowed Credential result")


def build_parser():
    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest="command", required=True)

    ensure_parser = sub.add_parser("ensure", add_help=False)
    ensure_parser.add_argument("--state-dir", required=True)
    ensure_parser.add_argument("--claim-id", required=True)
    ensure_parser.add_argument("--group-id", type=int, required=True)
    ensure_parser.add_argument("--node-id", required=True)
    ensure_parser.set_defaults(func=ensure)

    phase_parser = sub.add_parser("phase", add_help=False)
    phase_parser.add_argument("--state", required=True)
    phase_parser.add_argument("--expected", required=True)
    phase_parser.add_argument("--next", required=True)
    phase_parser.set_defaults(func=set_phase)

    verifier_parser = sub.add_parser("verifier", add_help=False)
    verifier_parser.add_argument("--credential-id", required=True)
    verifier_parser.add_argument("--group-id", type=int, required=True)
    verifier_parser.add_argument("--node-id", required=True)
    verifier_parser.add_argument("--secret-file", required=True)
    verifier_parser.set_defaults(func=verifier)

    response_parser = sub.add_parser("parse-response", add_help=False)
    response_parser.add_argument("--phase", choices=["PREPARE", "ACTIVATE"], required=True)
    response_parser.add_argument("--http-code", required=True)
    response_parser.add_argument("--response", required=True)
    response_parser.add_argument("--claim-id", required=True)
    response_parser.add_argument("--group-id", type=int, required=True)
    response_parser.add_argument("--node-id", required=True)
    response_parser.add_argument("--credential-id", required=True)
    response_parser.set_defaults(func=parse_response)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.func(args)
        return 0
    except StateError as exc:
        print(f"credential helper state error: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print("credential helper state error: local state operation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
