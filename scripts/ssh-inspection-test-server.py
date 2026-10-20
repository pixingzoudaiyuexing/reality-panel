#!/usr/bin/env python3
"""TEST ONLY: real loopback SSH, fixed public auth and emulated Debian OS probe.

Requires Python 3 + paramiko. Run: python3 scripts/ssh-inspection-test-server.py [MODE]
Only the exact repository inspection payload runs, under the current Python in an
empty temporary RP_INSPECT_ROOT. This is not a general shell or a Debian runtime.
The test parent owns this process and must terminate it after use.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

import paramiko
USERNAME, PASSWORD = "inspection-test", "public-fixture-password"
PYTHON_PROBE = "command -v python3 >/dev/null 2>&1"
OS_PROBE = "set -eu; . /etc/os-release; printf '%s|%s\\n' \"${PRETTY_NAME:-Linux}\" \"$(uname -m)\""
SCRIPTS = Path(__file__).resolve().parent
CLEANUP = base64.b64encode((SCRIPTS / "relay-node-failed-install-cleanup.py").read_bytes()).decode()
INSPECT = base64.b64encode((SCRIPTS / "relay-node-existing-install.py").read_bytes()).decode()
PAYLOAD = ('import base64; ns={"__name__":"retry_helper"};'
           f'exec(base64.b64decode("{CLEANUP}"),ns);'
           f'exec(base64.b64decode("{INSPECT}"),'
           '{"__name__":"__main__","failed_retry_inspection":ns["inspection"]})').encode()
LEGACY_COMMAND = "python3 -c '" + PAYLOAD.decode() + "'"
LIMIT = 1024 * 1024

def inventory(root):
    entries = []
    for path in [root, *sorted(root.rglob("*"))]:
        stat = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        entries.append((str(path.relative_to(root)), stat.st_mode, stat.st_size,
                        stat.st_mtime_ns, digest))
    return entries

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.requests = {}
    def get_allowed_auths(self, username):
        return "password"
    def check_auth_password(self, username, password):
        return (paramiko.AUTH_SUCCESSFUL if (username, password) == (USERNAME, PASSWORD)
                else paramiko.AUTH_FAILED)
    def check_channel_request(self, kind, chanid):
        if kind != "session":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.requests[chanid] = [threading.Event(), None]
        return paramiko.OPEN_SUCCEEDED
    def check_channel_exec_request(self, channel, command):
        try:
            command = command.decode("ascii")
        except UnicodeError:
            return False
        if command not in (PYTHON_PROBE, OS_PROBE, "python3 -", LEGACY_COMMAND):
            return False
        event, _ = self.requests[channel.get_id()]
        self.requests[channel.get_id()][1] = command
        # Let Paramiko send CHANNEL_SUCCESS after this callback returns, before
        # the worker can send EOF/exit-status (especially in fault modes).
        timer = threading.Timer(0.02, event.set)
        timer.daemon = True
        timer.start()
        return True
    # ServerInterface defaults deny PTY, shell, SFTP, agent/X11 and forwarding.

def inspect_payload(payload):
    if payload not in (PAYLOAD, PAYLOAD + b"\n"):
        raise ValueError("inspection payload is not the exact trusted fixture input")
    with tempfile.TemporaryDirectory(prefix="rp-ssh-inspection-") as directory:
        root = Path(directory)
        before = inventory(root)
        env = dict(os.environ, RP_INSPECT_ROOT=directory, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-"], input=payload, cwd=directory,
                                env=env, capture_output=True, timeout=10)
        if inventory(root) != before:
            raise ValueError("inspection mutated the temporary fixture inventory")
        # Child stderr remains private; never expose it through fixture diagnostics.
        if result.returncode:
            raise ValueError("trusted inspection subprocess failed")
        print("fixture inspection: actual Python completed; inventory unchanged", file=sys.stderr, flush=True)
        return result.stdout

def run_channel(channel, server, mode):
    try:
        channel.settimeout(15)
        event, _ = server.requests[channel.get_id()]
        if not event.wait(15):
            return
        command = server.requests[channel.get_id()][1]
        output, error, status = b"", b"", 0
        if command == PYTHON_PROBE:
            status = int(mode == "python_missing")
        elif command == OS_PROBE:
            output = b"Debian GNU/Linux 12|x86_64\n"
        elif mode == "truncated_input":
            channel.send_exit_status(1)
            return  # Deliberately close without accepting inspection stdin.
        else:
            payload = PAYLOAD
            if command == "python3 -":
                chunks, size = [], 0
                while True:
                    chunk = channel.recv(32768)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > LIMIT:
                        raise ValueError("inspection stdin exceeds fixture limit")
                    chunks.append(chunk)
                payload = b"".join(chunks)
            if payload not in (PAYLOAD, PAYLOAD + b"\n"):
                raise ValueError("inspection payload rejected")
            if mode == "command_failure":
                error, status = b"fixture-private-stderr-secret-marker\n", 1
            elif mode == "invalid_json":
                output = b"fixture intentionally returned invalid JSON\n"
            else:
                output = inspect_payload(payload)
        if output:
            channel.sendall(output)
        if error:
            channel.sendall_stderr(error)
        channel.send_exit_status(status)
        channel.shutdown_write()
    except (OSError, EOFError, ValueError, subprocess.TimeoutExpired) as error:
        print("fixture channel failed: " + type(error).__name__, file=sys.stderr, flush=True)
        try:
            channel.send_exit_status(1)
        except (OSError, EOFError):
            pass
    finally:
        channel.close()

def connection(sock, key, mode):
    transport = paramiko.Transport(sock, default_window_size=32768)
    try:
        transport.banner_timeout = transport.auth_timeout = 15
        transport.add_server_key(key)
        server = Server()
        transport.start_server(server=server)
        deadline = time.monotonic() + 45
        while transport.is_active() and time.monotonic() < deadline:
            channel = transport.accept(1)
            if channel is not None:
                threading.Thread(target=run_channel, args=(channel, server, mode), daemon=True).start()
    except (OSError, EOFError, paramiko.SSHException) as error:
        print("fixture connection ended: " + type(error).__name__, file=sys.stderr, flush=True)
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", default="clean",
                        choices=("clean", "python_missing", "command_failure", "invalid_json", "truncated_input"))
    mode = parser.parse_args().mode
    key = paramiko.RSAKey.generate(2048)  # Host key remains memory-only.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        print(json.dumps(dict(port=listener.getsockname()[1], username=USERNAME, password=PASSWORD)), flush=True)
        while True:
            sock, _ = listener.accept()
            sock.settimeout(15)
            threading.Thread(target=connection, args=(sock, key, mode), daemon=True).start()


if __name__ == "__main__":
    main()
