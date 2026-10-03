#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

path = pathlib.Path(__file__).with_name("relay-node-pool-migrate.py")
spec = importlib.util.spec_from_file_location("node_pool_migrate", path)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)
state_path = pathlib.Path(__file__).with_name("relay-node-credential-state.py")
state_spec = importlib.util.spec_from_file_location("node_pool_credential_state", state_path)
credential_state = importlib.util.module_from_spec(state_spec)
state_spec.loader.exec_module(credential_state)


class MigrationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"home_group_id": 7, "node_id": "NODE_A"}
        self.state = {"credential_id": "credential-a", "delivery_nonce": "nonce-a"}

    def test_bootstrap_exception_reports_fresh_stage_without_migration_or_secret(self):
        import subprocess
        result = subprocess.run(["python3", str(path), "--bootstrap", "--claim-id", "invalid",
            "--identity-group-id", "7", "--node-id", "NODE_A"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node credential bootstrap failed", result.stderr)
        self.assertIn("stage=", result.stderr)
        self.assertNotIn("安全迁移", result.stderr)

    def test_bootstrap_http_error_has_safe_business_details_and_no_secrets(self):
        import io
        import urllib.error
        migrate.ERROR_CONTEXT.update(stage="prepare", endpoint="/api/v1/node-credential-claims/claim-a/credential/prepare")
        migrate.ERROR_SECRETS[:] = ["group-token-fixture", "claim-secret-fixture", "nonce-fixture"]
        exc = urllib.error.HTTPError("https://unused", 409, "group-token-fixture", {},
            io.BytesIO(json.dumps({"code":409,"message":"claim-secret-fixture nonce-fixture prepare rejected"}).encode()))
        message = migrate.bootstrap_error(exc)
        self.assertIn("stage=prepare", message)
        self.assertIn("HTTP=409", message)
        self.assertIn("code=409", message)
        self.assertIn("prepare rejected", message)
        for secret in migrate.ERROR_SECRETS:
            self.assertNotIn(secret, message)

    def test_successful_activation(self):
        calls = []
        def request(*args):
            calls.append(args)
            return {"code": 0}
        migrate.activate_or_verify(request, "activate", self.identity, self.state, "secret")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "activate")

    def test_lost_activation_ack_recovers_only_after_exact_identity_proof(self):
        def request(endpoint, *_):
            if endpoint == "activate":
                raise RuntimeError("ACK lost")
            return {"identity_group_id": 7, "node_id": "NODE_A"}
        migrate.activate_or_verify(request, "activate", self.identity, self.state, "secret")

    def test_failed_activation_does_not_promote_wrong_or_missing_identity(self):
        for identity in ({"identity_group_id": 8, "node_id": "NODE_A"}, None):
            def request(endpoint, *_):
                if endpoint == "activate":
                    raise RuntimeError("activation failed")
                return identity
            with self.assertRaisesRegex(RuntimeError, "activation failed"):
                migrate.activate_or_verify(request, "activate", self.identity, self.state, "secret")

    def test_failed_descriptor_write_never_reports_completion(self):
        calls = []
        def fail_write(*_):
            raise OSError("disk unavailable")
        def request(*args):
            calls.append(args)
        with self.assertRaisesRegex(OSError, "disk unavailable"):
            migrate.commit_migration_descriptor(fail_write, "descriptor", {}, request,
                "claim-a", "secret", "credential-a")
        self.assertEqual(calls, [])

    def test_lost_completion_ack_retries_same_credential_after_durable_write(self):
        writes = []
        calls = []
        def write(path, data):
            writes.append((path, data))
        def request(*args):
            calls.append(args)
            if len(calls) == 1:
                raise TimeoutError("completion ACK lost")
        for attempt in range(2):
            if attempt == 0:
                with self.assertRaisesRegex(TimeoutError, "ACK lost"):
                    migrate.commit_migration_descriptor(write, "descriptor", {"node_id": "NODE_A"},
                        request, "claim-a", "secret", "credential-a")
            else:
                migrate.commit_migration_descriptor(write, "descriptor", {"node_id": "NODE_A"},
                    request, "claim-a", "secret", "credential-a")
        self.assertEqual(len(writes), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(calls[0][0], "node-pool/migrations/claim-a/complete")

    def test_completion_observes_atomically_durable_private_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime-auth.json"
            descriptor = {"identity_group_id": 7, "node_id": "NODE_A", "credential_id": "credential-a"}
            calls = []
            def request(*args):
                self.assertEqual(json.loads(path.read_text()), descriptor)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                calls.append(args)
            migrate.commit_migration_descriptor(credential_state.atomic_write, str(path),
                descriptor, request, "claim-a", "secret", "credential-a")
            self.assertEqual(len(calls), 1)

    def test_pool_bootstrap_persists_auth_without_legacy_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime-auth.json"
            descriptor = {"identity_group_id": 7, "node_id": "POOL_NEW"}
            calls = []
            migrate.commit_migration_descriptor(credential_state.atomic_write, str(path),
                descriptor, lambda *args: calls.append(args), "claim-a", "secret", "credential-a", bootstrap=True)
            self.assertEqual(json.loads(path.read_text()), descriptor)
            self.assertEqual(calls, [])

    def test_atomic_replace_failure_preserves_old_auth_environment_and_lkg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            descriptor = root / "runtime-auth.json"
            environment = root / "relay-node.env"
            lkg = root / "config-cache.json"
            credential_state.atomic_write(str(descriptor), b'{"credential_id":"previous"}')
            credential_state.atomic_write(str(environment), b'NODE_TOKEN=legacy-test-token\n')
            credential_state.atomic_write(str(lkg), b'{"listeners":[{"rule_id":7}]}')
            before = {path: path.read_bytes() for path in (descriptor, environment, lkg)}
            calls = []
            with mock.patch.object(credential_state.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    migrate.commit_migration_descriptor(credential_state.atomic_write, str(descriptor),
                        {"credential_id": "new"}, lambda *args: calls.append(args),
                        "claim-a", "secret", "credential-a")
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
