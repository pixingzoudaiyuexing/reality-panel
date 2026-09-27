#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).with_name("relay-node-pool-migrate.py")
spec = importlib.util.spec_from_file_location("node_pool_migrate", path)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)


class MigrationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"home_group_id": 7, "node_id": "NODE_A"}
        self.state = {"credential_id": "credential-a", "delivery_nonce": "nonce-a"}

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


if __name__ == "__main__":
    unittest.main()
