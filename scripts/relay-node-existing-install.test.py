#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('inspection', Path(__file__).with_name('relay-node-existing-install.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NODE = '11111111-1111-4111-8111-111111111111'
OTHER = '22222222-2222-4222-8222-222222222222'


class Inspection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        module.ROOT = Path(self.temp.name)

    def file(self, name, value, mode=0o600):
        p = module.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)
        p.chmod(mode)
        return p

    def installed(self):
        self.file('/opt/relay-node/node-id', NODE)
        self.file('/etc/relay-node/relay-node.env', 'PANEL_URL=https://panel.test\nNODE_TOKEN=must-never-leak\n')
        self.file('/etc/systemd/system/relay-node.service', '[Service]\nExecStart=/opt/relay-node/relay-node\n')

    def auth(self, node=NODE, phase='ACTIVE_CONFIRMED'):
        secret = 'rpn1_' + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        name = f'/var/lib/relay-panel/node-claims/{NODE}/node-credential.secret'
        self.file(name, secret)
        self.file(f'/var/lib/relay-panel/node-claims/{NODE}/credential-pending.json', json.dumps(dict(node_id=node, home_group_id=2, credential_id=NODE, phase=phase)))
        self.file('/var/lib/relay-panel/node-claims/runtime-auth.json', json.dumps(dict(node_id=node, identity_group_id=2, credential_id=NODE, secret_file=name)))
        return secret

    def test_clean_host(self):
        self.assertIsNone(module.inspect()['node_id'])

    def test_installed_exact_auth_is_verified_without_exporting_secret(self):
        self.installed(); secret = self.auth()
        facts = module.inspect()
        self.assertIsNone(facts['ambiguity'])
        self.assertTrue(facts['runtime_valid'])
        self.assertNotIn(secret, json.dumps(facts))
        self.assertNotIn('must-never-leak', json.dumps(facts))
        c = NODE.encode()
        expected = hashlib.sha256(b'relay-panel/node-credential/v1\0' + len(c).to_bytes(8, 'big') + c + (2).to_bytes(8, 'big', signed=True) + len(c).to_bytes(8, 'big') + c + bytes(range(32))).hexdigest()
        self.assertEqual(facts['credential_verifier'], expected)

    def test_auth_identity_conflict_blocks_and_changes_nothing(self):
        self.installed(); self.auth(OTHER)
        before = {str(p): p.read_bytes() for p in module.ROOT.rglob('*') if p.is_file()}
        self.assertIsNotNone(module.inspect()['ambiguity'])
        self.assertEqual(before, {str(p): p.read_bytes() for p in module.ROOT.rglob('*') if p.is_file()})

    def test_symlinked_identity_blocks(self):
        self.installed()
        p = module.path('/opt/relay-node/node-id'); p.unlink(); p.symlink_to('/etc/passwd')
        self.assertIsNotNone(module.inspect()['ambiguity'])

    def test_public_secret_file_blocks(self):
        self.installed(); self.auth()
        module.path(f'/var/lib/relay-panel/node-claims/{NODE}/node-credential.secret').chmod(0o644)
        self.assertIsNotNone(module.inspect()['ambiguity'])

    def test_inactive_state_is_not_claimed_as_valid_runtime(self):
        self.installed(); self.auth(phase='PREPARED')
        self.assertFalse(module.inspect()['runtime_valid'])

    def test_service_without_identity_blocks(self):
        self.installed(); module.path('/opt/relay-node/node-id').unlink()
        self.assertIsNotNone(module.inspect()['ambiguity'])

    def test_other_active_claim_blocks(self):
        self.installed(); self.auth()
        self.file(f'/var/lib/relay-panel/node-claims/{OTHER}/credential-pending.json', json.dumps(dict(node_id=OTHER, phase='ACTIVE_CONFIRMED')))
        self.assertIsNotNone(module.inspect()['ambiguity'])


if __name__ == '__main__':
    unittest.main()
