#!/usr/bin/env python3
"""Exercise the shipped rollback cleanup program, mocking only its HTTP peer."""
import contextlib, io, json, os, pathlib, tempfile, unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name('relay-node-bootstrap.sh')
PROGRAM = SCRIPT.read_text().split("<<'POOL_CLEANUP_PY'\n", 1)[1].split('\nPOOL_CLEANUP_PY', 1)[0]
NODE = '11111111-1111-4111-8111-111111111111'

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.transaction = self.root/'transaction'
        self.transaction.mkdir()
        self.identity = self.root/'opt/relay-node/node-id'
        self.claim = self.root/'var/lib/relay-panel/node-claims'/NODE
        self.descriptor = self.claim.parent/'runtime-auth.json'
        self.calls = []
        for key in ['pool_node_id.state', 'pool_runtime_auth.state', 'pool_claim.dir-state']:
            (self.transaction/key).write_text('absent\n')
        self.result = dict(outcome='CANCELLED', claim_id=NODE, home_group_id=6, node_id=NODE, state='CANCELLED')
    def candidate(self, phase):
        self.identity.parent.mkdir(parents=True, exist_ok=True)
        self.identity.write_text(NODE)
        self.claim.mkdir(parents=True, exist_ok=True)
        if phase >= 1: (self.claim/'credential-pending.json').write_text('{"phase":"ACTIVATE_READY"}')
        if phase >= 2:
            (self.claim/'pool-claimant-nonce').write_text('nonce-fixture')
            (self.claim/'node-credential.secret').write_text('credential-fixture')
        if phase >= 3:
            self.descriptor.write_text(json.dumps(dict(identity_group_id=6, node_id=NODE,
                secret_file='/var/lib/relay-panel/node-claims/'+NODE+'/node-credential.secret')))
    def run_cleanup(self, error=None):
        response = io.BytesIO(json.dumps(dict(code=0, data=self.result)).encode())
        def open_request(req, timeout):
            self.calls.append(req)
            if error: raise error
            return response
        opener = type('Opener', (), dict(open=staticmethod(open_request)))()
        out = io.StringIO()
        with patch.dict(os.environ, dict(POOL_NODE_ID=NODE, POOL_GROUP_ID='6',
                POOL_CLAIM_SECRET='claim-fixture', NODE_TOKEN='token-fixture', PANEL_URL='https://panel.example')), \
                patch('sys.argv', ['cleanup', str(self.transaction), str(self.root)]), \
                patch('urllib.request.build_opener', return_value=opener), contextlib.redirect_stderr(out):
            try:
                exec(compile(PROGRAM, str(SCRIPT), 'exec'), {'__name__':'cleanup_fixture'})
                code = 0
            except SystemExit as exc: code = exc.code
        return code, out.getvalue()
    def test_every_unactivated_failure_boundary_cleans_only_current_candidate(self):
        for phase in range(4):
            with self.subTest(phase=phase):
                self.candidate(phase)
                code, output = self.run_cleanup()
                self.assertEqual(code, 0, output)
                self.assertFalse(self.identity.exists())
                self.assertFalse(self.claim.exists())
                self.assertFalse(self.descriptor.exists())
                req = self.calls[-1]
                self.assertEqual(req.full_url, 'https://panel.example/api/v1/node-credential-claims/'+NODE+'/bootstrap/cancel')
                self.assertEqual(json.loads(req.data)['node_id'], NODE)
    def test_active_or_lost_activation_ack_preserves_all_identity_material(self):
        self.candidate(3)
        self.result.update(outcome='ACTIVE_PRESERVED', state='COMPLETED')
        code, output = self.run_cleanup()
        self.assertEqual(code, 20, output)
        self.assertTrue(self.identity.exists())
        self.assertTrue(self.descriptor.exists())
        self.assertTrue((self.claim/'node-credential.secret').exists())
    def test_unavailable_panel_never_authorizes_local_cleanup_or_leaks_exception(self):
        self.candidate(2)
        code, output = self.run_cleanup(TimeoutError('token-fixture claim-fixture credential-fixture'))
        self.assertEqual(code, 1)
        self.assertTrue(self.identity.exists())
        for secret in ['token-fixture', 'claim-fixture', 'credential-fixture']:
            self.assertNotIn(secret, output)
    def test_preexisting_identity_and_claim_directory_are_preserved(self):
        self.candidate(2)
        (self.transaction/'pool_node_id.state').write_text('present\n')
        (self.transaction/'pool_claim.dir-state').write_text('present\n')
        code, output = self.run_cleanup()
        self.assertEqual(code, 0, output)
        self.assertTrue(self.identity.exists())
        self.assertTrue(self.claim.exists())
    def test_other_identity_and_unexpected_files_are_not_removed(self):
        self.candidate(2)
        self.identity.write_text('different-existing-node')
        code, _ = self.run_cleanup()
        self.assertEqual(code, 1)
        self.assertTrue(self.claim.exists())
        self.identity.write_text(NODE)
        (self.claim/'operator-data').write_text('keep')
        code, _ = self.run_cleanup()
        self.assertEqual(code, 1)
        self.assertTrue(self.identity.exists())
    def test_incorrect_server_identity_and_parent_symlink_fail_closed(self):
        self.candidate(2)
        self.result['node_id']='other-node'
        code, _ = self.run_cleanup()
        self.assertEqual(code, 1)
        self.assertTrue(self.identity.exists())
        self.result['node_id']=NODE
        parent=self.claim.parent
        moved=parent.with_name('moved-claims')
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        code, _ = self.run_cleanup()
        self.assertEqual(code, 1)
        self.assertTrue((moved/NODE/'node-credential.secret').exists())

if __name__ == '__main__': unittest.main()
