#!/usr/bin/env python3
"""Execute the shipped filesystem cleanup; mock only process/service boundaries."""
import importlib.util
from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('retry', Path(__file__).with_name('relay-node-failed-install-cleanup.py'))
retry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retry)
NODE = '11111111-1111-4111-8111-111111111111'
OTHER = '22222222-2222-4222-8222-222222222222'
UNIT = '[Unit]\nDescription=Reality Panel relay-node\n[Service]\nEnvironmentFile=/etc/relay-node/relay-node.env\nWorkingDirectory=/opt/relay-node\nExecStart=/opt/relay-node/relay-node\n'

class RetryCleanup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def file(self, name, body):
        p = self.root / name.lstrip('/')
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body); p.chmod(0o600)
        return p
    def residue(self, node=NODE):
        self.file('/opt/relay-node/node-id', node)
        self.file('/opt/relay-node/relay-node', '# never executed: incompatible ELF fixture')
        self.file('/etc/relay-node/relay-node.env', 'PANEL_URL=https://panel.test\nNGINX_SNI_CONF_PATH=/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf\n')
        self.file(retry.UNIT, UNIT)
        self.file(retry.CLAIMS + '/' + node + '/credential-pending.json', '{ broken credential JSON')
        self.file(retry.CLAIMS + '/runtime-auth.json', '{ incomplete auth')
    def clean(self):
        p = retry.plan(self.root)
        retry.cleanup(self.root, 'check', p['snapshot'])
        retry.cleanup(self.root, 'stop', p['snapshot'])
        retry.cleanup(self.root, 'clean', p['snapshot'])
    def test_clean_host_has_no_retry_residue(self):
        self.assertFalse(retry.plan(self.root)['residue'])
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
    def test_unreadable_version_and_incomplete_credentials_clean_without_binary(self):
        self.residue()
        with patch.object(retry.subprocess, 'run', side_effect=AssertionError('no Node executed')):
            self.clean()
        self.assertFalse((self.root/'opt/relay-node/node-id').exists())
        self.assertFalse((self.root/'etc/relay-node/relay-node.env').exists())
        self.assertFalse((self.root/'var/lib/relay-panel/node-claims'/NODE).exists())
    def test_unknown_program_files_other_claim_and_shared_resources_survive(self):
        self.residue()
        protected = [self.file('/opt/relay-node/operator-backup', 'keep'), self.file('/etc/nginx/nginx.conf', 'unrelated server'), self.file('/var/lib/relay-panel/xiaoya-byoa/data', 'keep'), self.file(retry.CLAIMS+'/'+OTHER+'/credential-pending.json', json.dumps({'node_id':OTHER,'phase':'PREPARED'}))]
        self.clean()
        self.assertTrue(all(p.exists() for p in protected))
    def test_symlink_target_parent_and_hardlink_are_never_removed(self):
        for name in ['/opt/relay-node/node-id', '/etc/relay-node/relay-node.env']:
            with self.subTest(name=name):
                self.residue();p=self.root/name.lstrip('/');p.unlink();p.symlink_to(self.root/'outside')
                self.assertIsNone(retry.inspection(self.root)['retry_snapshot']);p.unlink()
        self.residue();p=self.root/'opt/relay-node/node-id';outside=self.file('/outside',NODE);p.unlink();os.link(outside,p)
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot']);self.assertEqual(outside.read_text(),NODE)
    def test_nonproduct_service_and_overrides_fail_before_deletion(self):
        self.residue();self.file(retry.UNIT, UNIT+'ExecStart=/usr/bin/other-program\n')
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
        self.file(retry.UNIT, UNIT);self.file(retry.UNIT+'.d/custom.conf','ExecStart=/usr/bin/other-program')
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot']);self.assertTrue((self.root/'opt/relay-node/node-id').exists())
    def test_indented_execstop_duplicate_start_and_continuation_are_protected(self):
        self.residue()
        for extra in ['  ExecStop = /usr/bin/operator-stop-shared-resource\n', '  ExecStart = /opt/relay-node/relay-node\n', 'ExecStart=/opt/relay-node/\\\nrelay-node\n', 'RootDirectory=/other-program\n']:
            with self.subTest(extra=extra):
                self.file(retry.UNIT,UNIT+extra)
                self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
                self.assertTrue((self.root/'opt/relay-node/node-id').exists())
    def test_parent_symlink_and_custom_working_directory_are_protected(self):
        self.residue();self.file(retry.UNIT, UNIT.replace('WorkingDirectory=/opt/relay-node', 'WorkingDirectory=/other-program'))
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
        self.file(retry.UNIT, UNIT)
        target = self.root/'opt/relay-node'; target.rename(self.root/'owned-backup'); target.symlink_to(self.root/'owned-backup')
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
        self.assertTrue((self.root/'owned-backup/node-id').exists())
    def test_effective_systemd_dropins_and_foreign_loaded_fragment_block_stop(self):
        for fragment,dropins in [(retry.UNIT,'/run/systemd/system/relay-node.service.d/override.conf'), (retry.UNIT,'/usr/lib/systemd/system/relay-node.service.d/override.conf'), ('/other-program.service','')]:
            with self.subTest(fragment=fragment,dropins=dropins),patch.object(retry.subprocess,'check_output',side_effect=[fragment,dropins]),patch.object(retry.subprocess,'run') as stop:
                with self.assertRaises(ValueError):retry.validate_loaded_service(True)
                stop.assert_not_called()
        with patch.object(retry.subprocess,'check_output',side_effect=[retry.UNIT,'']):retry.validate_loaded_service(True)
    def test_interrupted_unit_removal_refreshes_cache_without_stopping_unknown_service(self):
        with patch.object(retry.subprocess,'check_output',side_effect=[retry.UNIT,'','','']),patch.object(retry.subprocess,'run') as command:
            retry.validate_loaded_service(False)
            command.assert_called_once_with(['systemctl','daemon-reload'],check=True,timeout=20)
        with patch.object(retry.subprocess,'check_output',side_effect=[retry.UNIT,'','/usr/lib/systemd/system/relay-node.service','']),patch.object(retry.subprocess,'run') as command:
            with self.assertRaises(ValueError):retry.validate_loaded_service(False)
            command.assert_called_once_with(['systemctl','daemon-reload'],check=True,timeout=20)
    def test_committed_transaction_cannot_authorize_failed_retry(self):
        self.residue();base='/tmp/relay-panel-bootstrap-'+NODE
        self.file(base+'/bootstrap.sh','#!/usr/bin/env bash\n# RelayPanel Stage 1 bootstrap.\n')
        self.file(base+'/config.env','POOL_NODE_ID='+NODE+'\n')
        self.file(base+'/transaction/state','committed\n')
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
        self.assertTrue((self.root/'opt/relay-node/node-id').exists())
    def test_other_active_identity_and_escaped_credential_path_are_protected(self):
        self.residue();other=self.file(retry.CLAIMS+'/'+OTHER+'/credential-pending.json',json.dumps({'node_id':OTHER,'phase':'ACTIVE_CONFIRMED'}))
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot']);self.assertTrue(other.exists());other.unlink()
        self.file(retry.CLAIMS+'/runtime-auth.json',json.dumps({'node_id':NODE,'secret_file':'/etc/shadow'}))
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])
    def test_snapshot_change_requires_new_confirmation(self):
        self.residue();p=retry.plan(self.root);self.file('/opt/relay-node/node-id',OTHER)
        with self.assertRaises(ValueError):retry.cleanup(self.root,'clean',p['snapshot'])
        self.assertTrue((self.root/'opt/relay-node/relay-node').exists())
    def test_interrupted_cleanup_is_repeatable_after_new_inspection(self):
        self.residue();p=retry.plan(self.root);original=Path.unlink;calls=[]
        def interruption(path,*args,**kwargs):
            calls.append(path)
            if len(calls)==3:raise OSError('simulated disconnect')
            return original(path,*args,**kwargs)
        with patch.object(Path,'unlink',interruption),self.assertRaises(OSError):retry.cleanup(self.root,'clean',p['snapshot'])
        self.clean();self.assertFalse((self.root/'opt/relay-node/node-id').exists())
    def test_stale_empty_migration_lock_allows_retry_but_live_lock_blocks(self):
        self.residue();lock=self.file(retry.CLAIMS+'/migration.lock','');self.clean();self.assertTrue(lock.exists())
        self.residue()
        import fcntl
        with lock.open('r+') as owner:
            fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(OSError):retry.cleanup(self.root,'clean',retry.plan(self.root)['snapshot'])
        self.assertTrue((self.root/'opt/relay-node/node-id').exists())
    def test_disconnect_at_each_deletion_can_retry_without_losing_ownership_evidence(self):
        self.residue();count=len(retry.plan(self.root)['paths'])
        for stop in range(1,count+1):
            with self.subTest(stop=stop):
                self.residue();p=retry.plan(self.root);original=Path.unlink;calls=[]
                def interruption(path,*args,**kwargs):
                    calls.append(path)
                    if len(calls)==stop:raise OSError('disconnect')
                    return original(path,*args,**kwargs)
                with patch.object(Path,'unlink',interruption),self.assertRaises(OSError):retry.cleanup(self.root,'clean',p['snapshot'])
                self.assertIsNotNone(retry.inspection(self.root)['retry_snapshot'])
                self.clean()
                self.assertFalse((self.root/'opt/relay-node/relay-node').exists())
    def test_only_owned_pending_bootstrap_transaction_is_removed(self):
        self.residue();base='/tmp/relay-panel-bootstrap-'+NODE
        self.file(base+'/bootstrap.sh','#!/usr/bin/env bash\n# RelayPanel Stage 1 bootstrap.\n')
        self.file(base+'/config.env','POOL_NODE_ID='+NODE+'\nPOOL_GROUP_ID=6\n')
        self.file(base+'/transaction/state','pending\n')
        other=self.file('/tmp/relay-panel-bootstrap-'+OTHER+'/operator-data','keep')
        self.assertEqual(retry.plan(self.root)['failed_ids'],[NODE]);self.clean();self.assertTrue(other.exists())
    def test_unknown_transaction_file_and_claim_identity_conflict_are_protected(self):
        self.residue();base='/tmp/relay-panel-bootstrap-'+NODE
        self.file(base+'/bootstrap.sh','#!/usr/bin/env bash\n# RelayPanel Stage 1 bootstrap.\n');self.file(base+'/config.env','POOL_NODE_ID='+NODE+'\n');p=self.file(base+'/operator-data','keep')
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot']);self.assertTrue(p.exists());p.unlink()
        self.file(retry.CLAIMS+'/'+NODE+'/credential-pending.json',json.dumps({'node_id':OTHER,'phase':'PREPARED'}))
        self.assertIsNone(retry.inspection(self.root)['retry_snapshot'])

if __name__ == '__main__':unittest.main()
