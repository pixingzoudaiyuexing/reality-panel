"""Failure-boundary tests for the shipped host runner; no remote mutation."""
import hashlib, io, json, pathlib, tarfile, tempfile, types, unittest
from unittest.mock import patch
SCRIPT = pathlib.Path(__file__).with_name('legacy-node-upgrade-v1.3.0-one-time-single.sh')
module = types.ModuleType('legacy_upgrade_runner')
exec(compile(SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0], str(SCRIPT), 'exec'), module.__dict__)

class Host:
    def __init__(self, fault=None): self.events=[];self.fault=fault
    def precheck(self, identity):
        self.events.append('precheck')
        if self.fault=='old-checksum': raise module.Failure('OFFICIAL_V130_BINARY_REQUIRED')
    def run(self,args): return None
    def old_auth(self, identity): return {'Authorization':'in-memory-test'}
    def capture(self, work): self.events.append('snapshot')
    def stop_and_detach(self, work): self.events.append('stop')
    def install(self, work):
        self.events.append('install')
        if self.fault=='bootstrap': raise module.Failure('HOST_COMMAND_FAILED_BASH')
    def rollback(self, work): self.events.append('host-rollback')
    def complete(self, op, work): self.events.append('complete')

class Client:
    def __init__(self, fault=None): self.fault=fault;self.events=[];self.state='PREPARED';self.finalizes=0
    def request(self, method, route, **kw):
        if route.endswith('/capabilities'): return {'operation_protocol':1,'official_amd64_sha256':module.OFFICIAL_SHA256}
        if self.fault=='old-auth': raise module.ApiFailure('HTTP_401')
        return {}
    def start(self, identity, probes):
        self.events.append('start')
        if self.fault=='second-node': raise module.ApiFailure('MIGRATION_IN_PROGRESS')
        return {'operation':{'id':'one','new':{'node_id':'new'},'old':{'node_id':'old'}},'migration_token':'test-only'}
    def bundle(self, op):
        if self.fault=='download': raise module.ApiFailure('PANEL_UNAVAILABLE')
        files={'config.env':b'PUBLIC=1','relay-node-bootstrap.sh':b'#!/bin/bash\n','relay-node-linux-amd64':b'candidate'}
        manifest={'ARCHITECTURE':'amd64','ENROLLMENT_ID':'new'}
        for name,key in [('config.env','BOOTSTRAP_CONFIG_SHA256'),('relay-node-bootstrap.sh','BOOTSTRAP_SCRIPT_SHA256'),('relay-node-linux-amd64','ARTIFACT_SHA256')]:
            manifest[key]=hashlib.sha256(files[name]).hexdigest()
        if self.fault=='checksum': manifest['ARTIFACT_SHA256']='0'*64
        files['manifest.env']='\n'.join(k+'='+v for k,v in manifest.items()).encode()
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w') as tar:
            for name,value in files.items():
                info=tarfile.TarInfo(name);info.size=len(value);tar.addfile(info,io.BytesIO(value))
        return out.getvalue()
    def action(self, op, action):
        self.events.append(action)
        if action=='restore':
            faults={'never-online':'NODE_OFFLINE','membership':'MEMBERSHIP_RESTORE_FAILED','ip':'PUBLIC_IP_MISMATCH','auth':'NEW_CREDENTIAL_NOT_ACTIVE'}
            if self.fault in faults: raise module.ApiFailure(faults[self.fault])
            self.state='RESTORED'
        elif action=='finalize':
            self.finalizes+=1
            faults={'config':'EFFECTIVE_CONFIG_NOT_CONVERGED','listener':'LISTENERS_NOT_READY','forwarding':'FORWARDING_MARKER_MISMATCH','tx':'FINALIZE_TRANSACTION_FAILED','callback':'PANEL_UNAVAILABLE'}
            if self.fault in faults: raise module.ApiFailure(faults[self.fault])
            if self.fault=='lost-finalize-ack' and self.finalizes==1:
                self.state='COMMITTED';raise module.ApiFailure('PANEL_UNAVAILABLE')
            self.state='SUCCESS'
        elif action=='rollback': self.state='ROLLED_BACK'
        return {'state':self.state}
    def status(self, op):
        if self.fault=='callback': raise module.ApiFailure('PANEL_UNAVAILABLE')
        return {'state':self.state}

class Boundaries(unittest.TestCase):
    def run_case(self,fault=None):
        host=Host(fault);client=Client(fault)
        with tempfile.TemporaryDirectory() as root:
            runner=module.Runner(client,host,{'node_id':'old'},[],pathlib.Path(root),timeout=1 if fault=="lost-finalize-ack" else 0)
            with patch.object(module,'emit'),patch.object(module.time,'sleep'):
                try: runner.execute()
                except module.Failure: runner.recover_failure()
        return host,client
    def test_success_stops_here_and_never_starts_a_second_node(self):
        host,client=self.run_case()
        self.assertEqual(host.events,['precheck','snapshot','stop','install','complete'])
        self.assertEqual(client.events,['start','preflight','restore','finalize'])
    def test_every_pre_stop_failure_keeps_old_runtime(self):
        for fault in ['old-checksum','old-auth','download','checksum','second-node']:
            with self.subTest(fault=fault):
                host,client=self.run_case(fault)
                self.assertNotIn('stop',host.events);self.assertNotIn('host-rollback',host.events)
    def test_each_precommit_fault_restores_old_before_staged_cleanup(self):
        for fault in ['bootstrap','never-online','auth','membership','ip','config','listener','forwarding','tx']:
            with self.subTest(fault=fault):
                host,client=self.run_case(fault)
                self.assertIn('host-rollback',host.events);self.assertEqual(client.state,'ROLLED_BACK')
                self.assertNotIn('complete',host.events)
    def test_unknown_finalize_never_restores_old_identity(self):
        host,client=self.run_case('callback')
        self.assertNotIn('host-rollback',host.events);self.assertNotIn('rollback',client.events)
    def test_committed_ack_loss_finishes_readback_without_old_rollback(self):
        host,client=self.run_case('lost-finalize-ack')
        self.assertNotIn('host-rollback',host.events);self.assertIn('complete',host.events)
        self.assertEqual(client.finalizes,2)
    def test_detach_preserves_tls_assets_without_old_identity_or_auth(self):
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as tmp:
            root=pathlib.Path(tmp);work=root/'var/lib/relay-panel/legacy-v130-upgrade/test'
            work.mkdir(parents=True,mode=0o700)
            opt=root/'opt/relay-node';cert=opt/'certificates/generations/valid';cert.mkdir(parents=True)
            (cert/'fullchain.pem').write_text('test certificate')
            (cert/'privkey.pem').write_text('test private key');(cert/'privkey.pem').chmod(0o600)
            (opt/'node-id').write_text('old');(opt/'relay-node').write_text('old binary');(opt/'config-cache.json').write_text('old config')
            env=root/'etc/relay-node';env.mkdir(parents=True);(env/'relay-node.env').write_text('old credential')
            claims=root/'var/lib/relay-panel/node-claims';claims.mkdir(parents=True);(claims/'runtime-auth.json').write_text('old descriptor')
            nginx=root/'etc/nginx/conf.d';nginx.mkdir(parents=True)
            conf=nginx/'relay-panel-fallback.conf';conf.write_text('ssl_certificate /opt/relay-node/certificates/generations/valid/fullchain.pem;')
            manifest=root/'etc/relay-panel/camouflage-sites.json';manifest.parent.mkdir(parents=True);manifest.write_text('old sites')
            stream=root/'etc/nginx/relay-panel-stream.d';stream.mkdir();(stream/'managed.conf').write_text('old listeners')
            acme=nginx/'relay-panel-acme.conf';acme.write_text('old acme')
            host=module.Host(root)
            with patch.object(host,'run',return_value=types.SimpleNamespace(stdout=b'test\n')):
                host.capture(work)
                host.stop_and_detach(work)
                self.assertEqual((cert/'fullchain.pem').read_text(),'test certificate')
                self.assertEqual((cert/'privkey.pem').stat().st_mode&0o777,0o600)
                self.assertFalse((opt/'node-id').exists());self.assertFalse((opt/'relay-node').exists());self.assertFalse((opt/'config-cache.json').exists())
                self.assertFalse(env.exists());self.assertFalse(claims.exists())
                self.assertFalse(conf.exists(), 'stale SNI wrapper must not reject Bootstrap fallback')
                self.assertFalse(manifest.exists());self.assertFalse(stream.exists());self.assertFalse(acme.exists())
                host.rollback(work)
                self.assertIn('/opt/relay-node/certificates/',conf.read_text())
                self.assertEqual(manifest.read_text(),'old sites');self.assertEqual((stream/'managed.conf').read_text(),'old listeners');self.assertEqual(acme.read_text(),'old acme')
                self.assertEqual((opt/'node-id').read_text(),'old')
                self.assertEqual((env/'relay-node.env').read_text(),'old credential')
                self.assertEqual((claims/'runtime-auth.json').read_text(),'old descriptor')
                self.assertEqual((cert/'privkey.pem').read_text(),'test private key')
    def test_symlink_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);(root/'link').symlink_to(root,target_is_directory=True)
            with self.assertRaises(module.Failure):module.safe_path(root/'link'/'owned')
    def test_private_snapshot_mode_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'private.json';module.private_json(p,{'phase':'TEST'})
            self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertEqual(json.loads(p.read_text()),{'phase':'TEST'})

if __name__=='__main__':unittest.main()
