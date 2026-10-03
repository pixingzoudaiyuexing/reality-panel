"""Failure-boundary tests for the shipped host runner; no remote mutation."""
import hashlib, io, json, pathlib, tarfile, tempfile, types, unittest
from unittest.mock import patch
SCRIPT = pathlib.Path(__file__).with_name('reality-node-v1.3.0-to-v1.4.3.sh')
module = types.ModuleType('legacy_upgrade_runner')
exec(compile(SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0], str(SCRIPT), 'exec'), module.__dict__)

class Host:
    def __init__(self, fault=None): self.events=[];self.fault=fault;self.profile='lite'
    def precheck(self, identity):
        self.events.append('precheck')
        if self.fault=='old-checksum': raise module.Failure('OFFICIAL_V130_BINARY_REQUIRED')
        return self.profile
    def run(self,args): return types.SimpleNamespace(stdout=('relay-node '+module.TARGET_VERSION+'\n').encode())
    def old_auth(self, identity): return {'Authorization':'in-memory-test'}
    def capture(self, work): self.events.append('snapshot')
    def stop_and_detach(self, work):
        self.events.append('stop')
        if self.fault=='nginx-detach':raise module.Failure('HOST_COMMAND_FAILED_NGINX')
    def install(self, work):
        self.events.append('install')
        if self.fault=='bootstrap': raise module.Failure('HOST_COMMAND_FAILED_BASH')
    def rollback(self, work): self.events.append('host-rollback')
    def profile_postcheck(self, profile, work):
        if profile!=self.profile: raise module.Failure('INSTALL_PROFILE_CHANGED')
    def complete(self, op, work): self.events.append('complete')

class Client:
    def __init__(self, fault=None): self.fault=fault;self.events=[];self.profile='lite';self.state='PREPARED';self.finalizes=0
    def request(self, method, route, **kw):
        if route.endswith('/capabilities'): return {'operation_protocol':1,'official_amd64_sha256':module.OFFICIAL_SHA256}
        if self.fault=='old-auth': raise module.ApiFailure('HTTP_401')
        return {}
    def start(self, identity, probes, profile):
        self.events.append('start')
        if self.fault=='second-node': raise module.ApiFailure('MIGRATION_IN_PROGRESS')
        return {'operation':{'id':'one','source_profile':profile,'new':{'node_id':'new'},'old':{'node_id':'old'}},'migration_token':'test-only'}
    def bundle(self, op):
        if self.fault=='download': raise module.ApiFailure('PANEL_UNAVAILABLE')
        files={'config.env':('PUBLIC=1\nLITE_MODE='+('0' if op['operation']['source_profile']=='standard' else '1')+'\n').encode(),'relay-node-bootstrap.sh':b'#!/bin/bash\n','relay-node-linux-amd64':b'candidate'}
        manifest={'ARCHITECTURE':'amd64','ENROLLMENT_ID':'new','PROFILE':op['operation']['source_profile']}
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
    def run_case(self,fault=None,profile="lite"):
        host=Host(fault);client=Client(fault);host.profile=client.profile=profile
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as root:
            runner=module.Runner(client,host,{'node_id':'old'},[],pathlib.Path(root),timeout=1 if fault=="lost-finalize-ack" else 0)
            with patch.object(module,'emit'),patch.object(module.time,'sleep'),patch.object(module,'TARGET_SHA256',hashlib.sha256(b'candidate').hexdigest()):
                try: runner.execute()
                except module.Failure: runner.recover_failure()
        return host,client
    def test_success_stops_here_and_never_starts_a_second_node(self):
        host,client=self.run_case()
        self.assertEqual(host.events,['precheck','snapshot','stop','install','complete'])
        self.assertEqual(client.events,['start','preflight','restore','finalize'])
    def test_every_pre_stop_failure_keeps_old_runtime(self):
        for profile,fault in __import__('itertools').product(['standard','lite'],['old-checksum','old-auth','download','checksum','second-node']):
            with self.subTest(fault=fault,profile=profile):
                host,client=self.run_case(fault,profile)
                self.assertNotIn('stop',host.events);self.assertNotIn('host-rollback',host.events)
    def test_each_precommit_fault_restores_old_before_staged_cleanup(self):
        for profile,fault in __import__('itertools').product(['standard','lite'],['nginx-detach','bootstrap','never-online','auth','membership','ip','config','listener','forwarding','tx']):
            with self.subTest(fault=fault,profile=profile):
                host,client=self.run_case(fault,profile)
                self.assertIn('host-rollback',host.events);self.assertEqual(client.state,'ROLLED_BACK')
                self.assertNotIn('complete',host.events)
    def test_unknown_finalize_never_restores_old_identity(self):
        host,client=self.run_case('callback')
        self.assertNotIn('host-rollback',host.events);self.assertNotIn('rollback',client.events)
    def test_committed_ack_loss_finishes_readback_without_old_rollback(self):
        host,client=self.run_case('lost-finalize-ack')
        self.assertNotIn('host-rollback',host.events);self.assertIn('complete',host.events)
        self.assertEqual(client.finalizes,2)
    def test_standard_success_and_unknown_finalize_keep_profile(self):
        for fault in [None,'callback','lost-finalize-ack']:
            with self.subTest(fault=fault):
                host,client=self.run_case(fault,'standard')
                self.assertNotIn('host-rollback',host.events)
                self.assertEqual(host.profile,'standard')
                if fault!='callback':self.assertIn('complete',host.events)
    def test_bundle_profile_mismatch_fails_before_stop(self):
        host=Host();client=Client();original=client.start
        def mismatch(identity,probes,profile):
            result=original(identity,probes,profile);result['operation']['source_profile']='standard';return result
        client.start=mismatch
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as tmp:
            runner=module.Runner(client,host,{'node_id':'old'},[],pathlib.Path(tmp))
            with patch.object(module,'emit'),self.assertRaisesRegex(module.Failure,'SOURCE_INSTALL_PROFILE_MISMATCH'):runner.execute()
        self.assertNotIn('stop',host.events)
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
            conf=nginx/'relay-panel-fallback.conf';conf.write_text('# generated by relay-node; TLS camouflage sites\nssl_certificate /opt/relay-node/certificates/generations/valid/fullchain.pem;')
            manifest=root/'etc/relay-panel/camouflage-sites.json';manifest.parent.mkdir(parents=True);manifest.write_text('old sites')
            stream=root/'etc/nginx/relay-panel-stream.d';stream.mkdir();(stream/'relay-panel-sni.conf').write_text('# generated by relay-node; do not edit\nold listeners');(stream/'user-stream.conf').write_text('foreign config')
            acme=nginx/'relay-panel-acme.conf';acme.write_text('# generated by relay-node; global HTTP to HTTPS redirect\nold acme')
            host=module.Host(root)
            with patch.object(host,'run',return_value=types.SimpleNamespace(stdout=b'test\n')) as commands:
                with patch.object(host,'standard_fallback',return_value={'id':'unchanged'}): host.capture(work)
                host.stop_and_detach(work)
                self.assertEqual([c.args[0] for c in commands.call_args_list[-2:]],[['nginx','-t'],['systemctl','reload','nginx']], 'release stale Nginx ports before Bootstrap preflight')
                self.assertEqual((cert/'fullchain.pem').read_text(),'test certificate')
                self.assertEqual((cert/'privkey.pem').stat().st_mode&0o777,0o600)
                self.assertFalse((opt/'node-id').exists());self.assertFalse((opt/'relay-node').exists());self.assertFalse((opt/'config-cache.json').exists())
                self.assertFalse(env.exists());self.assertFalse(claims.exists())
                self.assertFalse(conf.exists(), 'stale SNI wrapper must not reject Bootstrap fallback')
                self.assertFalse(manifest.exists());self.assertFalse((stream/'relay-panel-sni.conf').exists());self.assertFalse(acme.exists());self.assertEqual((stream/'user-stream.conf').read_text(),'foreign config')
                with patch.object(host,'profile_postcheck'): host.rollback(work)
                self.assertIn('/opt/relay-node/certificates/',conf.read_text())
                self.assertEqual(manifest.read_text(),'old sites');self.assertIn('old listeners',(stream/'relay-panel-sni.conf').read_text());self.assertIn('old acme',acme.read_text());self.assertEqual((stream/'user-stream.conf').read_text(),'foreign config')
                self.assertEqual((opt/'node-id').read_text(),'old')
                self.assertEqual((env/'relay-node.env').read_text(),'old credential')
                self.assertEqual((claims/'runtime-auth.json').read_text(),'old descriptor')
                self.assertEqual((cert/'privkey.pem').read_text(),'test private key')
    def test_unmanaged_same_name_nginx_file_is_rejected_before_stop(self):
        for name in ['/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf', '/etc/nginx/conf.d/relay-panel-fallback.conf', '/etc/nginx/conf.d/relay-panel-acme.conf']:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as tmp:
                root=pathlib.Path(tmp);p=root/name.lstrip('/');p.parent.mkdir(parents=True);p.write_text('# Administrator configuration\n')
                host=module.Host(root)
                with patch.object(module.os,'geteuid',return_value=0),patch.object(module.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')),patch.object(host,'run') as run:
                    with self.assertRaisesRegex(module.Failure,'UNMANAGED_NGINX_CONFIG_REQUIRES_MANUAL_INSPECTION'):
                        host.precheck({'node_id':'old'})
                    run.assert_not_called()
                self.assertEqual(p.read_text(),'# Administrator configuration\n')
    def test_symlink_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);(root/'link').symlink_to(root,target_is_directory=True)
            with self.assertRaises(module.Failure):module.safe_path(root/'link'/'owned')
    def test_private_snapshot_mode_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'private.json';module.private_json(p,{'phase':'TEST'})
            self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertEqual(json.loads(p.read_text()),{'phase':'TEST'})

class OperatorReleaseContract(unittest.TestCase):
    class ReadClient:
        admin='fixture-admin'
        def __init__(self, fault=None): self.calls=[];self.fault=fault
        def request(self, method, route, **kwargs):
            self.calls.append((method,route));assert method=='GET'
            if route.endswith('/capabilities'):
                return {'operation_protocol':1,'official_amd64_sha256':module.OFFICIAL_SHA256,'target_version':'1.4.4' if self.fault=='future-panel' else '1.4.3','profile_preserving':True,'supported_profiles':['standard','lite']}
            if route=='/admin/node-artifacts':
                return {'config_protocol_version':10,'artifacts':[{'architecture':'amd64','available':True,'version':'1.4.4' if self.fault=='future-node' else '1.4.3','sha256':'f'*64 if self.fault=='wrong-sha' else module.TARGET_SHA256}]}
            if route.endswith('/current'):
                if self.fault=='none':raise module.ApiFailure('MIGRATION_NOT_FOUND')
                return {'operation':{'old':{'node_id':'another-node'},'state':'RESTORED' if self.fault=='active' else 'SUCCESS'}}
            if route=='/groups':return [{'id':7,'name':'legacy','group_type':'in'}]
            if route==module.BASE+'/identity':
                assert kwargs['headers']['X-Node-ID']=='old'
                assert kwargs['headers']['Authorization']=='Bearer fixture-group-token'
                return {'identity_group_id':7,'node_id':'old'}
            raise AssertionError('Unexpected non-readonly surface: '+route)
    def test_readonly_check_has_no_config_revision_or_metadata_registration(self):
        client=self.ReadClient();host=Host()
        module.readonly_panel_check(client,host,{'identity_group_id':7,'node_id':'old'})
        self.assertEqual(client.calls,[('GET',module.BASE+'/capabilities'),('GET','/admin/node-artifacts'),('GET','/admin'+module.BASE+'/current')])
        self.assertEqual(host.events,[])
    def test_check_rejects_future_target_wrong_hash_or_active_operation(self):
        for fault in ['future-panel','future-node','wrong-sha','active']:
            with self.subTest(fault=fault),self.assertRaises(module.Failure):
                module.readonly_panel_check(self.ReadClient(fault),Host(),{'node_id':'old','identity_group_id':7})
    def test_other_nodes_terminal_operation_and_no_operation_do_not_block_check(self):
        for fault in [None,'none']:
            module.readonly_panel_check(self.ReadClient(fault),Host(),{'node_id':'old','identity_group_id':7})
    def test_fixed_binary_guard_rejects_wrong_version_with_correct_hash(self):
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as root:
            binary=pathlib.Path(root)/'node';binary.write_bytes(b'fixture-v142')
            with patch.object(module,'TARGET_SHA256',hashlib.sha256(b'fixture-v142').hexdigest()):
                module.verify_target_binary(Host(),binary)
                host=Host();host.run=lambda args:types.SimpleNamespace(stdout=b'relay-node 1.4.4\n')
                with self.assertRaisesRegex(module.Failure,'FIXED_V143_ARTIFACT_VERSION_REQUIRED'):module.verify_target_binary(host,binary)
            with self.assertRaisesRegex(module.Failure,'FIXED_V143_ARTIFACT_SHA256_REQUIRED'):module.verify_target_binary(Host(),binary)
    def test_check_main_stops_before_creating_work_or_starting_operation(self):
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as root:
            base=pathlib.Path(root);opt=base/'opt/relay-node';opt.mkdir(parents=True);(opt/'node-id').write_text('old')
            env=base/'etc/relay-node';env.mkdir(parents=True);(env/'relay-node.env').write_text('PANEL_URL=https://panel.example.com\nNODE_TOKEN=fixture-group-token\n')
            host=module.Host(base);client=self.ReadClient()
            with tempfile.TemporaryFile(mode='w+') as auth:
                auth.write(json.dumps({'admin_token':'fixture-admin','probes':[]}));auth.seek(0)
                # main owns this duplicated fd, as real --auth-fd does.
                import os,sys
                fd=os.dup(auth.fileno())
                with patch.object(module,'Host',return_value=host),patch.object(host,'precheck'),patch.object(module,'Client',return_value=client),patch.object(module.os,'geteuid',return_value=0),patch.object(module.sys,'argv',['upgrader','--check','--auth-fd',str(fd)]),patch.object(module,'emit') as output:
                    module.main();self.assertEqual(output.call_args.args[0],'READY')
            self.assertFalse((base/'var/lib/relay-panel/legacy-v130-upgrade').exists())
            self.assertTrue(all(m=='GET' for m,p in client.calls))
    def test_legacy_identity_uses_authenticated_readonly_endpoint_not_group_dto(self):
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as root:
            host=module.Host(pathlib.Path(root));env=host.path('/etc/relay-node');env.mkdir(parents=True)
            (env/'relay-node.env').write_text('NODE_TOKEN=fixture-group-token\n')
            client=self.ReadClient()
            self.assertEqual(module.operator_identity(client,host,'old'),{'identity_group_id':7,'node_id':'old'})
            self.assertEqual(client.calls,[('GET',module.BASE+'/identity')])
    def test_recovery_resolves_panel_from_private_snapshot_when_environment_is_absent(self):
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as root:
            host=module.Host(pathlib.Path(root));work=pathlib.Path(root)/'work';backup=work/'backup/1';backup.mkdir(parents=True)
            (backup/'relay-node.env').write_text('PANEL_URL=https://panel.example.com\nNODE_TOKEN=fixture-secret\n')
            (backup/'relay-node.env').chmod(0o600)
            self.assertEqual(module.panel_url(host,None,work),'https://panel.example.com')
            self.assertEqual(module.panel_url(host,'https://explicit.example.com',work),'https://explicit.example.com')
            self.assertFalse(host.path('/etc/relay-node/relay-node.env').exists())
    def test_operator_cli_help_version_and_batch_rejection(self):
        import subprocess
        for option in ['--help','--version']:
            r=subprocess.run(['bash',str(SCRIPT),option],capture_output=True,text=True);self.assertEqual(r.returncode,0);self.assertIn('1.4.3',r.stdout)
        r=subprocess.run(['bash',str(SCRIPT),'--batch'],capture_output=True,text=True);self.assertNotEqual(r.returncode,0)
        self.assertNotIn('Traceback',r.stderr)

if __name__=='__main__':unittest.main()
