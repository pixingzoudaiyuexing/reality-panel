"""Strict host provenance and absent-marker rollback; no real host mutation."""
import ast
import copy
import io
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).parent
ORIGINAL = HERE / 'reality-node-v1.3.0-to-v1.4.2.sh'
HOTFIX = HERE / 'reality-node-v1.3.0-to-v1.4.3.sh'
def source(script):
    return script.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
module = types.ModuleType('layout_hotfix')
exec(compile(source(HOTFIX), str(HOTFIX), 'exec'), module.__dict__)
UNIT = '''[Unit]
Description=Reality Panel relay-node
After=network-online.target nginx.service
Wants=network-online.target
[Service]
Type=simple
RuntimeDirectory=relay-node
RuntimeDirectoryMode=0755
EnvironmentFile=/etc/relay-node/relay-node.env
WorkingDirectory=/opt/relay-node
ExecStart=/opt/relay-node/relay-node
Restart=always
RestartSec=3
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''

class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=str(pathlib.Path(tempfile.gettempdir()).resolve()))
        self.root = pathlib.Path(self.tmp.name)
        self.host = module.Host(self.root)
        self.commands = []
        self.bad_uid = set()
        self.version = b'relay-node 1.3.0\n'
        self.active = True
        self.fallback_listeners = b'LISTEN 0 511 127.0.0.1:5245 0.0.0.0:* users:(("nginx",pid=10,fd=4))\n'
        self.props = {'FragmentPath': '/etc/systemd/system/relay-node.service',
                      'DropInPaths': '', 'User': '', 'Group': '',
                      'Type': 'simple', 'WorkingDirectory': '/opt/relay-node',
                      'NeedDaemonReload': 'no'}
        self.dbus = {
            'ExecStart': {'type': 'a(sasbttttuii)', 'data': [['/opt/relay-node/relay-node', ['/opt/relay-node/relay-node'], False, 0, 0, 0, 0, 1, 0, 0]]},
            'EnvironmentFiles': {'type': 'a(sb)', 'data': [['/etc/relay-node/relay-node.env', False]]},
        }
        self.write('/opt/relay-node/relay-node', b'official-fixture', 0o755)
        self.write('/opt/relay-node/node-id', b'node_legacy-1\n', 0o600)
        self.write('/etc/relay-node/relay-node.env', b'PANEL_URL=https://test.invalid\nNODE_TOKEN=fixture-not-a-secret\n', 0o600)
        self.write('/etc/systemd/system/relay-node.service', UNIT.encode(), 0o644)
        self.write('/etc/os-release', b'ID=debian\nVERSION_ID="12"\n', 0o644)
        self.write('/etc/relay-panel/lite-mode', b'lite\n')
        self.write('/etc/nginx/conf.d/relay-panel-lite-fallback.conf', b'# RelayPanel managed Lite fallback\nserver {\n listen 127.0.0.1:5245;\n}\n')
        self.write('/var/www/fallback/index.html', b'<!-- RelayPanel managed Lite fallback -->\n')
        real_stat=pathlib.Path.stat
        def root_stat(p,*args,**kwargs):
            value=real_stat(p,*args,**kwargs)
            if p==self.root or self.root in p.parents:
                fields=list(value);fields[4]=1000 if p in self.bad_uid else 0;return os.stat_result(fields)
            return value
        patcher=patch.object(pathlib.Path,'stat',root_stat);patcher.start();self.addCleanup(patcher.stop)
        self.host.run = self.run_command
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, name, content, mode=0o644):
        p = self.host.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        p.chmod(mode)
        return p
    def run_command(self, args, check=True):
        self.commands.append(args)
        if args[0] == str(self.host.path('/opt/relay-node/relay-node')):
            output = self.version
        elif args[:2] == ['systemctl', 'is-active']:
            if not self.active: raise module.Failure('HOST_COMMAND_FAILED_SYSTEMCTL')
            output = b''
        elif args[:2] == ['systemctl', 'show']:
            output = self.props.get(args[3], '').encode()
        elif args[0] == 'busctl':
            output = json.dumps(self.dbus[args[-1]]).encode()
        elif args[0] == 'docker':
            output = json.dumps([self.container]).encode()
        elif args[0] == 'curl':
            output = b'pong\n'
        elif args[0] == 'ss':
            output = self.fallback_listeners
        elif args[:2] == ['sysctl', '-n']:
            output = b'fixture\n'
        else:
            output = b''
        return types.SimpleNamespace(returncode=0, stdout=output)
    def precheck(self, node_id='node_legacy-1'):
        real_stat = pathlib.Path.stat
        def root_stat(p, *args, **kwargs):
            value = real_stat(p, *args, **kwargs)
            if p == self.root or self.root in p.parents:
                fields = list(value)
                fields[4] = 1000 if p in self.bad_uid else 0
                return os.stat_result(fields)
            return value
        with patch.object(module.os, 'geteuid', return_value=0), \
             patch.object(module.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')), \
             patch.object(module, 'OFFICIAL_SHA256', hashlib.sha256(b'official-fixture').hexdigest()), \
             patch.object(module.shutil, 'which', return_value='/usr/bin/fixture'), \
             patch.object(pathlib.Path, 'stat', root_stat):
            return self.host.precheck({'node_id': node_id})
    def reject(self, category=None):
        before = self.tree_bytes()
        with self.assertRaisesRegex(module.Failure, category or '.+'):
            self.precheck()
        self.assertEqual(before, self.tree_bytes())
        self.assertFalse(any(c[:2] in [['systemctl', 'stop'], ['systemctl', 'restart'], ['systemctl', 'reload']] for c in self.commands))
        self.assertFalse(self.host.path('/var/lib/relay-panel/legacy-v130-upgrade').exists())
    def tree_bytes(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}
    def test_legacy_layout_without_marker_accepted_readonly(self):
        self.standard()
        before = self.tree_bytes()
        self.assertEqual(self.precheck(), 'standard')
        self.assertEqual(before, self.tree_bytes())
        self.assertFalse(self.host.path('/etc/relay-panel/lite-mode').exists())
    def test_lite_layout_accepted(self):
        self.write('/etc/relay-panel/lite-mode', b'lite\n')
        self.assertEqual(self.precheck(), 'lite')
    def test_wrong_binary_hash(self):
        self.host.path('/opt/relay-node/relay-node').write_bytes(b'custom')
        self.reject('OFFICIAL_V130_BINARY_REQUIRED')
    def test_wrong_binary_version(self):
        self.version = b'relay-node 1.3.1\n'
        self.reject('OFFICIAL_V130_VERSION_REQUIRED')
    def test_missing_node_id(self):
        self.host.path('/opt/relay-node/node-id').unlink()
        self.reject()
    def test_missing_environment(self):
        self.host.path('/etc/relay-node/relay-node.env').unlink()
        self.reject()
    def test_invalid_node_id(self):
        self.host.path('/opt/relay-node/node-id').write_text('node id\n')
        self.reject()
    def test_panel_identity_mismatch(self):
        with self.assertRaisesRegex(module.Failure, 'OLD_NODE_ID_MISMATCH'):
            self.precheck('different')
    def test_wrong_fragment(self):
        self.props['FragmentPath'] = '/lib/systemd/system/custom.service'
        self.reject()
    def test_dropin(self):
        self.props['DropInPaths'] = '/etc/systemd/system/relay-node.service.d/custom.conf'
        self.reject()
    def standard(self):
        for name in ['/etc/relay-panel/lite-mode','/etc/nginx/conf.d/relay-panel-lite-fallback.conf','/var/www/fallback/index.html']:
            self.host.path(name).unlink(missing_ok=True)
        self.host.path('/var/lib/relay-panel/xiaoya-byoa').mkdir(parents=True,exist_ok=True)
        marker={'version':1,'container_name':'relay-panel-xiaoya-byoa','data_path':'/var/lib/relay-panel/xiaoya-byoa','managed_label':'io.reality-panel.managed=xiaoya-byoa','last_successful_node_version':'1.3.0'}
        self.write('/var/lib/relay-panel/xiaoya-byoa-ownership.json',json.dumps(marker).encode(),0o600)
        self.container={'Id':'owned-container','Image':'owned-image','Name':'/relay-panel-xiaoya-byoa','State':{'Running':True},
            'Config':{'Labels':{'io.reality-panel.managed':'xiaoya-byoa'},'Env':['TZ=Asia/Shanghai','BYOA_XIAOYA_BOOTSTRAP=true','BYOA_XIAOYA_UPDATE=if-newer','BYOA_XIAOYA_STRICT=false']},
            'HostConfig':{'RestartPolicy':{'Name':'unless-stopped'},'PortBindings':{'5244/tcp':[{'HostIp':'127.0.0.1','HostPort':'5245'}]}},
            'Mounts':[{'Source':'/var/lib/relay-panel/xiaoya-byoa','Destination':'/opt/alist/data','RW':True}]}
        self.fallback_listeners=b'LISTEN 0 4096 127.0.0.1:5245 0.0.0.0:* users:(("docker-proxy",pid=8336,fd=4))\n'
    def native_environment(self):
        return b"PANEL_URL=https://test.invalid\nNODE_TOKEN=fixture\nNGINX_SNI_ENABLED=1\nNGINX_SNI_TEST_CMD='nginx -t'\nNGINX_SNI_RELOAD_CMD='systemctl reload nginx'\nNGINX_SNI_CONF_PATH=/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf\n"
    def test_official_historical_root_0644_node_id_accepted(self):
        self.standard()
        self.host.path('/opt/relay-node/node-id').chmod(0o644)
        self.assertEqual(self.precheck(), 'standard')
    def test_historical_docker_ordering_with_native_nginx_and_standard_fallback_accepted(self):
        self.standard()
        self.write('/etc/systemd/system/relay-node.service', UNIT.replace('After=network-online.target nginx.service', 'After=network-online.target docker.service nginx.service').encode())
        self.write('/etc/relay-node/relay-node.env', self.native_environment(), 0o600)
        self.assertEqual(self.precheck(), 'standard')
    def test_docker_ordering_without_positive_native_nginx_evidence_rejected(self):
        self.write('/etc/systemd/system/relay-node.service', UNIT.replace('After=network-online.target nginx.service', 'After=network-online.target docker.service nginx.service').encode())
        self.reject()
    def test_existing_docker_xiaoya_fallback_rejected_before_stop(self):
        self.write('/etc/relay-node/relay-node.env', self.native_environment(), 0o600)
        self.fallback_listeners = b'LISTEN 0 4096 127.0.0.1:5245 0.0.0.0:* users:(("docker-proxy",pid=8336,fd=4))\n'
        self.reject('LITE_FALLBACK_PORT_CONFLICT')
    def test_existing_managed_lite_fallback_accepted(self):
        self.fallback_listeners = b'LISTEN 0 511 127.0.0.1:5245 0.0.0.0:* users:(("nginx",pid=10,fd=4))\n'
        self.write('/etc/nginx/conf.d/relay-panel-lite-fallback.conf', b'# RelayPanel managed Lite fallback\nserver {\n listen 127.0.0.1:5245;\n}\n')
        self.write('/var/www/fallback/index.html', b'<!-- RelayPanel managed Lite fallback -->\n')
        self.assertEqual(self.precheck(), 'lite')
    def test_fallback_unknown_mixed_or_unparseable_owner_rejected(self):
        for lines in [b'garbage\n', b'LISTEN 0 1 127.0.0.1:5245 *:*\n', b'LISTEN 0 1 127.0.0.1:5245 *:* users:(("nginx",pid=1,fd=4),("foreign",pid=2,fd=4))\n', b'LISTEN 0 1 127.0.0.1:1234 *:* users:(("nginx",pid=1,fd=4))\n']:
            with self.subTest(lines=lines):
                self.fallback_listeners = lines
                self.reject('LITE_FALLBACK_PORT_CONFLICT')
    def test_fallback_wildcard_and_ipv6_listener_rejected(self):
        self.write('/etc/nginx/conf.d/relay-panel-lite-fallback.conf', b'# RelayPanel managed Lite fallback\nserver {\n listen 127.0.0.1:5245;\n}\n')
        self.write('/var/www/fallback/index.html', b'<!-- RelayPanel managed Lite fallback -->\n')
        for address in ['0.0.0.0:5245', '[::]:5245', '*:5245', '[::1]:5245']:
            with self.subTest(address=address):
                self.fallback_listeners = ('LISTEN 0 511 ' + address + ' *:* users:(("nginx",pid=10,fd=4))\n').encode()
                self.reject('LITE_FALLBACK_PORT_CONFLICT')
    def test_foreign_nginx_fallback_content_rejected(self):
        self.fallback_listeners = b'LISTEN 0 1 127.0.0.1:5245 *:* users:(("nginx",pid=1,fd=4))\n'
        self.write('/etc/nginx/conf.d/relay-panel-lite-fallback.conf', b'# foreign\n')
        self.reject('LITE_FALLBACK_PORT_CONFLICT')
    def test_fallback_ss_failure_rejected(self):
        previous = self.host.run
        def fail_ss(args, check=True):
            if args[0] == 'ss': raise module.Failure('HOST_COMMAND_FAILED_SS')
            return previous(args, check)
        self.host.run = fail_ss
        self.reject('HOST_COMMAND_FAILED_SS')
    def test_docker_or_custom_nginx_environment_rejected(self):
        for directive in ["NGINX_SNI_TEST_CMD='docker exec relay-node-nginx nginx -t'", "NGINX_SNI_RELOAD_CMD='docker exec relay-node-nginx nginx -s reload'", 'NGINX_SNI_CONF_PATH=/opt/relay-node/nginx-stream/relay-panel-sni.conf', "NGINX_SNI_TEST_CMD='nginx -t; custom-wrapper'", 'NGINX_SNI_MODE=docker']:
            with self.subTest(directive=directive):
                self.write('/etc/relay-node/relay-node.env', ('PANEL_URL=https://test.invalid\nNODE_TOKEN=fixture\n' + directive + '\n').encode(), 0o600)
                self.reject()
    def test_missing_official_unit_directive(self):
        self.write('/etc/systemd/system/relay-node.service', UNIT.replace('RuntimeDirectory=relay-node\n', '').encode())
        self.reject()
    def test_managed_parent_symlink(self):
        parent = self.host.path('/opt/relay-node')
        backup = parent.with_name('relay-node.saved')
        parent.rename(backup)
        parent.symlink_to(backup, target_is_directory=True)
        self.reject('SYMLINK')
    def test_malformed_dbus_boolean(self):
        self.dbus['ExecStart']['data'][0][2] = 0
        self.reject()
    def test_nonroot_unit_user(self):
        self.props['User'] = 'nobody'
        self.reject()
    def test_nonroot_unit_group(self):
        self.props['Group'] = 'nogroup'
        self.reject()
    def test_noncanonical_effective_exec(self):
        self.dbus['ExecStart']['data'][0][0] = '/bin/bash'
        self.reject()
    def test_extra_effective_exec_argument(self):
        self.dbus['ExecStart']['data'][0][1].append('--config=/tmp/custom')
        self.reject()
    def test_multiple_effective_exec(self):
        self.dbus['ExecStart']['data'] *= 2
        self.reject()
    def test_ignore_exec_failure(self):
        self.dbus['ExecStart']['data'][0][2] = True
        self.reject()
    def test_noncanonical_effective_environment(self):
        self.dbus['EnvironmentFiles']['data'][0][0] = '/tmp/custom.env'
        self.reject()
    def test_optional_effective_environment(self):
        self.dbus['EnvironmentFiles']['data'][0][1] = True
        self.reject()
    def test_additional_effective_environment(self):
        self.dbus['EnvironmentFiles']['data'].append(['/tmp/extra.env', False])
        self.reject()
    def test_malformed_dbus_property(self):
        self.dbus['ExecStart'] = {'type': 's', 'data': '/opt/relay-node/relay-node'}
        self.reject()
    def test_custom_unit_directives(self):
        for directive in ['ExecStartPre=/bin/true', 'ExecStartPost=/bin/true', 'ExecCondition=/bin/true', 'RootDirectory=/tmp/root', 'Environment=NODE_TOKEN=override', 'EnvironmentFile=/tmp/extra.env', 'ExecStart=/bin/bash /opt/relay-node/start.sh']:
            with self.subTest(directive=directive):
                self.write('/etc/systemd/system/relay-node.service', UNIT.replace('[Service]', '[Service]\n' + directive).encode())
                self.reject()
    def test_unsafe_permissions_and_ownership(self):
        for name in ['/opt/relay-node/relay-node', '/opt/relay-node/node-id', '/etc/relay-node/relay-node.env', '/etc/systemd/system/relay-node.service', '/opt/relay-node']:
            with self.subTest(name=name):
                p = self.host.path(name)
                mode = stat.S_IMODE(p.stat().st_mode)
                p.chmod(mode | 0o020)
                self.reject()
                p.chmod(mode)
                self.bad_uid.add(p)
                self.reject()
                self.bad_uid.clear()
    def test_public_readable_secret_environment(self):
        self.host.path('/etc/relay-node/relay-node.env').chmod(0o644)
        self.reject()
    def test_critical_symlinks(self):
        for name in ['/opt/relay-node/relay-node', '/opt/relay-node/node-id', '/etc/relay-node/relay-node.env', '/etc/systemd/system/relay-node.service']:
            with self.subTest(name=name):
                p = self.host.path(name)
                backup = p.with_name(p.name + '.saved')
                p.rename(backup)
                p.symlink_to(backup)
                self.reject('SYMLINK')
                p.unlink()
                backup.rename(p)
    def test_unsafe_optional_snapshot_path(self):
        p = self.write('/etc/relay-panel/camouflage-sites.json', b'{}')
        p.chmod(0o666)
        self.reject()
    def test_missing_token_or_malformed_environment(self):
        for content in [b'PANEL_URL=https://test.invalid\n', b'PANEL_URL=https://test.invalid\nNODE_TOKEN="unterminated\n', b'PANEL_URL=https://test.invalid\nNODE_TOKEN=first\nNODE_TOKEN=second\n', b'PANEL_URL=https://test.invalid\nNODE_TOKEN=one two\n']:
            with self.subTest(content=content):
                self.write('/etc/relay-node/relay-node.env', content, 0o600)
                self.reject()
    def test_pending_unit_reload(self):
        self.props['NeedDaemonReload'] = 'yes'
        self.reject()
    def test_loaded_custom_systemd_properties(self):
        for prop in ['ExecStartPre', 'ExecStartPost', 'ExecCondition', 'ExecStop', 'RootDirectory', 'Environment', 'PassEnvironment']:
            with self.subTest(prop=prop):
                self.props[prop] = 'custom'
                self.reject()
                self.props[prop] = ''
    def test_inactive_service(self):
        self.active = False
        self.reject()
    def test_unsupported_os(self):
        for os_id, version in [('debian', '11'), ('debian', '13'), ('ubuntu', '22')]:
            with self.subTest(os_id=os_id, version=version):
                self.write('/etc/os-release', ('ID=%s\nVERSION_ID=%s\n' % (os_id, version)).encode())
                self.reject('SUPPORTED_DEBIAN_12_REQUIRED')
    def test_unsupported_arch(self):
        with patch.object(module.os, 'uname', return_value=types.SimpleNamespace(machine='aarch64')):
            # Avoid the regular fixture's uname patch.
            with self.assertRaisesRegex(module.Failure, 'ROOT_AMD64_REQUIRED'):
                self.host.precheck({'node_id': 'node_legacy-1'})
    def test_foreign_nginx_rejected_before_any_commands(self):
        self.write('/etc/nginx/conf.d/relay-panel-fallback.conf', b'# foreign\n')
        self.reject('UNMANAGED_NGINX_CONFIG')
        self.assertEqual(self.commands, [])
    def test_absent_marker_and_legacy_state_restore_after_failure(self):
        self.standard()
        before = self.tree_bytes()
        work = self.root / 'work'
        work.mkdir(mode=0o700)
        self.host.capture(work)
        snapshot = json.loads((work / 'snapshot.json').read_text())
        self.assertNotIn(module.SNAPSHOT_PATHS.index('/etc/relay-panel/lite-mode'), snapshot['present'])
        self.host.stop_and_detach(work)
        self.write('/etc/relay-panel/lite-mode', b'new-bootstrap-marker\n')
        self.write('/var/lib/relay-panel/xiaoya-byoa-ownership.json', b'changed marker\n', 0o600)
        self.write('/opt/relay-node/node-id', b'new-identity\n', 0o600)
        self.host.rollback(work)
        after = {k: v for k, v in self.tree_bytes().items() if not k.startswith('work/')}
        self.assertEqual(before, after)
        self.assertFalse(self.host.path('/etc/relay-panel/lite-mode').exists())
        self.assertIn(['systemctl', 'start', 'relay-node.service'], self.commands)

    def test_missing_lite_marker_alone_never_implies_standard(self):
        self.host.path('/etc/relay-panel/lite-mode').unlink()
        self.reject('INSTALL_PROFILE_EVIDENCE_CONFLICT')
        self.host.path('/etc/nginx/conf.d/relay-panel-lite-fallback.conf').unlink()
        self.host.path('/var/www/fallback/index.html').unlink()
        self.reject('MANAGED_LAYOUT_FILE_REQUIRED')
    def test_lite_marker_alone_is_insufficient(self):
        self.host.path('/etc/nginx/conf.d/relay-panel-lite-fallback.conf').unlink()
        self.host.path('/var/www/fallback/index.html').unlink()
        self.fallback_listeners=b''
        self.reject('MANAGED_LAYOUT_FILE_REQUIRED')
    def test_lite_requires_live_owned_listener(self):
        self.fallback_listeners=b''
        self.reject('LITE_FALLBACK_PORT_CONFLICT')
    def test_lite_marker_content_is_exact(self):
        self.write('/etc/relay-panel/lite-mode',b'1\n')
        self.reject('INSTALL_PROFILE_EVIDENCE_CONFLICT')
    def test_standard_lite_evidence_conflict(self):
        self.standard();self.write('/etc/relay-panel/lite-mode',b'lite\n')
        self.reject('INSTALL_PROFILE_EVIDENCE_CONFLICT')
    def test_standard_requires_strong_marker_and_live_container(self):
        self.standard()
        marker=self.host.path('/var/lib/relay-panel/xiaoya-byoa-ownership.json')
        original=marker.read_bytes();marker.write_text('{}');self.reject('STANDARD_FALLBACK_OWNERSHIP_REQUIRED');marker.write_bytes(original)
        original=copy.deepcopy(self.container)
        faults=[('Name','/foreign'),('Id',''),('Image',''),('State',{'Running':False}),('Config',{}),('HostConfig',{}),('Mounts',[])]
        for key,value in faults:
            with self.subTest(key=key):
                self.container=copy.deepcopy(original);self.container[key]=value
                self.reject('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
    def test_standard_rejects_foreign_mixed_and_wildcard_owners(self):
        self.standard()
        for listeners in [b'LISTEN 0 1 127.0.0.1:5245 *:* users:(("nginx",pid=1,fd=4))\n', b'LISTEN 0 1 0.0.0.0:5245 *:* users:(("docker-proxy",pid=1,fd=4))\n', b'LISTEN 0 1 127.0.0.1:5245 *:* users:(("docker-proxy",pid=1,fd=4),("foreign",pid=2,fd=4))\n']:
            with self.subTest(listeners=listeners):
                self.fallback_listeners=listeners;self.reject()
    def test_standard_exact_binding_mount_env_and_label(self):
        self.standard();original=copy.deepcopy(self.container)
        variants=[]
        for edit in [lambda d:d['HostConfig']['PortBindings']['5244/tcp'][0].update(HostIp='0.0.0.0'),
                     lambda d:d['HostConfig']['RestartPolicy'].update(Name='no'),
                     lambda d:d['Mounts'][0].update(Source='/foreign'),
                     lambda d:d['Mounts'][0].update(RW=False),
                     lambda d:d['Config']['Labels'].clear(),
                     lambda d:d['Config']['Env'].remove('BYOA_XIAOYA_BOOTSTRAP=true')]:
            value=copy.deepcopy(original);edit(value);variants.append(value)
        for value in variants:
            with self.subTest(value=value):self.container=value;self.reject('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
    def test_standard_docker_kernel_nat_without_proxy_is_valid_when_healthy(self):
        self.standard();self.fallback_listeners=b''
        self.assertEqual(self.precheck(),'standard')
    def test_unhealthy_fallback_never_passes_either_profile(self):
        original=self.host.run
        def fail_ping(args,**kwargs):
            return types.SimpleNamespace(stdout=b'not pong') if args[0]=='curl' else original(args,**kwargs)
        self.host.run=fail_ping
        self.reject('MANAGED_FALLBACK_HEALTH_REQUIRED')
        self.standard();self.reject('MANAGED_FALLBACK_HEALTH_REQUIRED')
    def test_standard_snapshot_rollback_preserves_container_and_data_and_marker(self):
        self.standard();data=self.host.path('/var/lib/relay-panel/xiaoya-byoa/user-config.json');data.write_text('owner-data')
        container=copy.deepcopy(self.container);before=self.tree_bytes();work=self.root/'work';work.mkdir(mode=0o700)
        self.host.capture(work);self.host.stop_and_detach(work)
        self.write('/opt/relay-node/node-id',b'new-identity',0o600)
        marker=self.host.path('/var/lib/relay-panel/xiaoya-byoa-ownership.json');value=json.loads(marker.read_text());value['last_successful_node_version']='1.4.3';marker.write_text(json.dumps(value))
        self.host.rollback(work)
        self.assertEqual(container,self.container);self.assertEqual(data.read_text(),'owner-data')
        self.assertEqual(before,{k:v for k,v in self.tree_bytes().items() if not k.startswith('work/')})
        self.assertFalse(self.host.path('/etc/relay-panel/lite-mode').exists())
        self.assertFalse(any(c[0]=='docker' and c[1]!='inspect' for c in self.commands))
    def test_standard_postcheck_detects_container_replacement_or_configuration_change(self):
        self.standard();work=self.root/'work';work.mkdir(mode=0o700);self.host.capture(work)
        self.container['Id']='replacement'
        with self.assertRaisesRegex(module.Failure,'STANDARD_FALLBACK_CHANGED'):self.host.profile_postcheck('standard',work)
    def test_standard_install_passes_private_reuse_policy_and_lite_does_not(self):
        work=self.root/'work';work.mkdir(mode=0o700)
        self.host.install(work)
        self.assertEqual(self.commands[-1][0],'bash')
        self.standard();self.host.capture(work);self.host.install(work)
        self.assertEqual(self.commands[-1][:3],['env','RELAY_NODE_PRESERVE_STANDARD_FALLBACK=1','bash'])
    def test_installed_profile_mismatch_is_rejected(self):
        with self.assertRaisesRegex(module.Failure,'INSTALL_PROFILE_CHANGED'):self.host.profile_postcheck('standard',self.root)

class IsolationTests(unittest.TestCase):
    def test_published_v142_upgrader_bytes_unchanged(self):
        self.assertEqual(hashlib.sha256(ORIGINAL.read_bytes()).hexdigest(),'e68fced6e42fabee388bb438a51bbcf414edabcbf4870c2195fbb622e5563b99')
    def test_finalize_unknown_and_recovery_decisions_are_unchanged(self):
        def methods(script,cls):
            tree=ast.parse(source(script));node=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==cls)
            return {n.name:ast.dump(n) for n in node.body if isinstance(n,ast.FunctionDef)}
        old,new=methods(ORIGINAL,'Runner'),methods(HOTFIX,'Runner')
        for name in ['wait_action','recover_failure']:self.assertEqual(old[name],new[name],name)
        old,new=methods(ORIGINAL,'Host'),methods(HOTFIX,'Host')
        for name in ['stop_and_detach','complete','old_auth']:self.assertEqual(old[name],new[name],name)

if __name__=='__main__':unittest.main()
