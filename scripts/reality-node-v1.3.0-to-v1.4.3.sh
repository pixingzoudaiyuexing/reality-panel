#!/usr/bin/env bash
set -euo pipefail
# One explicit host invocation; exact official v1.3.0 amd64 managed systemd layouts.
# Profile-preserving v1.4.3 upgrade; published v1.4.2 upgrader remains unchanged.
# No batching, SSH traversal, implicit next Node or unchecked network execution.
python3 - "$@" <<'PY'
import argparse, contextlib, fcntl, getpass, hashlib, io, json, os, pathlib, re
import shutil, signal, ssl, subprocess, sys, tarfile, time, urllib.error, urllib.request

TARGET_VERSION = '1.4.3'
TARGET_SHA256 = '9ed519c48e2ca6ddd2993d9e2eaf1c54ff0e8b3cad2c24ceccfe3f9001e58067'
OFFICIAL_SHA256 = '5c70aac9aab2e78b739d0468d6920b56fac427fb31f18790bc0809c616f965f9'
BASE = '/legacy-node-upgrade-v130'
OWNED_TREES = ['/opt/relay-node', '/etc/relay-node', '/var/lib/relay-panel/node-claims']
SNAPSHOT_PATHS = OWNED_TREES + [
 '/etc/systemd/system/relay-node.service', '/etc/relay-panel/camouflage-sites.json',
 '/etc/relay-panel/lite-mode', '/etc/nginx/relay-panel-stream.d',
 '/etc/nginx/relay-panel-stream.conf', '/etc/nginx/conf.d/relay-panel-fallback.conf',
 '/etc/nginx/conf.d/relay-panel-acme.conf', '/etc/nginx/conf.d/relay-panel-lite-fallback.conf',
 '/etc/nginx/relay-panel-certs', '/var/www/fallback/index.html',
 '/etc/sysctl.d/99-reality-panel-bbr.conf', '/etc/modules-load.d/reality-panel-bbr.conf',
 '/var/lib/relay-panel/xiaoya-byoa-ownership.json',
]

class Failure(Exception):
    pass

class ApiFailure(Failure):
    pass

def emit(stage, message):
    print('[%s] %s' % (stage, message), flush=True)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def private_json(path, value):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out); out.flush(); os.fsync(out.fileno())
    os.replace(temporary, path)

def safe_path(path):
    for parent in [path] + list(path.parents):
        if parent.is_symlink():
            raise Failure('SYMLINK_PATH_REQUIRES_MANUAL_INSPECTION')

def remove_owned(path):
    safe_path(path)
    if path.is_dir(): shutil.rmtree(path)
    elif path.exists(): path.unlink()

class Client:
    def __init__(self, panel, admin):
        if not panel.startswith('https://'):
            raise Failure('HTTPS_PANEL_REQUIRED')
        self.url = panel.rstrip('/') + '/api/v1'; self.admin = admin
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(self, method, path, body=None, token=None, headers=None, binary=False):
        h = {'Content-Type': 'application/json', 'User-Agent': 'RealityPanel-NodeBootstrap/'+TARGET_VERSION}
        if token: h['Authorization'] = 'Bearer ' + token
        if headers: h.update(headers)
        req = urllib.request.Request(self.url+path, data=None if body is None else json.dumps(body).encode(), headers=h, method=method)
        try:
            with self.opener.open(req, timeout=60) as r:
                data = r.read()
                if binary: return data, r.headers.get('X-Content-SHA256', '')
                out = json.loads(data)
                if out.get('code', 0) != 0: raise ApiFailure('API_REJECTED')
                return out.get('data', out)
        except urllib.error.HTTPError as e:
            try: category=json.loads(e.read(65536)).get('message','HTTP_'+str(e.code))
            except (ValueError, UnicodeError): category='HTTP_'+str(e.code)
            if not re.fullmatch('[A-Z0-9_]+',category): category='HTTP_'+str(e.code)
            raise ApiFailure(category) from None
        except (OSError, ValueError):
            raise ApiFailure('PANEL_UNAVAILABLE') from None
    def start(self, identity, probes, profile):
        return self.request('POST', '/admin'+BASE+'/start', {**identity, 'official_sha256':OFFICIAL_SHA256, 'probes':probes, 'source_profile':profile}, self.admin)
    def status(self, op):
        return self.request('GET', BASE+'/'+op['operation']['id'], token=op['migration_token'])
    def action(self, op, action):
        return self.request('POST', BASE+'/'+op['operation']['id'], {'action':action}, op['migration_token'])
    def bundle(self, op):
        data, sha = self.request('GET', BASE+'/'+op['operation']['id']+'/bundle', token=op['migration_token'], binary=True)
        if not re.fullmatch('[a-f0-9]{64}',sha) or digest(data)!=sha: raise Failure('BUNDLE_CHECKSUM_FAILURE')
        return data

class Host:
    def __init__(self, root=pathlib.Path('/')):
        self.root=root
    def path(self, name): return self.root/name.lstrip('/')
    def run(self, args, check=True):
        # Bootstrap output may include private paths. Keep it in RAM; never log credentials.
        p=subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        if check and p.returncode: raise Failure('HOST_COMMAND_FAILED_'+pathlib.Path(args[0]).name.upper())
        return p
    def generated_nginx_paths(self):
        owned={
            '/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf': ['# generated by relay-node; do not edit'],
            '/etc/nginx/conf.d/relay-panel-fallback.conf': ['# generated by relay-node; TLS camouflage sites', '# RelayPanel managed bootstrap camouflage fallback'],
            '/etc/nginx/conf.d/relay-panel-acme.conf': ['# generated by relay-node; global HTTP to HTTPS redirect', '# generated by relay-node; ACME HTTP-01 only'],
        }
        for name, markers in owned.items():
            path=self.path(name);safe_path(path)
            if path.exists():
                if not path.is_file() or path.read_text().splitlines()[:1] not in [[m] for m in markers]:
                    raise Failure('UNMANAGED_NGINX_CONFIG_REQUIRES_MANUAL_INSPECTION')
        return list(owned)
    def trusted_path(self, name, private=False, directory=False):
        path=self.path(name);safe_path(path)
        if not path.exists(): raise Failure('MANAGED_LAYOUT_FILE_REQUIRED')
        for current in [path]+list(path.parents):
            info=current.stat()
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise Failure('ROOT_OWNED_SAFE_MANAGED_PATH_REQUIRED')
            if current==self.root: break
        if not (path.is_dir() if directory else path.is_file()): raise Failure('MANAGED_LAYOUT_PATH_TYPE_REQUIRED')
        if private and path.stat().st_mode & 0o077:
            raise Failure('PRIVATE_MANAGED_FILE_REQUIRED')
        return path
    def managed_environment(self, path):
        import shlex
        values={}
        try:
            for raw in path.read_text().splitlines():
                line=raw.strip()
                if not line or line.startswith('#'): continue
                if '=' not in line: raise ValueError()
                key,value=line.split('=',1)
                if not re.fullmatch('[A-Z][A-Z0-9_]*',key) or key in values: raise ValueError()
                parts=shlex.split(value)
                if len(parts)>1: raise ValueError()
                values[key]=parts[0] if parts else ''
        except (ValueError,UnicodeError): raise Failure('INVALID_MANAGED_ENVIRONMENT') from None
        if not values.get('PANEL_URL','').startswith('https://'):
            raise Failure('HTTPS_PANEL_REQUIRED')
        # STOP/rollback operate host Nginx only; Docker/custom Nginx is unsupported.
        native_nginx={'NGINX_SNI_TEST_CMD':'nginx -t',
                      'NGINX_SNI_RELOAD_CMD':'systemctl reload nginx',
                      'NGINX_SNI_CONF_PATH':'/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf',
                      'NGINX_SNI_MODE':'host'}
        if any(key in values and values[key]!=expected for key,expected in native_nginx.items()):
            raise Failure('HOST_NATIVE_NGINX_LAYOUT_REQUIRED')
        if values.get('NGINX_SNI_ENABLED','').lower() in ['1','true','yes','on']:
            if any(values.get(key)!=native_nginx[key] for key in ['NGINX_SNI_TEST_CMD','NGINX_SNI_RELOAD_CMD','NGINX_SNI_CONF_PATH']):
                raise Failure('HOST_NATIVE_NGINX_LAYOUT_REQUIRED')
        descriptor=self.path('/var/lib/relay-panel/node-claims/runtime-auth.json')
        if descriptor.exists(): self.trusted_path('/var/lib/relay-panel/node-claims/runtime-auth.json',private=True)
        elif not values.get('NODE_TOKEN'): raise Failure('OLD_AUTH_UNAVAILABLE')
        return values
    def systemd_property(self, name):
        return self.run(['systemctl','show','-p',name,'--value','relay-node.service']).stdout.decode().strip()
    def typed_service_property(self, name, signature):
        # systemd's structured D-Bus result avoids parsing human-readable ExecStart.
        output=self.run(['busctl','--system','--json=short','get-property',
                         'org.freedesktop.systemd1',
                         '/org/freedesktop/systemd1/unit/relay_2dnode_2eservice',
                         'org.freedesktop.systemd1.Service',name]).stdout
        try: value=json.loads(output)
        except (ValueError,UnicodeError): raise Failure('UNRECOGNIZED_SYSTEMD_PROPERTY') from None
        if not isinstance(value,dict) or value.get('type')!=signature or not isinstance(value.get('data'),list):
            raise Failure('UNRECOGNIZED_SYSTEMD_PROPERTY')
        return value['data']
    def managed_unit(self, unit):
        # The historical official native bootstrap generated these unit directives.
        # Reject custom directives, wrappers, duplicates and pending daemon reloads.
        allowed={
            'Unit': {'Description': None,
                     'After': {'network-online.target nginx.service','network-online.target docker.service nginx.service'},
                     'Wants': {'network-online.target'}},
            'Service': {'Type': {'simple'},'RuntimeDirectory': {'relay-node'},
                        'RuntimeDirectoryMode': {'0755'},
                        'EnvironmentFile': {'/etc/relay-node/relay-node.env'},
                        'WorkingDirectory': {'/opt/relay-node'},
                        'ExecStart': {'/opt/relay-node/relay-node'},
                        'Restart': {'always'},'RestartSec': {'3'},'LimitNOFILE': {'65536'},
                        'User': {'root'},'Group': {'root'}},
            'Install': {'WantedBy': {'multi-user.target'}},
        }
        section=None;seen=set();sections=set();docker_ordering=False
        for raw in unit.read_text().splitlines():
            line=raw.strip()
            if not line or line.startswith(('#',';')): continue
            if line.startswith('[') and line.endswith(']'):
                section=line[1:-1]
                if section not in allowed or section in sections: raise Failure('CUSTOM_SYSTEMD_UNIT_REQUIRES_MANUAL_INSPECTION')
                sections.add(section);continue
            if section is None or '=' not in line: raise Failure('CUSTOM_SYSTEMD_UNIT_REQUIRES_MANUAL_INSPECTION')
            key,value=line.split('=',1);key=key.strip();value=value.strip()
            choices=allowed[section].get(key,set())
            if (section,key) in seen or (choices is not None and value not in choices):
                raise Failure('CUSTOM_SYSTEMD_UNIT_REQUIRES_MANUAL_INSPECTION')
            seen.add((section,key))
            if section=='Unit' and key=='After': docker_ordering='docker.service' in value
        required={(section,key) for section,fields in allowed.items() for key in fields if key not in ['User','Group']}
        if sections!=set(allowed) or not required.issubset(seen):
            raise Failure('OFFICIAL_SYSTEMD_LAYOUT_REQUIRED')
        if self.systemd_property('FragmentPath')!='/etc/systemd/system/relay-node.service':
            raise Failure('OFFICIAL_SYSTEMD_LAYOUT_REQUIRED')
        if self.systemd_property('DropInPaths'): raise Failure('CUSTOM_UNIT_DROPINS_REQUIRE_MANUAL_INSPECTION')
        if any(self.systemd_property(p) not in ['', 'root'] for p in ['User','Group']):
            raise Failure('ROOT_SYSTEMD_SERVICE_REQUIRED')
        if self.systemd_property('NeedDaemonReload')!='no': raise Failure('SYSTEMD_UNIT_RELOAD_REQUIRED')
        if self.systemd_property('Type')!='simple' or self.systemd_property('WorkingDirectory')!='/opt/relay-node':
            raise Failure('OFFICIAL_SYSTEMD_LAYOUT_REQUIRED')
        for prop in ['ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost',
                     'RootDirectory','RootImage','Environment','PassEnvironment','UnsetEnvironment']:
            if self.systemd_property(prop): raise Failure('CUSTOM_SYSTEMD_UNIT_REQUIRES_MANUAL_INSPECTION')
        commands=self.typed_service_property('ExecStart','a(sasbttttuii)')
        if len(commands)!=1 or not isinstance(commands[0],list) or len(commands[0])!=10 or commands[0][:2]!=[
                '/opt/relay-node/relay-node',['/opt/relay-node/relay-node']] or commands[0][2] is not False:
            raise Failure('OFFICIAL_SYSTEMD_EXECSTART_REQUIRED')
        environment=self.typed_service_property('EnvironmentFiles','a(sb)')
        if environment!=[['/etc/relay-node/relay-node.env',False]] or environment[0][1] is not False:
            raise Failure('OFFICIAL_SYSTEMD_ENVIRONMENT_REQUIRED')
        return docker_ordering
    def lite_fallback_preflight(self):
        # Validate the currently installed, managed native Lite fallback before STOP.
        conf=self.path('/etc/nginx/conf.d/relay-panel-lite-fallback.conf')
        index=self.path('/var/www/fallback/index.html')
        for path,marker in [(conf,'# RelayPanel managed Lite fallback'),
                            (index,'<!-- RelayPanel managed Lite fallback -->')]:
            if path.exists() and path.read_text().splitlines()[:1]!=[marker]:
                raise Failure('LITE_FALLBACK_PORT_CONFLICT')
        output=self.run(['ss','-H','-ltnp','sport = :5245']).stdout.decode()
        lines=[line.strip() for line in output.splitlines() if line.strip()]
        if not lines: return
        for line in lines:
            fields=line.split(None,5)
            if len(fields)!=6 or fields[0]!='LISTEN' or not fields[1].isdigit() or not fields[2].isdigit() or fields[3]!='127.0.0.1:5245' or not re.fullmatch(
                    r'users:\(\("nginx",pid=[0-9]+,fd=[0-9]+\)(?:,\("nginx",pid=[0-9]+,fd=[0-9]+\))*\)',fields[5]):
                raise Failure('LITE_FALLBACK_PORT_CONFLICT')
        if not conf.is_file() or not index.is_file() or not re.search(r'(?m)^\s*listen\s+127\.0\.0\.1:5245\s*;',conf.read_text()):
            raise Failure('LITE_FALLBACK_PORT_CONFLICT')
    def listeners_5245(self):
        output=self.run(['ss','-H','-ltnp','sport = :5245']).stdout.decode()
        result=[]
        for line in output.splitlines():
            if not line.strip(): continue
            fields=line.split(None,5)
            if len(fields)!=6 or fields[0]!='LISTEN' or not fields[1].isdigit() or not fields[2].isdigit() or fields[3]!='127.0.0.1:5245':
                raise Failure('FALLBACK_LISTENER_OWNERSHIP_REQUIRED')
            owners=re.fullmatch(r'users:\((.*)\)',fields[5])
            if not owners: raise Failure('FALLBACK_LISTENER_OWNERSHIP_REQUIRED')
            entries=owners[1].split('),(')
            names=[]
            for entry in entries:
                match=re.fullmatch(r'\(?"([A-Za-z0-9_-]+)",pid=[0-9]+,fd=[0-9]+\)?',entry)
                if not match: raise Failure('FALLBACK_LISTENER_OWNERSHIP_REQUIRED')
                names.append(match[1])
            if not names: raise Failure('FALLBACK_LISTENER_OWNERSHIP_REQUIRED')
            result.extend(names)
        return result
    def fallback_health(self):
        response=self.run(['curl','--noproxy','*','--max-time','10','-fsS','http://127.0.0.1:5245/ping']).stdout
        if response.strip()!=b'pong': raise Failure('MANAGED_FALLBACK_HEALTH_REQUIRED')
    def standard_fallback(self):
        # Match the Node's existing Xiaoya ownership contract; name alone is insufficient.
        marker=self.trusted_path('/var/lib/relay-panel/xiaoya-byoa-ownership.json',private=True)
        self.trusted_path('/var/lib/relay-panel/xiaoya-byoa',directory=True)
        try:
            evidence=json.loads(marker.read_text())
            raw=self.run(['docker','inspect','relay-panel-xiaoya-byoa']).stdout
            inspected=json.loads(raw)
        except (ValueError,UnicodeError): raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED') from None
        expected={'version':1,'container_name':'relay-panel-xiaoya-byoa','data_path':'/var/lib/relay-panel/xiaoya-byoa','managed_label':'io.reality-panel.managed=xiaoya-byoa'}
        if not isinstance(evidence,dict) or type(evidence.get('version')) is not int or any(evidence.get(key)!=value for key,value in expected.items()) or (evidence.get('last_successful_node_version') is not None and not isinstance(evidence['last_successful_node_version'],str)):
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        if not isinstance(inspected,list) or len(inspected)!=1 or not isinstance(inspected[0],dict):
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        d=inspected[0];config=d.get('Config',{});host=d.get('HostConfig',{});mounts=d.get('Mounts',[])
        if not isinstance(config,dict) or not isinstance(host,dict) or not isinstance(d.get('State'),dict) or not isinstance(config.get('Env'),list) or not all(isinstance(v,str) for v in config['Env']) or not isinstance(config.get('Labels'),dict) or not all(isinstance(v,str) for v in config['Labels'].values()) or not isinstance(host.get('RestartPolicy'),dict) or not isinstance(mounts,list) or any(not isinstance(m,dict) for m in mounts):
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        binding={'5244/tcp':[{'HostIp':'127.0.0.1','HostPort':'5245'}]}
        required_env=['TZ=Asia/Shanghai','BYOA_XIAOYA_BOOTSTRAP=true','BYOA_XIAOYA_UPDATE=if-newer','BYOA_XIAOYA_STRICT=false']
        if d.get('Name')!='/relay-panel-xiaoya-byoa' or not isinstance(d.get('Id'),str) or not d['Id'] or not isinstance(d.get('Image'),str) or not d['Image'] or d.get('State',{}).get('Running') is not True:
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        if config.get('Labels',{}).get('io.reality-panel.managed')!='xiaoya-byoa' or not all(value in config.get('Env',[]) for value in required_env):
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        if host.get('RestartPolicy',{}).get('Name')!='unless-stopped' or host.get('PortBindings')!=binding:
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        if len(mounts)!=1 or mounts[0].get('Source')!='/var/lib/relay-panel/xiaoya-byoa' or mounts[0].get('Destination')!='/opt/alist/data' or mounts[0].get('RW') is not True:
            raise Failure('STANDARD_FALLBACK_OWNERSHIP_REQUIRED')
        owners=self.listeners_5245()
        if any(owner!='docker-proxy' for owner in owners): raise Failure('FALLBACK_LISTENER_OWNERSHIP_REQUIRED')
        # Docker may publish through kernel NAT without userland proxy; exact
        # inspect binding + running ownership + health still provide positive evidence.
        self.fallback_health()
        return {'id':d['Id'],'image':d['Image'],'config_sha256':digest(json.dumps(config,sort_keys=True).encode()),
                'host_config_sha256':digest(json.dumps(host,sort_keys=True).encode()),'mounts':mounts}
    def detect_profile(self):
        marker=self.path('/etc/relay-panel/lite-mode')
        standard_marker=self.path('/var/lib/relay-panel/xiaoya-byoa-ownership.json')
        lite_conf=self.path('/etc/nginx/conf.d/relay-panel-lite-fallback.conf')
        lite_index=self.path('/var/www/fallback/index.html')
        if marker.exists():
            self.trusted_path('/etc/relay-panel/lite-mode')
            if marker.read_text().strip()!='lite' or standard_marker.exists() or self.path('/var/lib/relay-panel/xiaoya-byoa').exists():
                raise Failure('INSTALL_PROFILE_EVIDENCE_CONFLICT')
            self.trusted_path('/etc/nginx/conf.d/relay-panel-lite-fallback.conf')
            self.trusted_path('/var/www/fallback/index.html')
            self.lite_fallback_preflight()
            if not self.listeners_5245(): raise Failure('LITE_FALLBACK_PORT_CONFLICT')
            self.fallback_health()
            return 'lite'
        if lite_conf.exists() or lite_index.exists(): raise Failure('INSTALL_PROFILE_EVIDENCE_CONFLICT')
        self.standard_fallback() # Missing Lite marker does not imply Standard.
        return 'standard'
    def profile_postcheck(self, profile, work):
        if self.detect_profile()!=profile: raise Failure('INSTALL_PROFILE_CHANGED')
        snapshot=work/'standard-fallback.json'
        if profile=='standard':
            if not snapshot.is_file() or self.standard_fallback()!=json.loads(snapshot.read_text()):
                raise Failure('STANDARD_FALLBACK_CHANGED')
    def precheck(self, identity):
        if os.geteuid()!=0 or os.uname().machine!='x86_64': raise Failure('ROOT_AMD64_REQUIRED')
        for name in SNAPSHOT_PATHS: safe_path(self.path(name))
        self.generated_nginx_paths() # Validate ownership before stopping the old runtime.
        directories=set(OWNED_TREES+['/etc/nginx/relay-panel-stream.d','/etc/nginx/relay-panel-certs'])
        for name in SNAPSHOT_PATHS:
            if self.path(name).exists(): self.trusted_path(name,directory=name in directories)
        node=self.trusted_path('/opt/relay-node/relay-node')
        node_id=self.trusted_path('/opt/relay-node/node-id') # Identifier is not a credential; official historical files can be 0644.
        env=self.trusted_path('/etc/relay-node/relay-node.env',private=True)
        values=self.managed_environment(env)
        unit=self.trusted_path('/etc/systemd/system/relay-node.service')
        if not node.stat().st_mode & 0o100 or digest(node.read_bytes())!=OFFICIAL_SHA256: raise Failure('OFFICIAL_V130_BINARY_REQUIRED')
        if self.run([str(node),'--version']).stdout.decode().strip()!='relay-node 1.3.0': raise Failure('OFFICIAL_V130_VERSION_REQUIRED')
        local_id=node_id.read_text().strip()
        if not re.fullmatch('[A-Za-z0-9_-]{1,128}',local_id): raise Failure('INVALID_OLD_NODE_ID')
        if local_id!=identity['node_id']: raise Failure('OLD_NODE_ID_MISMATCH')
        marker=self.path('/etc/relay-panel/lite-mode')
        if marker.exists(): self.trusted_path('/etc/relay-panel/lite-mode')
        self.run(['systemctl','is-active','--quiet','relay-node.service'])
        release=dict(line.split('=',1) for line in self.path('/etc/os-release').read_text().splitlines() if '=' in line)
        if release.get('ID','').strip(chr(34))!='debian' or release.get('VERSION_ID','').strip(chr(34))!='12': raise Failure('SUPPORTED_DEBIAN_12_REQUIRED')
        for exe in ['bash','systemctl','busctl','ss','curl','tar','sha256sum','nginx','apt-get','sysctl']:
            if not shutil.which(exe): raise Failure('HOST_PREREQUISITE_MISSING')
        if self.managed_unit(unit):
            # Historical ordering alone is not Docker Nginx; require positive native evidence.
            if any(key not in values for key in ['NGINX_SNI_TEST_CMD','NGINX_SNI_RELOAD_CMD','NGINX_SNI_CONF_PATH']):
                raise Failure('HOST_NATIVE_NGINX_LAYOUT_REQUIRED')
        if shutil.disk_usage(self.root).free < 512*1024*1024: raise Failure('DISK_SPACE_REQUIRED')
        self.run(['nginx','-t'])
        profile=self.detect_profile()
        emit('PROVENANCE','OFFICIAL_V130_MANAGED')
        emit('PROFILE',profile.upper())
        # Files prove managed provenance, not an unknowable fresh/upgrade chronology.
        return profile
    def old_auth(self, identity):
        descriptor=self.path('/var/lib/relay-panel/node-claims/runtime-auth.json')
        if descriptor.exists():
            safe_path(descriptor);d=json.loads(descriptor.read_text())
            if str(d['identity_group_id'])!=str(identity['identity_group_id']) or d['node_id']!=identity['node_id']: raise Failure('OLD_AUTH_IDENTITY_MISMATCH')
            secret=self.path(d['secret_file']);safe_path(secret)
            return {'Authorization':'RelayNodeCredential '+secret.read_text().strip(), 'X-Node-Credential-ID':d['credential_id'],'X-Node-ID':identity['node_id'],'X-Config-Protocol-Version':'10'}
        import shlex
        lines=self.path('/etc/relay-node/relay-node.env').read_text().splitlines()
        values={}
        for line in lines:
            if '=' in line and not line.lstrip().startswith('#'):
                k,v=line.split('=',1);parts=shlex.split(v);values[k]=parts[0] if parts else ''
        if not values.get('NODE_TOKEN'): raise Failure('OLD_AUTH_UNAVAILABLE')
        return {'Authorization':'Bearer '+values['NODE_TOKEN'],'X-Node-ID':identity['node_id'],'X-Config-Protocol-Version':'10'}
    def capture(self, work):
        if not self.path('/etc/relay-panel/lite-mode').exists():
            private_json(work/'standard-fallback.json',self.standard_fallback())
        backup=work/'backup';backup.mkdir(mode=0o700,exist_ok=True)
        present=[]
        for index,name in enumerate(SNAPSHOT_PATHS):
            path=self.path(name);safe_path(path)
            target=backup/str(index)
            if target.exists(): remove_owned(target)
            if path.exists():
                present.append(index)
                if path.is_dir(): shutil.copytree(path,target,symlinks=True)
                else: shutil.copy2(path,target)
        kernel={}
        for key in ['net.ipv4.tcp_congestion_control','net.core.default_qdisc']:
            kernel[key]=self.run(['sysctl','-n',key]).stdout.decode().strip()
        private_json(work/'snapshot.json',{'present':present,'kernel':kernel})
    def stop_and_detach(self, work):
        self.run(['systemctl','stop','relay-node.service'])
        for name in OWNED_TREES: remove_owned(self.path(name))
        # These generated files describe the detached identity's old runtime.
        # The complete snapshot restores them on rollback; Bootstrap recreates
        # its initial fallback before new Memberships deliver business Rules.
        for name in ['/etc/relay-panel/camouflage-sites.json']+self.generated_nginx_paths():
            remove_owned(self.path(name))
        # Existing managed Nginx still references these same-host TLS assets.
        # Preserve certificates only; old identity, credentials and LKG stay detached.
        certificates=work/'backup/0/certificates'
        safe_path(certificates)
        if certificates.exists():
            destination=self.path('/opt/relay-node/certificates')
            destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            shutil.copytree(certificates,destination,symlinks=True)
        # Release old managed listeners before Bootstrap checks port ownership.
        self.run(['nginx','-t']);self.run(['systemctl','reload','nginx'])
    def install(self, work):
        prefix=['env','RELAY_NODE_PRESERVE_STANDARD_FALLBACK=1'] if (work/'standard-fallback.json').is_file() else []
        self.run(prefix+['bash',str(work/'bundle/relay-node-bootstrap.sh'),str(work/'bundle/config.env'),str(work/'bundle/relay-node-linux-amd64'),str(work/'bootstrap-transaction')])
    def rollback(self, work):
        self.run(['systemctl','stop','relay-node.service'],check=False)
        script=work/'bundle/relay-node-bootstrap.sh'
        if (work/'bootstrap-transaction/state').exists():
            self.run(['bash',str(script),'--rollback',str(work/'bootstrap-transaction')],check=False)
        present=json.loads((work/'snapshot.json').read_text())['present']
        for index,name in enumerate(SNAPSHOT_PATHS):
            path=self.path(name);safe_path(path);remove_owned(path)
            if index in present:
                path.parent.mkdir(parents=True,exist_ok=True)
                original=work/'backup'/str(index)
                if original.is_dir(): shutil.copytree(original,path,symlinks=True)
                else: shutil.copy2(original,path)
        for key,value in json.loads((work/'snapshot.json').read_text()).get('kernel',{}).items():
            self.run(['sysctl','-w',key+'='+value])
        self.run(['systemctl','daemon-reload'])
        self.run(['nginx','-t']);self.run(['systemctl','reload','nginx'])
        self.run(['systemctl','start','relay-node.service'])
        self.run(['systemctl','is-active','--quiet','relay-node.service'])
        self.profile_postcheck('lite' if self.path('/etc/relay-panel/lite-mode').exists() else 'standard',work)
    def complete(self, op, work):
        private_json(self.path('/opt/relay-node/legacy-v130-upgrade-completed.json'),{'operation_id':op['operation']['id'],'old_node_id':op['operation']['old']['node_id'],'new_node_id':op['operation']['new']['node_id']})
        remove_owned(work)
        if not any(work.parent.iterdir()): work.parent.rmdir()

class Runner:
    def __init__(self, client, host, identity, probes, work, timeout=180):
        self.client=client;self.host=host;self.identity=identity;self.probes=probes;self.work=work;self.timeout=timeout
        self.op=None;self.destructive=False;self.commit_unknown=False
    def phase(self, stage):
        private_json(self.work/'phase.json',{'phase':stage});emit(stage,'single Node only')
    def wait_action(self, action, transient):
        deadline=time.monotonic()+self.timeout
        while True:
            try: return self.client.action(self.op,action)
            except ApiFailure as e:
                if str(e) not in transient or time.monotonic()>=deadline: raise
                time.sleep(1)
    def prepare_bundle(self, data):
        bundle=self.work/'bundle';bundle.mkdir(mode=0o700)
        expected={'manifest.env','relay-node-bootstrap.sh','relay-node-linux-amd64','config.env'}
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members=archive.getmembers()
            if set(m.name for m in members)!=expected or len(members)!=4 or any(not m.isfile() for m in members): raise Failure('INVALID_BUNDLE')
            for member in members:
                path=bundle/member.name
                with path.open('wb') as out: out.write(archive.extractfile(member).read())
                path.chmod(0o700 if member.name in ['relay-node-bootstrap.sh','relay-node-linux-amd64'] else 0o600)
        manifest=dict(line.split('=',1) for line in (bundle/'manifest.env').read_text().splitlines() if '=' in line)
        for filename,field in [('relay-node-bootstrap.sh','BOOTSTRAP_SCRIPT_SHA256'),('relay-node-linux-amd64','ARTIFACT_SHA256'),('config.env','BOOTSTRAP_CONFIG_SHA256')]:
            if digest((bundle/filename).read_bytes())!=manifest.get(field): raise Failure('ARTIFACT_CHECKSUM_FAILURE')
        if manifest.get('ARCHITECTURE')!='amd64' or manifest.get('ENROLLMENT_ID')!=self.op['operation']['new']['node_id']: raise Failure('BUNDLE_IDENTITY_MISMATCH')
        profile=self.op['operation'].get('source_profile')
        config=read_environment(bundle/'config.env')
        if profile not in ['standard','lite'] or manifest.get('PROFILE')!=profile or config.get('LITE_MODE')!=('1' if profile=='lite' else '0'):
            raise Failure('BUNDLE_INSTALL_PROFILE_MISMATCH')
    def execute(self):
        self.phase('1/10 PRECHECK');profile=self.host.precheck(self.identity)
        capabilities=self.client.request('GET',BASE+'/capabilities')
        if capabilities.get('operation_protocol')!=1 or capabilities.get('official_amd64_sha256')!=OFFICIAL_SHA256: raise Failure('PANEL_MIGRATION_CAPABILITY_REQUIRED')
        self.client.request('GET','/node/config',headers=self.host.old_auth(self.identity))
        self.phase('2/10 SNAPSHOT')
        try: self.op=self.client.start(self.identity,self.probes,profile)
        except ApiFailure as e:
            if str(e)!='PANEL_UNAVAILABLE': raise
            recovered=self.client.request('GET','/admin'+BASE+'/current',token=self.client.admin)
            if recovered['operation']['old']!={'home_group_id':self.identity['identity_group_id'],'node_id':self.identity['node_id']} or recovered['operation']['state']!='PREPARED': raise Failure('START_RESULT_UNKNOWN_REQUIRES_ADMIN_RECOVERY')
            self.op=recovered
        if self.op['operation'].get('source_profile')!=profile: raise Failure('SOURCE_INSTALL_PROFILE_MISMATCH')
        private_json(self.work/'operation.json',self.op)
        self.phase('3/10 VERIFIED DOWNLOAD');self.prepare_bundle(self.client.bundle(self.op))
        if digest((self.work/'bundle/relay-node-linux-amd64').read_bytes())==OFFICIAL_SHA256: raise Failure('CURRENT_CANDIDATE_ARTIFACT_REQUIRED')
        verify_target_binary(self.host, self.work/'bundle/relay-node-linux-amd64')
        self.client.action(self.op,'preflight') # Real public forwarding before old service stop.
        self.host.capture(self.work)
        self.phase('4/10 STOP OLD');self.destructive=True;self.host.stop_and_detach(self.work)
        self.phase('5/10 INSTALL CURRENT');self.host.install(self.work)
        self.host.profile_postcheck(profile,self.work)
        self.phase('6/10 RESTORE MEMBERSHIPS')
        self.wait_action('restore',{'NODE_OFFLINE','NODE_STATUS_MISSING','NEW_CREDENTIAL_NOT_ACTIVE','PUBLIC_IPV4_NOT_REPORTED'})
        self.phase('7/10 WAIT CONFIG + LISTENERS + REAL FORWARDING')
        deadline=time.monotonic()+self.timeout
        while True:
            self.phase('8/10 FINALIZE DECISION');self.commit_unknown=True
            try:
                current=self.client.action(self.op,'finalize')
                if current['state']=='SUCCESS': break
            except ApiFailure as e:
                try: current=self.client.status(self.op)
                except ApiFailure: raise Failure('FINALIZE_RESULT_UNKNOWN_KEEP_NEW_RUNTIME') from None
                if current['state'] in ['COMMITTED','SUCCESS']:
                    if current['state']=='SUCCESS': break
                    if time.monotonic()>=deadline: raise Failure('COMMITTED_DNS_NEEDS_ATTENTION_KEEP_NEW_RUNTIME') from None
                    time.sleep(1);continue
                self.commit_unknown=False
                if str(e) not in {'NODE_OFFLINE','NODE_STATUS_MISSING','PUBLIC_IPV4_NOT_REPORTED','EFFECTIVE_CONFIG_NOT_CONVERGED','LISTENERS_NOT_READY','FORWARDING_PROBE_FAILED','FORWARDING_MARKER_MISMATCH'} or time.monotonic()>=deadline: raise
                time.sleep(1)
        self.phase('9/10 DNS READBACK VERIFIED');self.phase('10/10 SUCCESS')
        self.host.complete(self.op,self.work)
        emit('SUCCESS','Reality Node upgrade completed successfully.')
        print('Old Node: '+self.identity['node_id']+'\nNew Node: '+self.op['operation']['new']['node_id']+'\nMembership: MATCH\nRules: MATCH\nCarrier: MATCH\nDNS: MATCH\nListeners: MATCH\nForwarding: PASS',flush=True)
    def recover_failure(self):
        if self.commit_unknown:
            emit('NEEDS_ATTENTION','Upgrade requires manual attention. Do not upgrade another Node. Old Node restored: NO; New Node active: UNKNOWN; Carrier finalized: COMMITTED OR UNKNOWN. Finalize outcome is committed or unknown. Keep new runtime; never restore old identity. Protected recovery directory: '+str(self.work));return
        if self.destructive:
            self.phase('ROLLBACK');self.host.rollback(self.work)
        if self.op:
            self.client.action(self.op,'rollback-begin')
            self.wait_action('rollback',{'NODE_OFFLINE','NODE_STATUS_MISSING','OLD_RUNTIME_NOT_RECOVERED','FORWARDING_PROBE_FAILED','FORWARDING_MARKER_MISMATCH'})
        self.phase('ROLLED_BACK' if self.destructive else 'FAILED_PRECHECK')
        if self.destructive: emit('ROLLED_BACK','Upgrade failed, but the original v1.3.0 Node was restored successfully. No other Node was modified. Old Node restored: YES; New Node active: NO; Carrier finalized: NO.')
        # Failed attempts retain protected backup for explicit recovery; no automatic next Node.

def verify_target_binary(host, binary):
    if digest(binary.read_bytes()) != TARGET_SHA256:
        raise Failure('FIXED_V143_ARTIFACT_SHA256_REQUIRED')
    if host.run([str(binary),'--version']).stdout.decode().strip() != 'relay-node '+TARGET_VERSION:
        raise Failure('FIXED_V143_ARTIFACT_VERSION_REQUIRED')

def read_environment(p):
    import shlex
    safe_path(p)
    values={}
    for line in p.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1);parts=shlex.split(value)
            values[key]=parts[0] if parts else ''
    return values

def environment(host):
    return read_environment(host.path('/etc/relay-node/relay-node.env'))

def panel_url(host, explicit, recovery_work):
    if explicit: return explicit
    if recovery_work:
        # The old managed environment may already be detached. Its protected
        # snapshot exists before STOP and is independent of Bootstrap success.
        saved=recovery_work/'backup'/str(SNAPSHOT_PATHS.index('/etc/relay-node'))/'relay-node.env'
        safe_path(saved)
        if saved.exists():
            if saved.stat().st_uid!=os.geteuid() or saved.stat().st_mode & 0o077: raise Failure('PRIVATE_RECOVERY_FILE_REQUIRED')
            return read_environment(saved).get('PANEL_URL')
    current=host.path('/etc/relay-node/relay-node.env');safe_path(current)
    return read_environment(current).get('PANEL_URL') if current.exists() else None

def operator_identity(client, host, node_id):
    descriptor=host.path('/var/lib/relay-panel/node-claims/runtime-auth.json');safe_path(descriptor)
    if descriptor.exists():
        data=json.loads(descriptor.read_text())
        if data['node_id']!=node_id: raise Failure('OLD_AUTH_IDENTITY_MISMATCH')
        hint={'identity_group_id':int(data['identity_group_id']),'node_id':node_id}
    else:
        hint={'node_id':node_id}
    identity=client.request('GET',BASE+'/identity',headers=host.old_auth(hint))
    if identity.get('node_id')!=node_id or not isinstance(identity.get('identity_group_id'),int): raise Failure('OLD_AUTH_IDENTITY_MISMATCH')
    if 'identity_group_id' in hint and identity['identity_group_id']!=hint['identity_group_id']: raise Failure('OLD_AUTH_IDENTITY_MISMATCH')
    return identity

def readonly_panel_check(client, host, identity):
    caps=client.request('GET',BASE+'/capabilities')
    if caps.get('operation_protocol')!=1 or caps.get('official_amd64_sha256')!=OFFICIAL_SHA256 or caps.get('target_version')!=TARGET_VERSION or caps.get('profile_preserving') is not True or set(caps.get('supported_profiles',[]))!={'standard','lite'}:
        raise Failure('PANEL_V143_MIGRATION_CAPABILITY_REQUIRED')
    catalog=client.request('GET','/admin/node-artifacts',token=client.admin)
    if catalog.get('config_protocol_version')!=10: raise Failure('CONFIG_PROTOCOL_10_REQUIRED')
    artifacts=[a for a in catalog['artifacts'] if a['architecture']=='amd64' and a['available']]
    if len(artifacts)!=1 or artifacts[0].get('version')!=TARGET_VERSION or artifacts[0].get('sha256')!=TARGET_SHA256:
        raise Failure('FIXED_V143_ARTIFACT_METADATA_REQUIRED')
    try: current=client.request('GET','/admin'+BASE+'/current',token=client.admin)
    except ApiFailure as error:
        if str(error)!='MIGRATION_NOT_FOUND': raise
    else:
        if current['operation']['state'] not in ['SUCCESS','ROLLED_BACK','FAILED_PRECHECK']:
            raise Failure('MIGRATION_IN_PROGRESS')
    host.old_auth(identity) # Read private local auth only; no config delivery/revision write.

def tty_prompt(message):
    with open('/dev/tty','r+') as tty:
        tty.write(message);tty.flush();return tty.readline().strip()

def operator_probes(config):
    # The existing migration preflight validates every submitted Rule publicly.
    listeners={l['rule_id']:l for l in config['listeners']}
    probes=[]
    for rule_id,listener in sorted(listeners.items()):
        print('Rule %s, public port %s: enter a stable HTTP forwarding check.'%(rule_id,listener['port']),flush=True)
        path=tty_prompt('HTTP path [/]: ') or '/'
        marker=tty_prompt('Expected response marker (required): ')
        if not path.startswith('/') or not marker: raise Failure('FORWARDING_PROBE_REQUIRED')
        probes.append({'rule_id':rule_id,'path':path,'expected_marker':marker})
    return probes

def main():
    parser=argparse.ArgumentParser(description='Official Reality Node v1.3.0 -> fixed v1.4.3, this host only; never multiple Nodes at once')
    parser.add_argument('--version',action='version',version='Reality Node one-time upgrader 1.3.0 -> '+TARGET_VERSION)
    parser.add_argument('--panel','--panel-url',dest='panel_url',help='HTTPS Panel v1.4.3 URL; default: managed Node environment')
    parser.add_argument('--check',action='store_true',help='Read-only host and Panel check; no operation, stop, Membership or DNS mutation')
    parser.add_argument('--identity-group-id',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--node-id',help=argparse.SUPPRESS)
    parser.add_argument('--probe-file',help=argparse.SUPPRESS)
    parser.add_argument('--auth-fd',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--recover-work',type=pathlib.Path,help='Explicit protected recovery directory; queries durable state first')
    args=parser.parse_args();host=Host()
    if args.recover_work and args.check: raise Failure('CHECK_AND_RECOVERY_ARE_DISTINCT')
    if os.geteuid()!=0: raise Failure('ROOT_REQUIRED')
    if not args.recover_work:
        receipt=host.path('/opt/relay-node/legacy-v130-upgrade-completed.json');safe_path(receipt)
        if receipt.exists():
            emit('ALREADY_MIGRATED','This host has already completed the one-time migration. No other Node was modified.');return
    if args.recover_work:
        root=host.path('/var/lib/relay-panel/legacy-v130-upgrade');safe_path(args.recover_work)
        if args.recover_work.parent.resolve()!=root.resolve(): raise Failure('RECOVERY_DIRECTORY_OUT_OF_SCOPE')
        operation_path=args.recover_work/'operation.json';safe_path(operation_path)
        if operation_path.stat().st_uid!=0 or operation_path.stat().st_mode & 0o077: raise Failure('PRIVATE_RECOVERY_FILE_REQUIRED')
        operation=json.loads(operation_path.read_text());old=operation['operation']['old']
        args.identity_group_id=old['home_group_id'];args.node_id=old['node_id']
    else:
        node_id=host.path('/opt/relay-node/node-id');safe_path(node_id)
        args.node_id=args.node_id or node_id.read_text().strip()
        emit('1/10','Verifying official Reality Node v1.3.0')
        try: host.precheck({'node_id':args.node_id})
        except Failure:
            print('This upgrader only supports the official Reality Node v1.3.0 installation.',flush=True);raise
    args.panel_url=panel_url(host,args.panel_url,args.recover_work)
    if not args.panel_url: raise Failure('HTTPS_PANEL_REQUIRED')
    if args.recover_work:
        admin=None;probes=operation['operation']['probes']
    elif args.auth_fd is not None:
        secret=json.load(os.fdopen(args.auth_fd));admin=secret['admin_token'];probes=secret['probes']
    else:
        username=tty_prompt('Panel administrator username: ')
        password=getpass.getpass('Panel administrator password (not stored): ')
        client=Client(args.panel_url,None)
        admin=client.request('POST','/auth/login',{'username':username,'password':password})['token'];password=None
        probes=None
    client=Client(args.panel_url,admin)
    if not args.recover_work:
        identity=operator_identity(client,host,args.node_id)
        if args.identity_group_id is not None and args.identity_group_id!=identity['identity_group_id']: raise Failure('OLD_AUTH_IDENTITY_MISMATCH')
        args.identity_group_id=identity['identity_group_id']
        readonly_panel_check(client,host,identity)
        if args.check: emit('READY','Official v1.3.0 host and fixed v1.4.3 artifact checks passed. No migration was started.');return
        config=client.request('GET','/node/config',headers=host.old_auth(identity))
        if probes is None: probes=json.loads(pathlib.Path(args.probe_file).read_text()) if args.probe_file else operator_probes(config)
    else: identity={'identity_group_id':args.identity_group_id,'node_id':args.node_id}
    root=host.path('/var/lib/relay-panel/legacy-v130-upgrade');safe_path(root);root.mkdir(mode=0o700,parents=True,exist_ok=True);root.chmod(0o700)
    lock=os.open(root/'host.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise Failure('MIGRATION_IN_PROGRESS') from None
    work=args.recover_work or root/str(os.getpid())
    safe_path(work)
    if work.parent.resolve()!=root.resolve(): raise Failure('RECOVERY_DIRECTORY_OUT_OF_SCOPE')
    if not args.recover_work: work.mkdir(mode=0o700)
    runner=Runner(client,host,identity,probes,work)
    if args.recover_work: runner.commit_unknown=True
    def interrupted(signum,frame): raise Failure('INTERRUPTED')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        if args.recover_work:
            runner.op=json.loads((work/'operation.json').read_text())
            if runner.op['operation']['old']!={'home_group_id':args.identity_group_id,'node_id':args.node_id}: raise Failure('RECOVERY_IDENTITY_MISMATCH')
            current=client.status(runner.op) # Failure here keeps both host and operation untouched.
            if current['state'] in ['COMMITTED','SUCCESS']:
                if current['state']=='COMMITTED': client.action(runner.op,'finalize')
                host.complete(runner.op,work);emit('SUCCESS','Explicit committed-operation recovery completed. Stop here.')
            else:
                runner.commit_unknown=False
                runner.destructive=(work/'snapshot.json').exists()
                runner.recover_failure()
        else: runner.execute()
    except (Failure,OSError,ValueError,subprocess.SubprocessError) as failure:
        emit('FAILED',str(failure) if isinstance(failure,Failure) else type(failure).__name__)
        if runner.op: emit('OPERATION',runner.op['operation']['id']+'; phase='+json.loads((work/'phase.json').read_text()).get('phase','unknown')+'; committed/unknown='+str(runner.commit_unknown))
        try: runner.recover_failure()
        except (Failure,OSError,ValueError,subprocess.SubprocessError): emit('RECOVERY_REQUIRED','Upgrade requires manual attention. Do not upgrade another Node. Protected recovery directory: '+str(work))
        raise SystemExit(1)
    finally:
        os.close(lock)
        # Host-wide exclusion lasts for this invocation only. Failed backups are retained.
        with contextlib.suppress(FileNotFoundError): (root/'host.lock').unlink()
        with contextlib.suppress(OSError): root.rmdir()

if __name__=='__main__':
    try: main()
    except (Failure,OSError,ValueError,subprocess.SubprocessError) as failure:
        emit('FAILED',str(failure) if isinstance(failure,Failure) else type(failure).__name__)
        raise SystemExit(1)
PY
