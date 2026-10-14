#!/usr/bin/env python3
"""Limited failed-bootstrap residue cleanup; never executes a Node binary."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

NODE_FILES = ('relay-node', 'relay-node.new', 'relay-node.rollback', 'node-id',
              'node-id.tmp', 'node-id.rollback', 'config-cache.json',
              'config-cache.backup.json', 'config-cache.json.tmp',
              'provisioning-capabilities.json', 'nginx-sni-log.offset')
CLAIM_FILES = ('credential-pending.json', 'node-credential.secret', 'pool-claimant-nonce')
UNIT = '/etc/systemd/system/relay-node.service'
ENV = '/etc/relay-node/relay-node.env'
CLAIMS = '/var/lib/relay-panel/node-claims'


def valid_id(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def checked(root, name, directory=False):
    p = root / name.lstrip('/')
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError('out-of-scope path')
    if '..' in p.parts:
        raise ValueError('out-of-scope path')
    for parent in [p, *p.parents]:
        if parent == root.parent:
            break
        try:
            meta = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != os.geteuid():
            raise ValueError('symlink or resource ownership conflict')
        if parent != p and not stat.S_ISDIR(meta.st_mode):
            raise ValueError('invalid product path parent')
    if not p.exists():
        return p
    meta = p.lstat()
    if directory:
        if not stat.S_ISDIR(meta.st_mode) or (os.path.ismount(str(p)) and name not in ('/tmp', CLAIMS)):
            raise ValueError('invalid product directory')
    elif not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
        raise ValueError('invalid product file or hardlink')
    return p


def text(root, name):
    p = checked(root, name)
    if not p.exists():
        return ''
    if p.stat().st_size > 65536:
        raise ValueError('oversized managed metadata')
    return p.read_text()


def values(raw):
    return {k: v.strip().strip('"\'') for k, sep, v in
            (line.partition('=') for line in raw.splitlines()) if sep}


def json_hint(raw):
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def relative(root, p):
    return '/' + str(p.relative_to(root))


def process_identity(pid):
    try:
        args = Path('/proc/{}/cmdline'.format(pid)).read_bytes().split(b'\0')[:-1]
        start = Path('/proc/{}/stat'.format(pid)).read_text().rsplit(')', 1)[1].split()[19]
        return args, start
    except FileNotFoundError:
        return [], None


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def owned_unit(raw):
    allowed = {
        'Unit': {'Description', 'After', 'Wants'},
        'Service': {'Type', 'RuntimeDirectory', 'RuntimeDirectoryMode', 'EnvironmentFile',
                    'WorkingDirectory', 'ExecStart', 'Restart', 'RestartSec', 'LimitNOFILE'},
        'Install': {'WantedBy'},
    }
    section = None
    entries = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.endswith('\\'):
            raise ValueError('continued service directives are protected')
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            if section not in allowed:
                raise ValueError('unknown service section is protected')
            continue
        key, sep, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not sep or key not in allowed.get(section, set()) or (section, key) in entries:
            raise ValueError('custom or duplicate service directives are protected')
        entries[section, key] = value
    expected = {('Unit', 'Description'): 'Reality Panel relay-node',
                ('Service', 'EnvironmentFile'): ENV,
                ('Service', 'WorkingDirectory'): '/opt/relay-node',
                ('Service', 'ExecStart'): '/opt/relay-node/relay-node'}
    if any(entries.get(key) != value for key, value in expected.items()):
        raise ValueError('relay-node unit is not product-owned')


def plan(root):
    root = Path(root)
    removals = []
    ids = set()
    failed_ids = set()
    installers = []
    node = text(root, '/opt/relay-node/node-id').strip()
    env = values(text(root, ENV))
    unit = text(root, UNIT)
    if valid_id(node):
        ids.add(node)
    if unit:
        owned_unit(unit)
    dropins = checked(root, UNIT + '.d', directory=True)
    if dropins.exists() and any(dropins.iterdir()):
        raise ValueError('service overrides are protected')
    for key, allowed in {'NGINX_SNI_CONF_PATH': '/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf',
                         'CAMOUFLAGE_SITES_STATE_DIR': '/opt/relay-node/camouflage-sites',
                         'CERTIFICATE_STATE_DIR': '/opt/relay-node/certificates'}.items():
        if key in env and env[key] != allowed:
            raise ValueError('custom managed paths are protected')
    # Only the exact local candidate's files, never the shared claim root.
    descriptor = json_hint(text(root, CLAIMS + '/runtime-auth.json'))
    descriptor_id = descriptor.get('node_id')
    if descriptor_id and node and descriptor_id != node:
        raise ValueError('another runtime identity is protected')
    if descriptor.get('secret_file'):
        secret = descriptor['secret_file']
        expected = CLAIMS + '/' + str(descriptor_id) + '/node-credential.secret'
        if not valid_id(descriptor_id) or secret != expected:
            raise ValueError('credential path is outside the candidate')
        checked(root, secret)
    claims = checked(root, CLAIMS, directory=True)
    if claims.exists():
        for entry in claims.iterdir():
            if entry.name in ('runtime-auth.json', 'migration.lock'):
                checked(root, relative(root, entry))
                continue
            if not valid_id(entry.name):
                continue
            checked(root, relative(root, entry), directory=True)
            hint = json_hint(text(root, relative(root, entry / 'credential-pending.json')))
            if hint.get('node_id') not in (None, entry.name):
                raise ValueError('claim metadata points to another identity')
            if hint.get('phase') == 'ACTIVE_CONFIRMED' and entry.name != node:
                raise ValueError('another active local identity is protected')
    tmp = checked(root, '/tmp', directory=True)
    if tmp.exists():
        for d in sorted(tmp.glob('relay-panel-bootstrap-*')):
            task = d.name[len('relay-panel-bootstrap-'):]
            if not valid_id(task):
                continue
            checked(root, relative(root, d), directory=True)
            script = text(root, relative(root, d / 'bootstrap.sh'))
            config = values(text(root, relative(root, d / 'config.env')))
            candidate = config.get('POOL_NODE_ID', '')
            if not valid_id(candidate) or (node and candidate != node):
                continue  # A different install's transaction is not this retry's authority.
            if not script.startswith('#!/usr/bin/env bash\n# RelayPanel Stage 1 bootstrap.'):
                raise ValueError('bootstrap residue script is not product-owned')
            state = text(root, relative(root, d / 'transaction/state')).strip()
            if state not in ('', 'pending', 'rolled_back'):
                raise ValueError('committed installation is protected')
            ids.add(candidate)
            failed_ids.add(candidate)
            # Snapshot transaction directories only after validating every entry;
            # names are closed over the shipped bootstrap transaction contract.
            for folder, _, filenames in os.walk(str(d), followlinks=False):
                current = Path(folder)
                checked(root, relative(root, current), directory=True)
                for child in current.iterdir():
                    checked(root, relative(root, child), directory=child.is_dir())
                for name in filenames:
                    p = current / name
                    parent = p.parent.relative_to(d)
                    if parent == Path('.'):
                        owned = name in ('bootstrap.sh', 'config.env', 'relay-node-linux-amd64', 'relay-node-linux-arm64')
                    elif parent == Path('transaction'):
                        owned = name in ('state', 'pool-bootstrap.conf', 'sni.path', 'wrapper.path', 'http01.path') or bool(re.fullmatch(r'[a-z_][a-z0-9_-]*\.(state|dir-state|link-state|link-target|sha256|active|enabled)', name))
                    elif parent == Path('transaction/lock'):
                        owned = name == 'pid'
                    elif parent == Path('transaction/candidate'):
                        owned = name in ('pool-secret', 'migrate.py', 'relay-node.service')
                    elif parent == Path('transaction/files'):
                        owned = name in ('pool_node_id', 'pool_runtime_auth', 'binary', 'env', 'unit', 'nginx_conf', 'stream_root', 'sni_conf', 'wrapper_conf', 'http01_conf', 'fallback_cert', 'fallback_key', 'capabilities', 'lite_marker', 'lite_fallback_index', 'lite_fallback_conf')
                    else:
                        owned = False
                    if not owned:
                        raise ValueError('unknown bootstrap residue is protected')
                    removals.append(relative(root, p))
            pid_text = text(root, relative(root, d / 'transaction/lock/pid')).strip()
            if root == Path('/') and pid_text.isdigit():
                pid = int(pid_text)
                argv, start = process_identity(pid)
                if argv:
                    expected = [str(d / 'bootstrap.sh').encode(), str(d / 'config.env').encode()]
                    artifacts = [str(d / name).encode() for name in ('relay-node-linux-amd64', 'relay-node-linux-arm64')]
                    if len(argv) != 5 or Path(os.fsdecode(argv[0])).name != 'bash' or argv[1:3] != expected or argv[3] not in artifacts or argv[-1] != str(d / 'transaction').encode() or os.getpgid(pid) != pid:
                        raise ValueError('installer process ownership conflict')
                    installers.append((pid, argv, start))
    if descriptor_id and not node and descriptor_id not in failed_ids:
        raise ValueError('descriptor alone cannot authorize another identity cleanup')
    if len(ids) > 1:
        raise ValueError('multiple local installation identities are protected')
    if node and not valid_id(node) and not unit and 'PANEL_URL' not in env and not failed_ids:
        raise ValueError('invalid identity without product ownership evidence')
    if valid_id(node) or unit or 'PANEL_URL' in env or failed_ids:
        for name in NODE_FILES:
            p = checked(root, '/opt/relay-node/' + name)
            if p.exists():
                removals.append(relative(root, p))
        for name in (ENV, ENV + '.new', ENV + '.rollback', UNIT,
                     '/etc/relay-panel/lite-mode'):
            p = checked(root, name)
            if p.exists():
                removals.append(name)
        if descriptor_id or text(root, CLAIMS + '/runtime-auth.json'):
            removals.append(CLAIMS + '/runtime-auth.json')
        for candidate in ids:
            directory = checked(root, CLAIMS + '/' + candidate, directory=True)
            if directory.exists():
                for p in directory.iterdir():
                    name = p.name
                    if name not in CLAIM_FILES and not re.fullmatch(r'\.(credential-pending\.json|node-credential\.secret|pool-claimant-nonce)\.[0-9]+\.[0-9a-f]{16}', name):
                        raise ValueError('unknown candidate claim files are protected')
                    checked(root, relative(root, p))
                    removals.append(relative(root, p))
    # Panel checks active candidates against pending-transaction or exact failed-task
    # evidence. Credential validity is not a prerequisite for this filesystem plan.
    # Keep product/identity evidence until other files are gone, so a disconnect
    # midway through cleanup does not strand an unverifiable binary-only residue.
    def removal_order(name):
        proof = {'/opt/relay-node/node-id': 2, UNIT: 3, ENV: 4}
        return (proof.get(name, 1 if name.endswith(('/config.env', '/bootstrap.sh')) else 0), name)
    removals = sorted(set(removals), key=removal_order)
    snapshots = []
    for name in removals:
        p = checked(root, name)
        if p.exists():
            m = p.lstat()
            snapshots.append((name, m.st_ino, m.st_size, m.st_mtime_ns, file_hash(p)))
    snapshot = hashlib.sha256(json.dumps(snapshots, separators=(',', ':')).encode()).hexdigest()
    return dict(paths=removals, node_ids=sorted(ids), failed_ids=sorted(failed_ids),
                installers=installers, guards={row[0]: row[1:] for row in snapshots}, snapshot=snapshot, residue=bool(removals))


def inspection(root):
    try:
        p = plan(root)
        return dict(retry_snapshot=p['snapshot'] if p['residue'] else None,
                    retry_node_ids=p['node_ids'], retry_failed_ids=p['failed_ids'], retry_blocker=None)
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError):
        # Neither exceptions nor file contents are returned to the admin DTO.
        return dict(retry_snapshot=None, retry_node_ids=[], retry_failed_ids=[],
                    retry_blocker='产品路径、资源归属或正在使用的身份无法安全清理')


def validate_loaded_service(unit_exists):
    loaded = subprocess.check_output(['systemctl', 'show', '--property=FragmentPath', '--value', 'relay-node.service'], timeout=10, text=True).strip()
    dropins = subprocess.check_output(['systemctl', 'show', '--property=DropInPaths', '--value', 'relay-node.service'], timeout=10, text=True).strip()
    if dropins:
        raise ValueError('effective service overrides are protected')
    if not unit_exists and loaded == UNIT:
        # A prior interrupted cleanup may already have unlinked our unit.
        # Refresh systemd's cache, then require no loaded replacement; never
        # stop a cached service whose file/ownership can no longer be verified.
        subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=20)
        loaded = subprocess.check_output(['systemctl', 'show', '--property=FragmentPath', '--value', 'relay-node.service'], timeout=10, text=True).strip()
        dropins = subprocess.check_output(['systemctl', 'show', '--property=DropInPaths', '--value', 'relay-node.service'], timeout=10, text=True).strip()
        if loaded or dropins:
            raise ValueError('replacement service is protected')
    if loaded and (not unit_exists or loaded != UNIT):
        raise ValueError('loaded service is not the owned unit')


def cleanup(root, phase, expected_snapshot):
    root = Path(root)
    if phase not in ('check', 'stop', 'clean'):
        raise ValueError('invalid retry cleanup phase')
    lock_path = checked(root, CLAIMS + '/migration.lock')
    lock = None
    if lock_path.exists():
        m = lock_path.stat()
        if m.st_size or stat.S_IMODE(m.st_mode) != 0o600:
            raise ValueError('migration lock ownership conflict')
        lock = os.open(str(lock_path), os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        p = plan(root)
        if p['snapshot'] != expected_snapshot:
            raise ValueError('failed residue changed; inspect and confirm again')
        if phase == 'check':
            return
        if root == Path('/'):
            if os.geteuid() != 0:
                raise ValueError('root required')
            unit = checked(root, UNIT)
            validate_loaded_service(unit.exists())
            if unit.exists():
                subprocess.run(['systemctl', 'stop', 'relay-node.service'], check=True, timeout=20)
            for pid, argv, start in p['installers']:
                if process_identity(pid) == (argv, start) and os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 5
                    while process_identity(pid) == (argv, start) and time.monotonic() < deadline:
                        time.sleep(.1)
                    if process_identity(pid) == (argv, start) and os.getpgid(pid) == pid:
                        os.killpg(pid, signal.SIGKILL)
        if phase == 'stop':
            return
        # Revalidate after service/installer stop; output mutation changes require a new confirmation.
        if plan(root)['snapshot'] != expected_snapshot:
            raise ValueError('installer changed residue while stopping; inspect and retry')
        for name in p['paths']:
            file = checked(root, name)
            if file.exists():
                meta = file.lstat()
                current = (meta.st_ino, meta.st_size, meta.st_mtime_ns, file_hash(file))
                if current != p['guards'].get(name):
                    raise ValueError('candidate file changed during cleanup')
                file.unlink()
        for name in ('/opt/relay-node', '/etc/relay-node') + tuple(CLAIMS + '/' + n for n in p['node_ids']):
            directory = checked(root, name, directory=True)
            if directory.exists() and not any(directory.iterdir()):
                directory.rmdir()
        if root == Path('/'):
            subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=20)
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == '__main__':
    try:
        cleanup(Path(os.environ.get('RP_INSPECT_ROOT', '/')), sys.argv[1], sys.argv[2])
        print('FAILED_INSTALL_RESIDUE_CLEANUP_OK')
    except Exception:
        print('FAILED_INSTALL_RESIDUE_CLEANUP_BLOCKED: 检查路径归属或残留已改变，请重新检测并确认', file=sys.stderr)
        sys.exit(1)
