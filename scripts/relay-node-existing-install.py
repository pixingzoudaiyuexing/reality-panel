#!/usr/bin/env python3
"""Private SSH inspection. Never print credentials; verifier stays server-side.

The Panel converts these facts to a separate, allowlisted administrator DTO.
No writes or cleanup are performed here.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(os.environ.get('RP_INSPECT_ROOT', '/'))


def path(name):
    return ROOT / name.lstrip('/')


def regular(name, private=False):
    p = path(name)
    for ancestor in [p, *p.parents]:
        if ancestor == ROOT.parent:
            break
        if ancestor.is_symlink():
            raise ValueError('managed path contains a symlink')
    if not p.exists():
        return None
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid():
        raise ValueError('managed file ownership/type cannot be verified')
    if private and stat.S_IMODE(s.st_mode) & 0o077:
        raise ValueError('credential file is not private')
    if s.st_size > 65536:
        raise ValueError('managed metadata is too large')
    return p.read_text()


def inspect():
    facts = dict(node_id=None, version=None, profile=None, service_active=False,
                 panel_url=None, identity_group_id=None, credential_id=None,
                 credential_verifier=None, runtime_valid=False, state_phase=None,
                 residue_owned=False, ambiguity=None)
    try:
        facts['node_id'] = (regular('/opt/relay-node/node-id') or '').strip() or None
        env = regular('/etc/relay-node/relay-node.env', True) or regular('/etc/relay-panel/node.env', True) or ''
        values = {}
        for line in env.splitlines():
            key, sep, value = line.partition('=')
            if sep:
                values[key] = value.strip().strip('\"\'')
        facts['panel_url'] = values.get('PANEL_URL')
        lite_marker = regular('/etc/relay-panel/lite-mode')
        if lite_marker is not None and lite_marker.strip() != 'lite':
            raise ValueError('install profile marker is invalid')
        facts['profile'] = 'lite' if lite_marker is not None else 'standard'
        service = regular('/etc/systemd/system/relay-node.service')
        if service and 'ExecStart=/opt/relay-node/relay-node' not in service:
            raise ValueError('service is not the product-owned unit')
        facts['residue_owned'] = bool(service or env)
        if ROOT == Path('/'):
            result = subprocess.run(['systemctl', 'is-active', 'relay-node.service'], capture_output=True, text=True, timeout=10)
            facts['service_active'] = result.stdout.strip() == 'active'
            binary = path('/opt/relay-node/relay-node')
            if binary.is_symlink():
                raise ValueError('managed binary is a symlink')
            if binary.is_file():
                result = subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    raise ValueError('installed binary version cannot be verified')
                facts['version'] = result.stdout.strip()[:100]
        if path('/etc/systemd/system/relay-node-uninstall-finalizer.timer').exists() or path('/etc/systemd/system/relay-node-uninstall-finalizer.service').exists():
            raise ValueError('existing uninstall completion is still pending')
        raw = regular('/var/lib/relay-panel/node-claims/runtime-auth.json', True)
        if raw:
            descriptor = json.loads(raw)
            node = descriptor['node_id']
            group = descriptor['identity_group_id']
            credential = descriptor['credential_id']
            secret_path = descriptor['secret_file']
            if node != facts['node_id'] or not isinstance(group, int) or group <= 0:
                raise ValueError('runtime-auth points to another identity')
            secret_file = Path(secret_path)
            relative = secret_file.relative_to('/var/lib/relay-panel/node-claims')
            if len(relative.parts) != 2 or relative.name != 'node-credential.secret':
                raise ValueError('credential path is not exact product-owned storage')
            state = json.loads(regular(str(secret_file.parent / 'credential-pending.json'), True) or '{}')
            if (state.get('node_id'), state.get('home_group_id'), state.get('credential_id')) != (node, group, credential):
                raise ValueError('credential state conflicts with runtime-auth')
            facts.update(identity_group_id=group, credential_id=credential, state_phase=state.get('phase'))
            secret = (regular(secret_path, True) or '').strip()
            if not secret.startswith('rpn1_'):
                raise ValueError('credential material cannot be verified')
            data = base64.urlsafe_b64decode(secret[5:] + '=' * (-len(secret[5:]) % 4))
            if len(data) != 32:
                raise ValueError('credential material cannot be verified')
            c = credential.encode(); n = node.encode()
            digest = hashlib.sha256(b'relay-panel/node-credential/v1\0' + len(c).to_bytes(8, 'big') + c + group.to_bytes(8, 'big', signed=True) + len(n).to_bytes(8, 'big') + n + data)
            facts['credential_verifier'] = digest.hexdigest()
            facts['runtime_valid'] = state.get('phase') == 'ACTIVE_CONFIRMED'
        claims = path('/var/lib/relay-panel/node-claims')
        if claims.is_symlink():
            raise ValueError('credential storage is a symlink')
        if claims.exists():
            for candidate in claims.glob('*/credential-pending.json'):
                state = json.loads(regular('/' + str(candidate.relative_to(ROOT)), True) or '{}')
                if state.get('phase') == 'ACTIVE_CONFIRMED' and state.get('node_id') != facts['node_id']:
                    raise ValueError('another active identity shares this installation')
        if not facts['node_id'] and (raw or service or env):
            raise ValueError('product resources exist without a node identity')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not propagate exceptions containing metadata contents or secrets.
        allowed = {'install profile marker is invalid', 'managed path contains a symlink', 'managed file ownership/type cannot be verified', 'credential file is not private', 'managed metadata is too large', 'service is not the product-owned unit', 'managed binary is a symlink', 'installed binary version cannot be verified', 'runtime-auth points to another identity', 'credential path is not exact product-owned storage', 'credential state conflicts with runtime-auth', 'credential material cannot be verified', 'credential storage is a symlink', 'another active identity shares this installation', 'product resources exist without a node identity', 'existing uninstall completion is still pending'}
        facts['ambiguity'] = str(error) if str(error) in allowed else 'Local identity, authentication or managed metadata cannot be safely verified'
    return facts


if __name__ == '__main__':
    print(json.dumps(inspect()))
