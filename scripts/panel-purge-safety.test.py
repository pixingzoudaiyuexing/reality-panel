#!/usr/bin/env python3
"""Execute both existing uninstall entrypoints against private fixture roots."""
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parent.parent
PATHS = ['/opt/relay-panel', '/etc/relay-panel', '/var/lib/relay-panel', '/usr/local/lib/reality-panel', '/usr/local/sbin/reality-panel-update', '/etc/systemd/system/relay-panel.service']

for entry in ['install.sh', 'deploy.sh']:
    with tempfile.TemporaryDirectory(prefix='rp-purge-test-', dir=REPO) as temp:
        root = Path(temp)
        fake = root / 'bin'; fake.mkdir()
        log = root / 'commands'
        replacements = {p: str(root / p.lstrip('/')) for p in PATHS}
        source = (REPO / entry).read_text()
        for path, replacement in replacements.items(): source = source.replace(path, replacement)
        script = root / entry; script.write_text(source)
        commands = {
            'id': '[ "${1:-}" != -u ] || echo 0',
            'systemctl': 'echo "systemctl $*" >> "$HARNESS_LOG"; case "${1:-}" in is-active) exit 3;; disable) [ "${STOP_FAIL:-0}" != 1 ] || exit 1;; esac',
            'getent': 'case "$1" in passwd) [ -n "${ACCOUNT:-}" ] && [ ! -e "$HARNESS_USER_REMOVED" ] || exit 2; echo "$ACCOUNT";; group) [ "${GROUP_PRESENT:-0}" = 1 ] && [ ! -e "$HARNESS_GROUP_REMOVED" ] || exit 2; echo "relay-panel:x:999:";; esac',
            'userdel': 'echo "userdel $*" >> "$HARNESS_LOG"; [ "${USERDEL_FAIL:-0}" != 1 ] || exit 1; touch "$HARNESS_USER_REMOVED"; if [ "${USERDEL_REMOVES_GROUP:-0}" = 1 ]; then touch "$HARNESS_GROUP_REMOVED"; fi',
            'groupdel': 'echo "groupdel $*" >> "$HARNESS_LOG"; [ ! -e "$HARNESS_GROUP_REMOVED" ]',
        }
        for command, body in commands.items():
            path = fake / command; path.write_text('#!/usr/bin/env bash\n' + body + '\n'); path.chmod(0o755)
        env = dict(os.environ, PATH=str(fake) + ':' + os.environ['PATH'], HARNESS_LOG=str(log), HARNESS_GROUP_REMOVED=str(root / 'group-removed'), HARNESS_USER_REMOVED=str(root / 'user-removed'))
        def run(**extra):
            return subprocess.run(['bash', str(script), 'uninstall', '--yes', '--purge'], env=dict(env, **extra), text=True, capture_output=True)
        def seed(owned=True):
            (root / 'user-removed').unlink(missing_ok=True)
            for absolute in PATHS[:4]: Path(replacements[absolute]).mkdir(parents=True, exist_ok=True)
            for relative in ['relay-panel', 'certificates/cert', 'releases/.staging/temp', '.current.new.123']:
                path = Path(replacements[PATHS[0]]) / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('runtime')
            service = Path(replacements[PATHS[-1]]); service.parent.mkdir(parents=True, exist_ok=True)
            service.write_text('User=relay-panel\nExecStart=' + replacements[PATHS[0]] + '/current/relay-panel\n')
            Path(replacements[PATHS[2]], 'data.db').write_text('fixture database')
            if owned: Path(replacements[PATHS[1]], 'installer-account').write_text('999:999\n')
        foreign = root / 'foreign'; foreign.mkdir(); (foreign / 'keep').write_text('foreign')
        account = 'relay-panel:x:999:999::' + replacements[PATHS[2]] + ':/usr/sbin/nologin'
        seed()
        shortcut = Path(replacements['/usr/local/sbin/reality-panel-update'])
        shortcut.parent.mkdir(parents=True, exist_ok=True)
        shortcut.symlink_to(foreign / 'keep')
        result = run(ACCOUNT=account)
        assert result.returncode != 0 and shortcut.is_symlink() and (foreign / 'keep').exists()
        assert Path(replacements[PATHS[0]], 'relay-panel').exists()
        shortcut.unlink()
        # Real installer contract: absolute shortcut to the owned update script.
        update_script = Path(replacements['/usr/local/lib/reality-panel']) / 'update.sh'
        update_script.write_text('owned update helper')
        shortcut.symlink_to(update_script)
        result = run(ACCOUNT=account, STOP_FAIL='1')
        assert result.returncode != 0 and Path(replacements[PATHS[0]], 'relay-panel').exists(), result.stdout
        result = run(ACCOUNT=account, USERDEL_FAIL='1')
        assert result.returncode != 0 and Path(replacements[PATHS[1]], 'installer-account').exists()
        result = run(ACCOUNT=account)
        assert result.returncode == 0, result.stderr
        assert not any(Path(replacements[p]).exists() for p in PATHS[:4])
        assert not shortcut.exists() and not shortcut.is_symlink()
        assert 'userdel relay-panel' in log.read_text()
        assert (foreign / 'keep').read_text() == 'foreign'
        assert run().returncode == 0
        for auto_remove in ['0', '1']:
            log.write_text(''); seed()
            (root / 'group-removed').unlink(missing_ok=True)
            result = run(ACCOUNT=account, GROUP_PRESENT='1', USERDEL_REMOVES_GROUP=auto_remove)
            assert result.returncode == 0, result.stderr
            assert ('groupdel relay-panel' in log.read_text()) == (auto_remove == '0')
            assert not any(Path(replacements[p]).exists() for p in PATHS[:4])
        (root / 'group-removed').unlink(missing_ok=True)
        log.write_text(''); seed(owned=False)
        result = run(ACCOUNT='relay-panel:x:1001:1001::/home/admin:/bin/bash')
        assert result.returncode == 0 and 'userdel' not in log.read_text(), result.stderr
        install = Path(replacements[PATHS[0]])
        install.symlink_to(foreign)
        result = run()
        assert result.returncode != 0 and (foreign / 'keep').exists()
        print(entry + ': full purge / owned account / foreign account / failure / retry / idempotency / symlink preservation PASS')
