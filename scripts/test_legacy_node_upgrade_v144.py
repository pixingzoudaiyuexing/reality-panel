"""R2 start-response recovery regressions; test credentials/hosts only."""
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name('reality-node-v1.3.0-to-v1.4.4.sh')
runner = types.ModuleType('r2_runner')
exec(compile(SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0], str(SCRIPT), 'exec'), runner.__dict__)
spec = importlib.util.spec_from_file_location('v143_fixtures', SCRIPT.with_name('test_legacy_node_upgrade_v143.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
fixtures.module = runner
IDENTITY = {'identity_group_id': 7, 'node_id': 'old-test-node'}
OP_ID = 'b81a5dc0-0b49-47da-ad40-9c51f862531a'


class Clock:
    def __init__(self): self.now = 0.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


class RecoverClient(fixtures.Client):
    def __init__(self, clock, states=None, lost=True, delay=61):
        super().__init__()
        self.clock = clock
        self.states = iter(states or ['PRECHECK', 'PREPARED'])
        self.state = 'PRECHECK' if lost else 'PREPARED'
        self.lost = lost
        self.delay = delay
        self.admin = 'test-only-admin'
        self.profile = 'standard'
        self.work = None
        self.current_fault = None
        self.poll_fault = None
        self.target_version = '1.4.4'
        self.previous = None
        self.unavailable_polls = 0
        self.lost_category = 'PANEL_UNAVAILABLE'
        self.poll_count = 0
    def operation(self):
        return {'id': OP_ID, 'state': self.state, 'old': {'home_group_id': 7, 'node_id': IDENTITY['node_id']},
                'new': {'home_group_id': 8, 'node_id': 'new'},
                'source_profile': self.profile, 'memberships': [7], 'probes': []}
    def current(self):
        value = {'operation': self.operation(), 'migration_token': 'test-only-operation-auth'}
        if self.current_fault: self.current_fault(value)
        return value
    def start(self, identity, probes, profile):
        self.events.append('start')
        self.clock.now += self.delay if self.lost else 0
        if self.lost: raise runner.ApiFailure(self.lost_category)
        return self.current()
    def request(self, method, route, **kw):
        if route.endswith('/capabilities'):
            return {'operation_protocol': 1, 'official_amd64_sha256': runner.OFFICIAL_SHA256,
                    'target_version': self.target_version}
        if route.endswith('/current'):
            self.events.append('current')
            if 'start' not in self.events:
                if self.previous is not None: return self.previous
                raise runner.ApiFailure('MIGRATION_NOT_FOUND')
            return self.current()
        return super().request(method, route, **kw)
    def status(self, op, **kw):
        self.poll_count += 1
        self.events.append('poll')
        assert json.loads((self.work/'operation.json').read_text())['operation']['id'] == OP_ID
        assert (self.work/'operation.json').stat().st_mode & 0o777 == 0o600
        if self.unavailable_polls:
            self.unavailable_polls -= 1
            raise runner.ApiFailure('PANEL_UNAVAILABLE')
        self.state = next(self.states, self.state)
        value = self.operation()
        if self.poll_fault: self.poll_fault(value)
        return value
    def action(self, op, action):
        if action == 'preflight':
            assert self.state == 'PREPARED'
            self.events.append('prepared-preflight')
        return super().action(op, action)


class StartRecovery(unittest.TestCase):
    def execute(self, client, budget=300):
        host = fixtures.Host()
        host.profile = 'standard'
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as directory:
            work = pathlib.Path(directory)
            client.work = work
            subject = runner.Runner(client, host, IDENTITY, [], work)
            subject.start_timeout = budget
            with patch.object(runner, 'emit'), patch.object(runner, 'time', client.clock), \
                 patch.object(runner, 'TARGET_SHA256', __import__('hashlib').sha256(b'candidate').hexdigest()):
                subject.execute()
            self.assertEqual(client.events.count('start'), 1)
            self.assertIn('stop', host.events)
            self.assertIn('prepared-preflight', client.events)
            self.assertEqual(client.state, 'SUCCESS')
        return host, client
    def test_durable_precheck_after_sixty_seconds_is_resumed_with_one_start(self):
        client = RecoverClient(Clock())
        self.execute(client)
        self.assertGreaterEqual(client.clock.now, 61)
        self.assertGreaterEqual(client.poll_count, 1)
    def test_lost_start_metadata_is_saved_before_poll(self):
        self.execute(RecoverClient(Clock(), delay=0))
    def test_stop_old_only_after_prepared(self):
        self.execute(RecoverClient(Clock(), ['PRECHECK', 'PRECHECK', 'PREPARED']))

    def failed(self, client, category, budget=300, metadata=True):
        host = fixtures.Host();host.profile = 'standard'
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as directory:
            work = pathlib.Path(directory);client.work = work
            subject = runner.Runner(client, host, IDENTITY, [], work)
            subject.start_timeout = budget
            with patch.object(runner, 'emit') as output, patch.object(runner, 'time', client.clock):
                with self.assertRaisesRegex(runner.Failure, category): subject.execute()
                subject.recover_failure()
            self.assertNotIn('stop', host.events)
            self.assertNotIn('host-rollback', host.events)
            self.assertNotIn('rollback-begin', client.events)
            self.assertLessEqual(client.events.count('start'), 1)
            self.assertEqual((work/'operation.json').exists(), metadata)
            if metadata:
                saved = json.loads((work/'operation.json').read_text())
                self.assertEqual(saved['operation']['id'], OP_ID)
                self.assertEqual(saved['recovery']['target_version'], '1.4.4')
                self.assertEqual(saved['recovery']['target_sha256'], runner.TARGET_SHA256)
                self.assertEqual(work.joinpath('operation.json').stat().st_mode & 0o777, 0o600)
                self.assertIn(OP_ID, ' '.join(str(call) for call in output.call_args_list))
        return host, client
    def test_normal_start_keeps_original_prepared_flow(self):
        client = RecoverClient(Clock(), lost=False)
        self.execute(client)
        self.assertEqual(client.poll_count, 0)
    def test_precheck_failed_exits_without_stop_or_second_start(self):
        self.failed(RecoverClient(Clock(), ['FAILED_PRECHECK']), 'START_OPERATION_TERMINAL_FAILED_PRECHECK')
    def test_rolled_back_exits_without_stop(self):
        self.failed(RecoverClient(Clock(), ['ROLLED_BACK']), 'START_OPERATION_TERMINAL_ROLLED_BACK')
    def test_budget_includes_initial_sixty_second_wait(self):
        client = RecoverClient(Clock(), ['PRECHECK'], delay=61)
        self.failed(client, 'START_WAIT_TIMEOUT_PRECHECK_REQUIRES_RECOVERY', budget=65)
        self.assertEqual(client.clock.now, 65)
    def test_lost_response_immediately_prepared_is_resumed(self):
        client = RecoverClient(Clock(), delay=0)
        original = client.start
        def prepared(*args):
            try: original(*args)
            finally: client.state = 'PREPARED'
        client.start = prepared
        self.execute(client)
        self.assertEqual(client.poll_count, 0)
    def test_poll_transport_failure_is_bounded_and_not_reposted(self):
        client = RecoverClient(Clock());client.unavailable_polls = 2
        self.execute(client)
    def test_reject_wrong_identity_group_node_and_profile(self):
        for field, value in [('group', 70), ('node', 'other-node'), ('profile', 'lite')]:
            with self.subTest(field=field):
                client = RecoverClient(Clock())
                def mutate(data):
                    op = data['operation']
                    if field == 'group': op['old']['home_group_id'] = value
                    elif field == 'node': op['old']['node_id'] = value
                    else: op['source_profile'] = value
                client.current_fault = mutate
                self.failed(client, 'START_OPERATION_IDENTITY_OR_PROFILE_MISMATCH', metadata=False)
    def test_reject_wrong_target_version_before_start(self):
        client = RecoverClient(Clock());client.target_version = '1.4.5'
        self.failed(client, 'PANEL_MIGRATION_CAPABILITY_REQUIRED', metadata=False)
        self.assertNotIn('start', client.events)
    def test_never_adopt_previous_terminal_attempt(self):
        client = RecoverClient(Clock())
        client.previous = client.current();client.previous['operation']['state'] = 'ROLLED_BACK'
        self.failed(client, 'START_OPERATION_NOT_THIS_ATTEMPT', metadata=False)
    def test_reject_poll_changed_operation_id_or_new_identity(self):
        for field in ['id', 'new']:
            with self.subTest(field=field):
                client = RecoverClient(Clock())
                def mutate(op):
                    if field == 'id': op['id'] = '7d4f6321-9a4c-47fa-9668-819f987ee109'
                    else: op['new']['node_id'] = 'different-new'
                client.poll_fault = mutate
                self.failed(client, 'START_OPERATION_CHANGED')
    def test_unexpected_committed_state_never_rolls_back(self):
        self.failed(RecoverClient(Clock(), ['COMMITTED']), 'START_OPERATION_UNEXPECTED_STATE')
    def test_auth_failure_does_not_trigger_start_retry(self):
        client = RecoverClient(Clock());client.lost_category = 'HTTP_401'
        self.failed(client, 'HTTP_401', metadata=False)
    def test_lite_existing_profile_support_is_preserved(self):
        client = RecoverClient(Clock());client.profile = 'lite'
        with tempfile.TemporaryDirectory(dir=pathlib.Path(tempfile.gettempdir()).resolve()) as directory:
            client.work = pathlib.Path(directory)
            subject = runner.Runner(client, fixtures.Host(), IDENTITY, [], client.work)
            with patch.object(runner, 'emit'), patch.object(runner, 'time', client.clock):
                subject.start_operation('lite')
            self.assertEqual(subject.op['operation']['source_profile'], 'lite')
            self.assertEqual(client.events.count('start'), 1)
    def test_start_current_response_temporarily_unavailable_is_bounded(self):
        client = RecoverClient(Clock(), delay=61)
        original = client.request
        def missing(method, route, **kw):
            if route.endswith('/current') and 'start' in client.events:
                raise runner.ApiFailure('MIGRATION_NOT_FOUND')
            return original(method, route, **kw)
        client.request = missing
        self.failed(client, 'START_WAIT_TIMEOUT_OPERATION_UNKNOWN_NO_RETRY', budget=65, metadata=False)
        self.assertEqual(client.clock.now, 65)


profile_spec = importlib.util.spec_from_file_location('v144_profiles', SCRIPT.with_name('test_legacy_node_upgrade_profiles.py'))
profiles = importlib.util.module_from_spec(profile_spec)
profile_spec.loader.exec_module(profiles)
profiles.module = runner
class V144ProfileContract(profiles.LayoutTests):
    pass

if __name__ == '__main__':
    unittest.main()
