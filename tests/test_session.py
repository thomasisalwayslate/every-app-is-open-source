"""Exercise the real spawned worker, including pending work and disconnection."""
import io
import fcntl
import json
import multiprocessing
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from eaos.backend import Backend
from eaos.cli import serve
from eaos.session import AnalysisUnavailable, McpSession


class JsonOnlyInt(int):
    def __reduce__(self):
        raise TypeError('Native wrapper cannot be unpickled outside its runtime')


class ControlledBackend(Backend):
    def __init__(self, target, started, release, fail=False):
        super().__init__(target)
        self.started_event, self.release_event, self.fail = started, release, fail

    def _load(self):
        self._report_stage('analyzing')
        self.started_event.set()
        self.release_event.wait()
        if self.fail:
            raise RuntimeError('controlled analysis failure')
        self._report_stage('saving')

    def open_program(self, full=False):
        return self.result('open_program', 'computed', {
            'sha256': self.digest, 'captured': self.snapshot.read_text(),
            'analysis_count': 1})

    def search(self, **arguments):
        return self.result('search', 'computed', {'items': ['ready']})

    def read_memory(self, address):
        return self.result('read_memory', 'fact', {'length': JsonOnlyInt(16)})


class LockingBackend(Backend):
    """Use the real cross-process lock without starting Java."""

    def _load_project(self):
        self._report_stage('analyzing')

    def open_program(self, full=False):
        return self.result('open_program', 'computed', {'sha256': self.digest})


class Sessions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        target = Path(self.temporary.name) / 'selected'
        target.write_text('original input')
        context = multiprocessing.get_context('spawn')
        self.started, self.release = context.Event(), context.Event()
        self.backend = ControlledBackend(str(target), self.started, self.release)
        self.session = McpSession(self.backend, initial_wait=0.02)
        self.addCleanup(self.session.close)

    def ready(self):
        self.release.set()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = self.session.call('open_program', {})
            if 'analysis' not in value['data']:
                return value
            time.sleep(0.02)
        self.fail('worker never became ready')

    def test_pending_status_ping_and_calculation_stay_responsive(self):
        pending = self.session.call('open_program', {})
        self.assertEqual(pending['data']['analysis']['state'], 'running')
        self.assertNotIn('evidence', pending)
        self.assertTrue(self.started.wait(10))
        start = time.monotonic()
        status = self.session.call('open_program', {})['data']['analysis']
        self.assertEqual(status['stage'], 'analyzing')
        self.assertTrue(status['worker_alive'])
        self.assertLess(time.monotonic() - start, 0.5)
        requests = [{'id': 1, 'method': 'ping'}, {'id': 2, 'method': 'tools/list'},
                    {'id': 3, 'method': 'tools/call', 'params': {'name': 'search'}}]
        with patch('sys.stdin', io.StringIO('\n'.join(map(json.dumps, requests)))), patch('sys.stdout', io.StringIO()) as output:
            serve(self.session)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[0]['result'], {})
        self.assertEqual(len(responses[1]['result']['tools']), 7)
        failure = responses[2]['result']
        self.assertTrue(failure['isError'])
        self.assertEqual(json.loads(failure['content'][0]['text'])['analysis']['state'], 'running')
        self.assertEqual(self.session.call('calculate', {'expression': '6*7'})['data']['value'], '42')
        with self.assertRaises(AnalysisUnavailable) as failure:
            self.session.call('search', {})
        self.assertEqual(failure.exception.status['state'], 'running')
        opened = self.ready()
        evidence = self.session.call('read_evidence', {'id': opened['evidence']['id']})
        self.assertIn(self.backend.digest, evidence['text'])
        self.assertEqual(self.session.call('search', {})['data']['items'], ['ready'])

    def test_spawn_does_not_recapture_replaced_input_and_reuses_worker(self):
        self.backend.target.write_text('replacement')
        self.session.call('open_program', {})
        process_id = self.session.process.pid
        opened = self.ready()
        self.assertEqual(opened['data']['captured'], 'original input')
        self.assertEqual(self.session.call('open_program', {})['data']['analysis_count'], 1)
        self.assertEqual(self.session.process.pid, process_id)

    def test_bad_arguments_do_not_start_native_work(self):
        with self.assertRaises(ValueError):
            self.session.call('open_program', {'full': 'false'})
        self.assertIsNone(self.session.process)

    def test_native_style_values_cross_transport_as_json(self):
        self.session.call('open_program', {})
        self.ready()
        result = self.session.call('read_memory', {'address': '1000'})
        self.assertEqual(result['data']['length'], 16)
        self.assertIs(type(result['data']['length']), int)

    def test_failure_is_reported_and_does_not_restart_on_status_checks(self):
        self.backend.fail = True
        self.session.call('open_program', {})
        self.assertTrue(self.started.wait(10))
        self.release.set()
        deadline = time.monotonic() + 10
        while self.session.status()['state'] != 'failed' and time.monotonic() < deadline:
            time.sleep(0.02)
        process_id = self.session.process.pid
        for _ in range(2):
            with self.assertRaisesRegex(AnalysisUnavailable, 'controlled analysis failure'):
                self.session.call('open_program', {})
        self.assertEqual(self.session.process.pid, process_id)

    def test_close_ends_pending_worker_and_is_idempotent(self):
        self.session.call('open_program', {})
        self.assertTrue(self.started.wait(10))
        start = time.monotonic()
        self.session.close()
        self.assertLess(time.monotonic() - start, 5)
        self.session.close()
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            self.session.call('open_program', {})

    def test_open_retries_after_another_process_releases_program_lock(self):
        backend = LockingBackend(str(self.backend.target))
        session = McpSession(backend, initial_wait=5)
        self.addCleanup(session.close)
        with (backend.directory / 'session.lock').open('a+') as holder:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(AnalysisUnavailable, 'already open'):
                session.call('open_program', {})
            failed_pid = session.process.pid
            for _ in range(2):
                self.assertEqual(session.status()['state'], 'failed')
                with self.assertRaises(AnalysisUnavailable):
                    session.call('search', {})
                self.assertEqual(session.process.pid, failed_pid)
            fcntl.flock(holder, fcntl.LOCK_UN)
        opened = session.call('open_program', {})
        self.assertEqual(session.state, 'ready')
        self.assertNotEqual(session.process.pid, failed_pid)
        self.assertEqual(opened['data']['sha256'], backend.digest)
        self.assertIsNone(session.error)


if __name__ == '__main__':
    unittest.main()
