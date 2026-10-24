import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from eaos.application import Application
from eaos.application_session import ApplicationSession
from eaos.contracts import APPLICATION_TOOLS, TOOLS, validate_arguments
from eaos.js_index import SyntaxOwner, inspect_index
from eaos.js_syntax import parse_batch, SOURCE_LIMIT, parser_identity


class SyntaxFixtures(unittest.TestCase):
    def test_tree_not_text_matches_and_exact_multibyte_ranges(self):
        data = '''// ipcMain.handle('comment', cb)
const s="ipcMain.handle('string',cb)";
const r=/ipcMain.handle('regex',cb)/;
const 日本語=1;
obj.handle('real', cb);
'''.encode()
        result = parse_batch(data)
        calls = [x for x in result['observations'] if x['kind'] == 'call_site']
        self.assertEqual([x['literal_argument'] for x in calls], ['real'])
        call = calls[0]
        self.assertEqual(data[call['start_byte']:call['end_byte']], b"obj.handle('real', cb)")
        self.assertEqual((call['line'], call['column_byte']), (5, 0))
        self.assertIn('binding', call['relationship'])
        self.assertFalse(result['tree_has_errors'])

    def test_original_byte_locations_lf_crlf_and_eof(self):
        for newline in (b'\n', b'\r\n'):
            raw = b'// prefix'+newline+'const x="日本語";'.encode()+newline+b'obj.handle('+newline+'"日本語", cb'.encode()+newline+b')'
            row = parse_batch(raw)['observations'][0]
            for location in (row, row['callee_location'], row['argument_location']):
                start, end = location['start_byte'], location['end_byte']
                self.assertEqual(location['line'],raw[:start].count(b'\n')+1)
                self.assertEqual(location['column_byte'],start-raw.rfind(b'\n',0,start)-1)
                self.assertEqual(location['end_line'],raw[:end].count(b'\n')+1)
                self.assertEqual(location['end_column_byte'],end-raw.rfind(b'\n',0,end)-1)
            self.assertEqual(row['end_byte'],len(raw))
            self.assertEqual(raw[row['start_byte']:row['end_byte']],b'obj.handle('+newline+'"日本語", cb'.encode()+newline+b')')

    def test_coherent_source_beyond_old_cap_and_chunk_boundary(self):
        # The apparent call is inside one long literal crossing the former cap.
        data = b'const s="' + b'a'*(1024*1024) + b"ipcMain.handle('fake',cb)" + b'";\nwindow.loadURL(target);'
        result = parse_batch(data)
        calls = result['observations']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['method'], 'loadURL')
        self.assertGreater(calls[0]['start_byte'], 1024*1024)
        self.assertIsNone(calls[0]['literal_argument'])

    def test_multiple_batches_no_gaps_or_duplicate_results(self):
        data = b';'.join(b'obj.handle("c%d",f)' % n for n in range(30))
        expected = parse_batch(data)
        state = None
        counts = []
        for _ in range(200):
            state = parse_batch(data, state, max_nodes=7)
            counts.append(state['nodes_indexed'])
            if state['traversal_complete']:
                break
        self.assertTrue(state['traversal_complete'])
        self.assertEqual(state['observations'], expected['observations'])
        self.assertEqual(state['nodes_indexed'], expected['nodes_indexed'])
        self.assertEqual(counts, sorted(set(counts)))

    def test_errors_escapes_dynamic_shadowing_are_not_semantic_proof(self):
        data = b"function f(require){require('electron');} obj.handle('a\\x62',f); obj.invoke(channel); const broken = ;"
        result = parse_batch(data)
        self.assertTrue(result['tree_has_errors'])
        self.assertGreater(result['error_count'], 0)
        self.assertEqual(result['observations'][0]['module'], 'electron')
        self.assertIn('unverified', result['observations'][0]['relationship'])
        self.assertTrue(all(x.get('literal_argument') is None for x in result['observations'][1:]))

    def test_resource_count_time_record_and_depth_cutoffs(self):
        data = b'obj.handle("x",f);obj.invoke("y");'
        first = parse_batch(data, max_nodes=0)
        self.assertEqual(first['nodes_indexed'], 0)
        self.assertEqual(first['stopping_reason'], 'node_budget')
        self.assertTrue(first['indexing_possible'])
        timed = parse_batch(data, max_seconds=0)
        self.assertEqual(timed['batch_nodes'], 0)
        self.assertEqual(timed['stopping_reason'], 'time_budget')
        capped = parse_batch(data, max_records=1)
        self.assertEqual(capped['stopping_reason'], 'record_budget')
        self.assertFalse(capped['indexing_possible'])
        with patch('eaos.js_syntax.DEPTH_LIMIT', 2):
            deep = parse_batch(data)
        self.assertEqual(deep['stopping_reason'], 'depth_budget')
        self.assertFalse(deep['traversal_complete'])
        with self.assertRaises(UnicodeDecodeError):
            parse_batch(b'\xff')
        with self.assertRaises(ValueError):
            parse_batch(b' '*(SOURCE_LIMIT+1))

    def test_import_preload_and_source_map_declarations(self):
        result = parse_batch(b"import {x} from 'electron'; export {y} from 'other'; const w={preload:path.join('a','b')};\n//# sourceMappingURL=main.js.map\n")
        self.assertEqual([x.get('module') for x in result['observations'][:2]], ['electron','other'])
        self.assertIsNone(result['observations'][2]['literal_argument'])
        self.assertEqual(result['observations'][3]['reference'], 'main.js.map')
        self.assertIn('not_resolved', result['observations'][3]['availability'])


class IndexFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base/'input.js'
        self.path.write_bytes(b'obj.handle("first", f);obj.invoke("second");obj.on("third",f)')
        self.capture = {'path':str(self.path),'sha256':hashlib.sha256(self.path.read_bytes()).hexdigest(),
                        'component_id':'component','application_snapshot':'snapshot'}
        self.folder = self.base/'index';self.folder.mkdir()
        self.owner = SyntaxOwner();self.addCleanup(self.owner.close)

    def inspect(self, **kw):
        return inspect_index(self.owner, self.capture, self.folder, **kw)

    def test_result_pages_do_not_expand_and_old_view_rejected(self):
        a = self.inspect(max_nodes=13, limit=1)
        self.assertTrue(a['coverage']['index_cursor'])
        revision = a['index_revision']
        with patch.object(self.owner, 'run', side_effect=AssertionError('paging must not parse')):
            b = self.inspect(limit=1)
            self.assertEqual(b['index_revision'], revision)
        expanded = self.inspect(index_cursor=a['coverage']['index_cursor'], max_nodes=100)
        self.assertNotEqual(expanded['index_revision'], revision)
        self.assertEqual(expanded['matches'], 3)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.inspect(offset=1, view=a['view'])
        page = self.inspect(offset=1, view=expanded['view'], limit=1)
        self.assertEqual(page['observations'][0]['literal_argument'], 'second')
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.inspect(index_cursor=a['coverage']['index_cursor'])
        with self.assertRaisesRegex(ValueError, 'pagination'):
            self.inspect(index_cursor=a['coverage']['index_cursor'], view=expanded['view'])

    def test_wrong_context_or_malformed_cursor_is_not_a_path(self):
        a = self.inspect(max_nodes=1)
        for bad in ('../../arbitrary', a['coverage']['index_cursor'].replace('js1:', 'other:')):
            with self.assertRaisesRegex(ValueError, 'cursor'):
                self.inspect(index_cursor=bad)
        other = dict(self.capture, component_id='different')
        with self.assertRaisesRegex(ValueError, 'identity'):
            inspect_index(self.owner, other, self.folder)
        with patch('eaos.js_index.parser_identity', return_value=dict(parser_identity(), index_schema=999)):
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.inspect()

    def test_reopening_hash_checks_and_failed_expansion_keeps_progress(self):
        a = self.inspect(max_nodes=1)
        pointer = (self.folder/'current.json').read_bytes()
        with patch.object(self.owner, 'run', side_effect=InterruptedError('cancelled')):
            with self.assertRaises(InterruptedError):
                self.inspect(index_cursor=a['coverage']['index_cursor'])
        self.assertEqual((self.folder/'current.json').read_bytes(), pointer)
        other_owner = SyntaxOwner();self.addCleanup(other_owner.close)
        self.assertEqual(inspect_index(other_owner,self.capture,self.folder)['index_revision'], a['index_revision'])
        state = next(self.folder.glob('state-*.json'));state.chmod(0o644);state.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.inspect()

    def test_source_changed_before_worker_never_commits(self):
        self.path.write_text('different')
        with self.assertRaisesRegex(RuntimeError, 'identity/size mismatch'):
            self.inspect()
        self.assertFalse((self.folder/'current.json').exists())
        self.assertIsNone(self.owner.process)

    def test_worker_cancel_deadline_and_conflicting_owner(self):
        real_popen = subprocess.Popen
        started = threading.Event(); errors=[]; processes=[]
        def slow(*a, **kw):
            if 'eaos.js_worker' not in a[0]:
                return real_popen(*a, **kw)
            p = real_popen([sys.executable, '-c', 'import sys,time;sys.stdin.buffer.read();time.sleep(30)'], **kw)
            processes.append(p);started.set();return p
        cancel = threading.Event()
        def run():
            try:self.inspect(cancelled=cancel.is_set)
            except Exception as exc:errors.append(exc)
        with patch('eaos.js_index.subprocess.Popen', side_effect=slow):
            t = threading.Thread(target=run);t.start()
            self.assertTrue(started.wait(2))
            with self.assertRaisesRegex(RuntimeError, 'owns'):
                self.inspect()
            cancel.set();t.join(2)
        self.assertFalse(t.is_alive());self.assertIsInstance(errors[0], InterruptedError)
        self.assertTrue(all(p.poll() is not None for p in processes))
        self.assertIsNone(self.owner.process)
        self.assertFalse((self.folder/'current.json').exists())
        with patch('eaos.js_index.subprocess.Popen', side_effect=slow):
            with self.assertRaises(TimeoutError):
                self.inspect(wall_seconds=.05)
        self.assertIsNone(self.owner.process)

    def test_native_exit_preserves_committed_bytes_and_can_resume(self):
        a = self.inspect(max_nodes=1)
        preserved = {str(p):p.read_bytes() for p in self.folder.glob('*.json')}
        real_popen = subprocess.Popen
        def fault(*args, **kwargs):
            if 'eaos.js_worker' not in args[0]:
                return real_popen(*args, **kwargs)
            return real_popen([sys.executable,'-c',
                'import sys,os,signal,resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.stdin.buffer.read();os.kill(os.getpid(),signal.SIGSEGV)'], **kwargs)
        with patch('eaos.js_index.subprocess.Popen',side_effect=fault):
            with self.assertRaisesRegex(RuntimeError,r'failed \(-11\)'):
                self.inspect(index_cursor=a['coverage']['index_cursor'])
        self.assertIsNone(self.owner.process)
        for name,raw in preserved.items():self.assertEqual(Path(name).read_bytes(),raw)
        recovered = self.inspect(index_cursor=a['coverage']['index_cursor'])
        self.assertTrue(recovered['coverage']['syntax_tree_traversal_complete'])
        self.assertEqual(recovered['matches'],3)

    def test_output_state_limits_and_close_leave_valid_progress(self):
        a=self.inspect(max_nodes=1)
        old=(self.folder/'current.json').read_bytes()
        with patch('eaos.js_index.STATE_LIMIT',1):
            with self.assertRaisesRegex(ValueError,'budget'):
                self.inspect(index_cursor=a['coverage']['index_cursor'])
        self.assertEqual((self.folder/'current.json').read_bytes(),old)
        self.owner.close()
        with self.assertRaisesRegex(RuntimeError,'closed'):
            self.inspect(index_cursor=a['coverage']['index_cursor'])
        self.assertEqual((self.folder/'current.json').read_bytes(),old)

    def test_observed_peak_memory_fails_closed_and_storage_is_bounded(self):
        with patch('eaos.js_index.RSS_LIMIT', 1):
            with self.assertRaises(MemoryError):self.inspect()
        self.assertFalse((self.folder/'current.json').exists())
        self.inspect(max_nodes=1)
        with patch('eaos.js_index.GENERATION_LIMIT', 1):
            result=self.inspect()
            self.assertFalse(result['coverage']['further_indexing_possible'])
            self.assertEqual(result['coverage']['stopping_reason'], 'snapshot_storage_budget')


class ApplicationSyntax(unittest.TestCase):
    def test_session_evidence_reopen_source_window_and_closed_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'Fixture.app';root.mkdir()
            raw='// 日本語\nobj.handle("check",f);'.encode()
            (root/'main.js').write_bytes(raw)
            s=ApplicationSession(root,base/'cache')
            try:
                component=s.call('inventory_application',{})['data']['items'][0]['component_id']
                result=s.call('inspect_javascript',{'component_id':component})
                identifier=result['evidence']['id']
                saved=s.call('read_evidence',{'id':identifier})['text']
                self.assertEqual(json.loads(saved)['data']['parser']['engine_version'],'0.26.0')
                window=s.call('inspect_javascript',{'component_id':component,'source_offset':4,'source_length':8})['data']['source_window']
                self.assertEqual(raw[window['start_byte']:window['end_byte']].decode(),window['text'])
                with self.assertRaisesRegex(ValueError, 'too small'):
                    s.call('inspect_javascript',{'component_id':component,'source_offset':3,'source_length':1})
                self.assertEqual(len(s.tools),len(TOOLS)+len(APPLICATION_TOOLS))
                self.assertEqual(s.analysis_mode,'full')
                for args in ({'component_id':component,'source_length':8193},
                             {'component_id':component,'find':'x'*257},
                             {'component_id':component,'index_cursor':'x'*201}):
                    with self.assertRaises(ValueError):validate_arguments('inspect_javascript',args)
            finally:s.close()
            with self.assertRaises(RuntimeError):s.call('inspect_javascript',{'component_id':component})
            reopened=ApplicationSession(root,base/'cache')
            try:
                reopened.call('inventory_application',{})
                self.assertEqual(reopened.call('read_evidence',{'id':identifier})['text'],saved)
                self.assertEqual(reopened.call('inspect_javascript',{'component_id':component})['data']['index_revision'],result['data']['index_revision'])
            finally:reopened.close()
            self.assertEqual((root/'main.js').read_bytes(),raw)
