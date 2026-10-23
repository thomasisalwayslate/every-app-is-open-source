import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from eaos.application import Application, asar_entries


def asar(header, payload=b''):
    raw = json.dumps(header, separators=(',', ':')).encode()
    padding = b'\0' * (-len(raw) % 4)
    pickle_header = struct.pack('<II', 4+len(raw)+len(padding), len(raw)) + raw + padding
    return struct.pack('<II', 4, len(pickle_header)) + pickle_header + payload


class Inventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'App.app'
        self.root.mkdir()
        self.workspace = self.base/'workspace'

    def make(self, path, data=b'file'):
        target = self.root/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def test_capture_identity_reopen_and_changed_input(self):
        source = self.make('Contents/Resources/main.js', b"ipcMain.handle('read', cb)")
        app = Application(self.root, self.workspace)
        result = app.inventory(pattern='main.js', limit=1)
        component = result['items'][0]
        captured = app.capture(component['component_id'])
        self.assertEqual(captured['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertFalse(Path(captured['path']).is_relative_to(self.root))
        self.assertEqual(len(captured['component_id']), 64)
        self.assertEqual(len(result['application_snapshot']), 64)
        self.assertEqual(len(app.inspect_javascript(component['component_id'])['observations']), 1)
        again = Application(self.root, self.workspace).inventory('main.js')
        self.assertEqual(result['application_snapshot'], again['application_snapshot'])
        source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'changed'):
            app.capture(component['component_id'])
        changed = Application(self.root, self.workspace)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            changed.inventory('main.js', view=result['view'])
        self.assertTrue(Path(captured['path']).exists())

    def test_symlinks_not_followed_or_captured(self):
        outside = self.base/'secret'; outside.write_bytes(b'secret')
        os.symlink(outside, self.root/'escape.js')
        os.symlink(self.base, self.root/'escape-directory')
        app = Application(self.root, self.workspace)
        result = app.inventory()
        self.assertEqual(len(result['items']), 2)
        self.assertTrue(all(x['kind'] == 'symlink' for x in result['items']))
        for item in result['items']:
            with self.assertRaisesRegex(ValueError, 'cannot be captured'):
                app.capture(item['component_id'])
        with self.assertRaisesRegex(ValueError, 'outside'):
            Application(self.root, self.root/'cache')

    def test_symlink_parent_swap_refused(self):
        self.make('sub/main.js', b'original')
        outside = self.base/'outside'; outside.mkdir(); (outside/'main.js').write_bytes(b'original')
        app = Application(self.root, self.workspace)
        item = app.inventory('main.js')['items'][0]
        (self.root/'sub/main.js').unlink(); (self.root/'sub').rmdir()
        os.symlink(outside, self.root/'sub')
        with self.assertRaises(OSError):
            app.capture(item['component_id'])

    def test_pagination_distinct_components_and_cancel(self):
        self.make('a/main.js', b''); self.make('b/main.js', b'')
        app = Application(self.root, self.workspace)
        first = app.inventory('main.js', limit=1)
        self.assertEqual(first['matches'], 2)
        with self.assertRaisesRegex(ValueError, 'missing'):
            app.inventory('main.js', offset=1)
        second = app.inventory('main.js', offset=1, limit=1, view=first['view'])
        self.assertNotEqual(first['items'][0]['component_id'], second['items'][0]['component_id'])
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            app.capture('0'*64)
        cancelled = Application(self.root, self.base/'cancel', cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            cancelled.inventory()
        self.assertIsNone(cancelled._manifest)
        self.assertFalse((self.base/'cancel').exists())

    def test_budgets_and_invalid_limits(self):
        self.make('one.js', b'1234'); self.make('sub/two.js', b'1234')
        app = Application(self.root, self.workspace, limits={'file_bytes': 2, 'depth': 1})
        result = app.inventory()
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual({x['reason'] for x in result['coverage']['gaps']}, {'file_byte_budget', 'depth_budget'})
        for limits in ({'seconds': float('nan')}, {'files': True}, {'depth': 0}, {'files': 1.5}):
            with self.assertRaises(ValueError):
                Application(self.root, self.workspace, limits=limits)

    def test_asar_package_layout_and_javascript(self):
        package = b'{"name":"fixture","main":"main.js"}'
        javascript = b"ipcRenderer.invoke('fixture')"
        archive = asar({'files': {'package.json': {'size': len(package), 'offset': '0'}, 'main.js': {'size': len(javascript), 'offset': str(len(package))}}}, package+javascript)
        self.make('Contents/Resources/app.asar', archive)
        app = Application(self.root, self.workspace)
        rows = app.inventory()['items']
        package_row = next(x for x in rows if x['path'].endswith('!/package.json'))
        self.assertEqual(package_row['package']['main'], 'main.js')
        js = next(x for x in rows if x['kind'] == 'javascript')
        inspected = app.inspect_javascript(js['component_id'])
        self.assertEqual(inspected['observations'][0]['literal_argument'], 'fixture')
        self.assertEqual(Path(app.capture(js['component_id'])['path']).read_bytes(), javascript)

    def test_malformed_asar_and_bounds(self):
        malformed = [b'', asar({'files': {'../escape': {'size': 1, 'offset': '0'}}}, b'a'),
                     asar({'files': {'main.js': {'size': 100, 'offset': '0'}}}, b'a'),
                     asar({'files': {'x': {'size': 2, 'offset': '0'}, 'y': {'size': 2, 'offset': '1'}}}, b'abc')]
        for value in malformed:
            with self.assertRaises(ValueError):
                asar_entries(value, len(value))
        value = asar({'files': {'x': {'size': 1, 'offset': '0'}, 'y': {'size': 1, 'offset': '1'}}}, b'ab')
        result = asar_entries(value, len(value), max_entries=1)
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['entries']), 1)
        self.make('bad.asar', b'not asar')
        result = Application(self.root, self.workspace).inventory()
        self.assertFalse(result['coverage']['complete'])

    def test_asar_duplicate_keys_and_link(self):
        raw = b'{"files":{"x":{"size":0,"offset":"0"},"x":{"size":0,"offset":"0"}}}'
        pad = b'\0'*(-len(raw)%4)
        header = struct.pack('<II', len(raw)+len(pad)+4, len(raw))+raw+pad
        value = struct.pack('<II',4,len(header))+header
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            asar_entries(value, len(value))
        value = asar({'files': {'link': {'link': '../../secret'}}})
        self.assertFalse(asar_entries(value, len(value))['entries'][0]['capturable'])

    def test_strict_global_entry_and_asar_entry_budgets(self):
        for n in range(8):
            self.make(f'{n}.js', b'')
        result = Application(self.root, self.workspace, limits={'files': 3}).inventory()
        self.assertEqual(result['coverage']['entries'], 3)
        self.assertFalse(result['coverage']['complete'])
        other = self.base/'Other'; other.mkdir()
        data = asar({'files': {'x.js': {'size': 0, 'offset': '0'}}})
        (other/'app.asar').write_bytes(data)
        result = Application(other, self.base/'other-cache', limits={'files': 1}).inventory()
        self.assertEqual(result['coverage']['entries'], 1)
        self.assertFalse(result['coverage']['complete'])

    def test_bundle_workspace_guard_and_native_identity(self):
        for path in (self.base/'Other.app/cache', self.base/'Other.framework/cache', self.root/'cache'):
            with self.assertRaisesRegex(ValueError, 'outside'):
                Application(self.root, path)
        native = b'\xcf\xfa\xed\xfe' + struct.pack('<IIIIIII', 0x100000c, 0, 2, 0, 0, 0, 0)
        self.make('Contents/MacOS/main', native)
        app = Application(self.root, self.workspace)
        row = app.inventory('MacOS/main')['items'][0]
        self.assertEqual(row['architectures'], ['arm64'])
        result = app.capture(row['component_id'], architecture='arm64')
        self.assertEqual(result['selection']['sha256'], result['sha256'])
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            app.capture(row['component_id'], architecture='x86_64')

    def test_cancel_during_expansion_no_partial_manifest(self):
        self.make('one.js', b'a'*20000)
        calls = 0
        def cancelled():
            nonlocal calls
            calls += 1
            return calls > 5
        app = Application(self.root, self.workspace, cancelled=cancelled)
        with self.assertRaises(InterruptedError):
            app.inventory()
        self.assertIsNone(app._manifest)
        self.assertFalse((self.workspace/'inventories').exists())
        app.cancelled = None
        self.assertTrue(app.inventory()['coverage']['complete'])

    def test_declared_entry_not_execution_and_package_traversal(self):
        self.make('package.json', b'{"main":"main.js"}')
        self.make('main.js', b'')
        result = Application(self.root, self.workspace).inventory()
        edge = result['relationships'][0]
        self.assertEqual(edge['status'], 'recorded_exact_path')
        self.assertIn('execution', edge['limitation'])
        self.make('package.json', b'{"main":"../secret.js"}')
        result = Application(self.root, self.base/'workspace2').inventory()
        self.assertIsNone(result['relationships'][0]['target_component_id'])
        self.assertIsNone(result['relationships'][0]['candidate_path'])

    def test_large_native_candidate_remains_visible_without_hash(self):
        native = b'\xcf\xfa\xed\xfe' + struct.pack('<IIIIIII', 0x100000c, 0, 2, 0, 0, 0, 0)
        self.make('main', native + b'\0'*100)
        result = Application(self.root, self.workspace, limits={'file_bytes': 32}).inventory()
        row = result['items'][0]
        self.assertEqual(row['kind'], 'native')
        self.assertEqual(row['architectures'], ['arm64'])
        self.assertFalse(row['capturable'])
        self.assertNotIn('sha256', row)

    def test_cache_symlink_cannot_redirect_bundle_writes(self):
        self.make('main.js', b'')
        self.workspace.mkdir()
        os.symlink(self.root, self.workspace/'inventories')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            Application(self.root, self.workspace).inventory()
        self.assertEqual([x.name for x in self.root.iterdir()], ['main.js'])

    def test_declared_asar_sha256_matches_without_authenticity_claim(self):
        payload = b"ipcMain.handle('fixture', callback)"
        digest = hashlib.sha256(payload).hexdigest()
        archive = asar({'files': {'main.js': {'offset': '0', 'size': len(payload),
                                             'integrity': {'algorithm': 'SHA256', 'hash': digest,
                                                           'blockSize': len(payload), 'blocks': [digest]}}}}, payload)
        self.make('app.asar', archive)
        app = Application(self.root, self.workspace)
        row = next(x for x in app.inventory()['items'] if x['kind'] == 'javascript')
        self.assertEqual(row['declared_integrity']['trust'], 'untrusted_archive_metadata')
        self.assertEqual(row['declared_integrity']['status'], 'supported_sha256_unverified')
        result = app.capture(row['component_id'])
        self.assertEqual(result['declared_integrity_verification']['status'], 'matched')
        self.assertFalse(result['declared_integrity_verification']['authenticity_established'])
        self.assertFalse(result['declared_integrity_verification']['block_hashes_checked'])
        self.assertEqual(result['sha256'], digest)

    def test_bad_declared_asar_digest_preserves_snapshot(self):
        payload = b'fixture'
        archive = asar({'files': {'main.js': {'offset': '0', 'size': len(payload),
                                             'integrity': {'algorithm': 'SHA256', 'hash': '0'*64}}}}, payload)
        source = self.make('app.asar', archive)
        app = Application(self.root, self.workspace)
        inventory = app.inventory()
        saved = list((self.workspace/'inventories').glob('*.json'))[0]
        saved_bytes = saved.read_bytes()
        row = next(x for x in inventory['items'] if x['kind'] == 'javascript')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            app.capture(row['component_id'])
        self.assertEqual(source.read_bytes(), archive)
        self.assertEqual(saved.read_bytes(), saved_bytes)
        self.assertFalse((self.workspace/'captures').exists())

    def test_unsupported_declared_asar_integrity_is_not_absence(self):
        declarations = [None, 'sha256', {'algorithm': 'SHA512', 'hash': '0'*128},
                        {'algorithm': 'SHA256', 'hash': 'wrong'},
                        {'algorithm': 'SHA256', 'hash': '0'*64, 'blocks': []},
                        {'algorithm': 'SHA256', 'hash': '0'*64, 'extra': True}]
        for n, declaration in enumerate(declarations):
            with self.subTest(declaration=declaration):
                root = self.base/f'case{n}'; root.mkdir()
                archive = asar({'files': {'x.js': {'offset': '0', 'size': 1, 'integrity': declaration}}}, b'x')
                (root/'app.asar').write_bytes(archive)
                app = Application(root, self.base/f'cache{n}')
                row = next(x for x in app.inventory()['items'] if x['kind'] == 'javascript')
                self.assertEqual(row['declared_integrity']['status'], 'unsupported')
                with self.assertRaisesRegex(ValueError, 'Unsupported ASAR declared integrity'):
                    app.capture(row['component_id'])

    def test_unpacked_integrity_is_explicitly_unverified(self):
        archive = asar({'files': {'native.node': {'size': 1, 'unpacked': True,
                                                'integrity': {'algorithm': 'SHA256', 'hash': '0'*64}}}})
        result = asar_entries(archive, len(archive))
        self.assertFalse(result['complete'])
        row = result['entries'][0]
        self.assertFalse(row['capturable'])
        self.assertEqual(row['declared_integrity']['status'], 'supported_sha256_unverified')
        self.assertEqual(result['gaps'][0]['reason'], 'asar_unpacked_bytes_not_captured')
