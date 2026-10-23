import unittest
from eaos.javascript import inspect_source, JavaScriptError


class JavaScript(unittest.TestCase):
    def test_electron_literal_calls_only(self):
        result = inspect_source(b'''const {ipcMain} = require('electron');
        // ipcMain.handle('fake', x)
        const fake = "ipcRenderer.send('fake')";
        ipcMain.handle('read', callback); ipcRenderer.invoke('read');
        win.loadFile('index.html'); const config = {preload: 'preload.js'};
        win.loadURL(prefix + '/page');''')
        calls = [x for x in result['observations'] if x['kind'] == 'call_site']
        self.assertEqual([x['literal_argument'] for x in calls], ['read', 'read', 'index.html', None])
        self.assertFalse(result['coverage']['complete'])
        self.assertTrue(all('unverified' in x['relationship'] for x in calls))

    def test_dynamic_escaped_template_regex(self):
        result = inspect_source(b'''ipcMain.handle(channel, cb);
        const x = `ipcMain.handle('fake', cb)`;
        const y = /ipcMain.handle('fake', cb)/;
        ipcMain.handle('es\\x63ape', cb);''')
        calls = [x for x in result['observations'] if x['kind'] == 'call_site']
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(x['literal_argument'] is None for x in calls))
        self.assertGreaterEqual(len(result['coverage']['unparsed']), 3)

    def test_boundaries_cancellation(self):
        with self.assertRaises(JavaScriptError):
            inspect_source(b'abc', max_bytes=2)
        with self.assertRaises(JavaScriptError):
            inspect_source(b'\xff')
        with self.assertRaises(InterruptedError):
            inspect_source(b'abc', cancelled=lambda: True)
        result = inspect_source(b'var a = 1; var b = 2;', max_tokens=2)
        self.assertEqual(result['coverage']['unparsed'][0]['reason'], 'token_budget')
        result = inspect_source(b'ipcMain.on("a", f); ipcMain.on("b", f);', max_observations=1)
        self.assertEqual(len(result['observations']), 1)
        self.assertEqual(result['coverage']['unparsed'][-1]['reason'], 'observation_budget')

    def test_import_and_preload_not_runtime_proof(self):
        result = inspect_source(b"import {x} from 'electron'; const c={preload: path.join('a','b')};")
        self.assertEqual(result['observations'][0]['module'], 'electron')
        self.assertIsNone(result['observations'][1]['literal_argument'])

    def test_fake_module_spellings_and_dynamic_import(self):
        result = inspect_source(b'''obj.require('fake'); const a = 'require';
        import(dynamic('fake')); import('literal');
        export const x = {from: 'fake'};
        import {x} from 'real';''')
        modules = [x['module'] for x in result['observations'] if x['kind'] == 'module_specifier']
        self.assertEqual(modules, ['literal', 'real'])
        self.assertIn('dynamic_import_unparsed', [x['reason'] for x in result['coverage']['unparsed']])

    def test_long_literal_cancellation_and_time_bound(self):
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls > 2
        with self.assertRaises(InterruptedError):
            inspect_source(b'"'+b'a'*100000+b'"', cancelled=cancel)
        with self.assertRaises(TimeoutError):
            inspect_source(b'x', max_seconds=-1)

    def test_unterminated_arguments_never_become_literal_facts(self):
        for ending in (b'\n)', b'', b'\\'):
            with self.subTest(ending=ending):
                module = inspect_source(b"require('electron" + ending)
                self.assertFalse(any(x['kind'] == 'module_specifier' for x in module['observations']))
                call = inspect_source(b"ipcMain.handle('channel" + ending)
                for observation in call['observations']:
                    self.assertIsNone(observation.get('literal_argument'))
                    self.assertEqual(observation['argument_status'], 'dynamic_or_unparsed')
                for result in (module, call):
                    self.assertIn('unterminated_string', [x['reason'] for x in result['coverage']['unparsed']])
                    self.assertFalse(result['coverage']['complete'])
