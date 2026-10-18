import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from eaos.backend import Backend
from eaos.cli import serve
from eaos.contracts import validate_arguments


class Validation(unittest.TestCase):
    def test_invalid_values_are_rejected_before_native_loading(self):
        invalid = [
            ('open_program', {'full': 'false'}),
            ('search', {'limit': True}),
            ('search', {'offset': -1}),
            ('search', {'kind': 'files'}),
            ('inspect', {'addresses': '1000'}),
            ('inspect', {'addresses': []}),
            ('inspect', {'addresses': ['1000'] * 9}),
            ('read_memory', {'address': '1000', 'length': 65537}),
            ('read_memory', {'address': 1000}),
            ('read_evidence', {'id': 'a' * 32, 'limit': 0}),
            ('decode_swift_string', {'words': [True, 0]}),
            ('decode_swift_string', {}),
            ('decode_swift_string', {'words': [0, 1], 'address': '1000'}),
            ('decode_swift_string', {'words': [-1, 0]}),
            ('calculate', {'expression': '1' * 10001}),
            ('open_program', {'path': '/arbitrary/file'}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'selected'
            target.write_bytes(b'fixture')
            backend = Backend(str(target))
            with patch.object(backend, '_load') as load:
                for name, arguments in invalid:
                    with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                        getattr(backend, name)(**arguments)
                load.assert_not_called()
            backend.close()

    def test_transport_does_not_delegate_invalid_types(self):
        backend = Mock()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'open_program', 'arguments': {'full': 'false'}}}
        with patch('sys.stdin', io.StringIO(json.dumps(request) + '\n')), patch('sys.stdout', io.StringIO()) as output:
            serve(backend)
        self.assertTrue(json.loads(output.getvalue())['result']['isError'])
        backend.open_program.assert_not_called()

    def test_valid_argument_shapes_and_false_are_preserved(self):
        for name, arguments in [
            ('open_program', {'full': False}),
            ('search', {'offset': 0, 'limit': 200}),
            ('inspect', {'addresses': ['1000'], 'mode': 'assembly'}),
            ('decode_swift_string', {'words': ['0x01', 2]}),
        ]:
            self.assertEqual(validate_arguments(name, arguments), arguments)
        for value in [[], None, 'not an object']:
            with self.assertRaises(ValueError):
                validate_arguments('open_program', value)


if __name__ == '__main__':
    unittest.main()
