import json
import tempfile
import unittest
from pathlib import Path
from eaos.swift import decode_small_string
from eaos.evidence import Evidence
from eaos.calculator import calculate
from eaos.cli import TOOLS
from eaos.backend import Backend


class Contracts(unittest.TestCase):
    def test_swift_ascii_and_utf8(self):
        for text, tag in [('hello',0xE0),('日本語',0xA0),('',0xE0)]:
            raw=text.encode();storage=raw+b'\0'*(15-len(raw))+bytes([tag|len(raw)])
            words=[int.from_bytes(storage[:8],'little'),int.from_bytes(storage[8:],'little')]
            self.assertEqual(decode_small_string(words)['text'],text)

    def test_decoder_rejects_pointer_and_wrong_ascii(self):
        with self.assertRaises(ValueError):decode_small_string([0x100000000,0x8000000000000000])
        with self.assertRaises(ValueError):decode_small_string([0xA9C3,0xE200000000000000])

    def test_evidence_is_persistent_resolvable_and_tamper_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Evidence(Path(tmp),'a'*64)
            item=store.save('decompile','computed',{'code':'return 7;'})
            self.assertTrue(Path(item['path']).is_file())
            self.assertEqual(item['uri'],Path(item['path']).as_uri())
            self.assertIn('return 7',store.read(item['id'])['text'])
            with self.assertRaises(ValueError):store.read('../private/oracle')
            Path(item['path']).write_text('changed')
            with self.assertRaises(ValueError):store.read(item['id'])

    def test_calculator_has_no_file_or_import_route(self):
        self.assertEqual(calculate('sum(x*3 for x in range(4))'),'18')
        for expression in ["open('/etc/passwd').read()", "__import__('os').system('id')", '().__class__']:
            with self.assertRaises(ValueError):calculate(expression)

    def test_evidence_identity_is_stable_and_scoped_to_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Evidence(Path(tmp)/'a','a'*64)
            first=store.save('read','fact',{'hex':'00','address':'10'})
            second=store.save('read','fact',{'address':'10','hex':'00'})
            # Payload key order must not produce a second identity or corrupt one.
            self.assertEqual(first['id'],second['id'])
            other=Evidence(Path(tmp)/'b','b'*64).save('read','fact',{'hex':'00','address':'10'})
            self.assertNotEqual(first['id'],other['id'])

    def test_catalog_is_seven_tools_with_closed_argument_objects(self):
        self.assertEqual(len(TOOLS),7)
        self.assertTrue(all(t[2]['additionalProperties'] is False for t in TOOLS))

    def test_calculator_subprocess_works_with_real_os_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'fixture';target.write_bytes(b'calculator boundary test')
            backend=Backend(str(target))
            try:
                result=backend.calculate('sum(x*3 for x in range(4))')
                self.assertEqual(result['data']['value'],'18')
                self.assertEqual(result['classification'],'computed')
                self.assertTrue((backend.evidence.directory/(result['evidence']['id']+'.json')).is_file())
            finally:backend.close()


if __name__=='__main__':unittest.main()
