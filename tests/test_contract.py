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

    def test_read_rejects_foreign_target_and_changed_content_identity(self):
        import hashlib
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            first=Evidence(Path(tmp)/'first','a'*64)
            second=Evidence(Path(tmp)/'second','b'*64)
            item=first.save('inspect','computed',{'code':'return 7;'})
            for suffix in ('.json','.sha256'):
                shutil.copy2(first.directory/(item['id']+suffix),second.directory/(item['id']+suffix))
            with self.assertRaisesRegex(ValueError,'target'):
                second.read(item['id'])
            path=Path(item['path']);record=json.loads(path.read_text());record['data']['code']='return 8;'
            raw=json.dumps(record).encode();path.write_bytes(raw)
            path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest()+'\n')
            with self.assertRaisesRegex(ValueError,'identity'):
                first.read(item['id'])

    def test_native_catalog_adds_distinct_bounded_trace_with_closed_arguments(self):
        self.assertEqual(len(TOOLS),8)
        self.assertEqual(TOOLS[-1][0],'trace_calls')
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
