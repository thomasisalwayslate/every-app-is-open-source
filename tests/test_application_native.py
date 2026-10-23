"""Small compiled fixtures only; never launch a selected application."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from eaos.application_session import ApplicationSession
from eaos.backend import Backend
from eaos.session import McpSession


@unittest.skipUnless(os.environ.get('EAOS_NATIVE_TESTS')=='1','requires existing Java/Ghidra and clang')
class ApplicationNative(unittest.TestCase):
    def test_component_scope_native_trace_and_evidence_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'Fixture.app';root.mkdir()
            binary=root/'program'
            subprocess.run(['clang','-O0',str(Path(__file__).parent/'fixture.c'),'-o',str(binary)],check=True)
            original=binary.read_bytes()
            app=ApplicationSession(root,base/'workspace',request_timeout=30,analysis_timeout=30)
            try:
                item=next(x for x in app.call('inventory_application',{})['data']['items'] if x['kind']=='native')
                selected=app.call('select_component',{'component_id':item['component_id']})
                self.assertEqual(selected['data']['analysis_mode'],'full')
                app.wait_ready()
                quote=app.call('search',{'kind':'functions','pattern':'quote'})['data']['items'][0]
                result=app.call('trace_calls',{'address':quote['address'],'direction':'callers',
                                             'max_depth':2,'max_nodes':8,'max_edges':16,'max_seconds':2})
                self.assertTrue(result['data']['edges'])
                self.assertTrue(any(x['address']==quote['address'] for x in result['data']['nodes']))
                self.assertGreaterEqual(len(result['data']['nodes']),2)
                self.assertTrue(all('call_site' in x for x in result['data']['edges']))
                record=app.call('read_evidence',{'id':result['evidence']['id']})
                saved=json.loads(record['text'])
                self.assertEqual(saved['analysis']['identity']['application_component']['component_id'],item['component_id'])
                self.assertEqual(saved['analysis']['identity']['selection']['architecture'],'arm64')
            finally:app.close()
            reopened=ApplicationSession(root,base/'workspace')
            try:
                reopened.call('inventory_application',{})
                reopened.call('select_component',{'component_id':item['component_id']})
                self.assertEqual(reopened.call('read_evidence',{'id':result['evidence']['id']})['text'],record['text'])
            finally:reopened.close()
            self.assertEqual(binary.read_bytes(),original)
            self.assertFalse((root/'eaos-analysis').exists())

    def test_quick_trace_does_not_silently_prepare_or_claim_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/'fixture'
            subprocess.run(['clang','-O0',str(Path(__file__).parent/'fixture.c'),'-o',str(binary)],check=True)
            backend=Backend(str(binary),analysis_mode='quick')
            session=McpSession(backend,request_timeout=30,analysis_timeout=30)
            try:
                session.wait_ready()
                found=session.call('search',{'kind':'functions','pattern':'quote'})
                address=found['data']['items'][0]['address']
                before=session.call('open_program',{})['analysis']['revision']
                result=session.call('trace_calls',{'address':address})
                after=session.call('open_program',{})['analysis']['revision']
                self.assertEqual(before,after)
                self.assertFalse(result['data']['coverage']['traversal_complete'])
                self.assertTrue(result['data']['frontier'])
            finally:session.close()
