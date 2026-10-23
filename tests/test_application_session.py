import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from eaos.application_session import ApplicationSession
from eaos.contracts import TOOLS, APPLICATION_TOOLS, validate_arguments


class FakeNative:
    def __init__(self, backend, **kwargs):
        self.backend, self.active, self.state, self.closed = backend, None, 'ready', False
    def close(self):
        self.closed=True
        self.backend.close()
    def call(self,name,arguments,request_id=None):
        if name=='read_evidence':return self.backend.read_evidence(**arguments)
        return self.backend.result(name,'computed',{'component':self.backend.component_context})
    def status(self):return {'state':self.state,'worker_alive':False}
    def wait_ready(self,mode=None):pass
    def cancel(self):self.state='cancelled'
    def cancel_request(self,request_id):self.cancel()
    def forget_request(self,request_id):pass


def image():
    return struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,0,0,0,0)


class ApplicationSessions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'Fixture.app';self.root.mkdir()
        (self.root/'main.js').write_text("ipcMain.handle('one',f); ipcRenderer.invoke('two');")
        (self.root/'first').write_bytes(image());(self.root/'second').write_bytes(image())
        self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)

    def test_directory_catalog_and_explicit_selection(self):
        self.assertEqual({t[0] for t in self.session.tools}, {t[0] for t in TOOLS+APPLICATION_TOOLS})
        self.assertIsNone(self.session.call('open_program',{})['data']['analysis']['selected_component'])
        with self.assertRaisesRegex(ValueError,'select_component'):
            self.session.call('search',{})
        with self.assertRaises(ValueError):
            validate_arguments('trace_calls',{'address':'100','max_seconds':31})
        with self.assertRaises(ValueError):
            validate_arguments('inventory_application',{'path':'/other'})

    def test_javascript_paging_evidence_and_reopening(self):
        inventory=self.session.call('inventory_application',{'pattern':'main.js'})
        component=inventory['data']['items'][0]['component_id']
        first=self.session.call('inspect_javascript',{'component_id':component,'limit':1})
        with self.assertRaisesRegex(ValueError,'missing'):
            self.session.call('inspect_javascript',{'component_id':component,'offset':1})
        second=self.session.call('inspect_javascript',{'component_id':component,'offset':1,'view':first['data']['view']})
        self.assertNotEqual(first['data']['observations'],second['data']['observations'])
        evidence=self.session.call('read_evidence',{'id':first['evidence']['id']})
        record=json.loads(evidence['text']);self.assertEqual(record['data']['component_id'],component)
        self.session.close()
        reopened=ApplicationSession(self.root,self.base/'cache');self.addCleanup(reopened.close)
        reopened.call('inventory_application',{})
        self.assertEqual(reopened.call('read_evidence',{'id':first['evidence']['id']})['text'],evidence['text'])
        with self.assertRaisesRegex(ValueError,'evidence id'):
            reopened.call('read_evidence',{'id':'../../escape'})

    def test_native_component_evidence_isolation_and_capture_identity(self):
        inventory=self.session.call('inventory_application',{})
        components=[row for row in inventory['data']['items'] if row['kind']=='native']
        with patch('eaos.application_session.McpSession',FakeNative):
            self.session.call('select_component',{'component_id':components[0]['component_id']})
            first=self.session.native.backend
            self.assertEqual(first.analysis_mode,'full')
            self.assertFalse(first.target.is_relative_to(self.root))
            result=self.session.call('open_program',{})
            identifier=result['evidence']['id']
            before=self.session.call('read_evidence',{'id':identifier})['text']
            self.assertIn(components[0]['component_id'],before)
            self.session.call('select_component',{'component_id':components[1]['component_id'],'analysis_mode':'quick'})
            self.assertNotEqual(self.session.native.backend.identity,first.identity)
            with self.assertRaises(FileNotFoundError):self.session.call('read_evidence',{'id':identifier})
            self.session.call('select_component',{'component_id':components[0]['component_id']})
            self.assertEqual(self.session.call('read_evidence',{'id':identifier})['text'],before)
        self.assertFalse((self.root/'eaos-analysis').exists())

    def test_local_cancellation_status_and_conflict(self):
        started=threading.Event();errors=[]
        def blocking(**kwargs):
            started.set()
            while not self.session.application.cancelled():time.sleep(.001)
            raise InterruptedError('cancelled inventory')
        def work():
            try:self.session.call('inventory_application',{},request_id=4)
            except Exception as e:errors.append(e)
        with patch.object(self.session.application,'inventory',blocking):
            thread=threading.Thread(target=work);thread.start();self.assertTrue(started.wait(1))
            self.assertEqual(self.session.status()['operation'],'inventory_application')
            with self.assertRaisesRegex(RuntimeError,'active'):
                self.session.call('select_component',{'component_id':'a'*64})
            self.session.cancel_request(4);thread.join(1)
            self.assertFalse(thread.is_alive());self.assertIsInstance(errors[0],InterruptedError)
        self.assertFalse(self.session.application.workspace.exists())

    def test_cancellation_does_not_wait_for_previous_owner_shutdown(self):
        items=self.session.call('inventory_application',{})['data']['items']
        native=[x for x in items if x['kind']=='native']
        started=threading.Event();release=threading.Event();errors=[]
        with patch('eaos.application_session.McpSession',FakeNative):
            self.session.call('select_component',{'component_id':native[0]['component_id']})
            owner=self.session.native;original_close=owner.close
            def slow_close():
                started.set();release.wait(2);original_close()
            def work():
                try:self.session.call('select_component',{'component_id':native[1]['component_id']},request_id=7)
                except Exception as e:errors.append(e)
            with patch.object(owner,'close',slow_close):
                worker=threading.Thread(target=work);worker.start();self.assertTrue(started.wait(1))
                done=threading.Event()
                canceller=threading.Thread(target=lambda:(self.session.cancel_request(7),done.set()))
                canceller.start()
                try:self.assertTrue(done.wait(.3),'Cancellation waited on the owner shutdown lock')
                finally:release.set();worker.join(2);canceller.join(2)
            self.assertIsInstance(errors[0],InterruptedError)
            self.assertIsNone(self.session.native)

    def test_component_selection_refuses_dispatch_gap(self):
        native=[x for x in self.session.call('inventory_application',{})['data']['items'] if x['kind']=='native']
        started=threading.Event();release=threading.Event();errors=[]
        with patch('eaos.application_session.McpSession',FakeNative):
            self.session.call('select_component',{'component_id':native[0]['component_id']})
            owner=self.session.native;original_call=owner.call
            def delayed(*args,**kwargs):
                started.set();release.wait(2);return original_call(*args,**kwargs)
            def work():
                try:self.session.call('search',{})
                except Exception as e:errors.append(e)
            with patch.object(owner,'call',delayed):
                worker=threading.Thread(target=work);worker.start();self.assertTrue(started.wait(1))
                try:
                    with self.assertRaisesRegex(RuntimeError,'Native work is active'):
                        self.session.call('select_component',{'component_id':native[1]['component_id']})
                    self.assertIs(self.session.native,owner)
                finally:release.set();worker.join(2)
            self.assertEqual(errors,[])
