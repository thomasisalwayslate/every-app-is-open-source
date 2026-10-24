"""MCP reader responsiveness with a deliberately slow owned parser stand-in."""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SCRIPT = r'''
import subprocess,sys
from pathlib import Path
from eaos.cli import serve
from eaos.application_session import ApplicationSession
import eaos.js_index
real_popen=subprocess.Popen
marker=Path(sys.argv[3])
def stand_in(*args,**kwargs):
    if 'eaos.js_worker' not in args[0]:return real_popen(*args,**kwargs)
    process=real_popen([sys.executable,'-c','import sys,time;sys.stdin.buffer.read();time.sleep(30)'],**kwargs)
    with marker.open('a') as output:output.write(str(process.pid)+'\n')
    return process
eaos.js_index.subprocess.Popen=stand_in
serve(ApplicationSession(sys.argv[1],sys.argv[2]))
'''


class SyntaxTransport(unittest.TestCase):
    def test_cancel_then_ping_and_eof_reap_workers(self):
        self.exercise_transport({})

    def test_selected_module_and_ancestor_cancellation_use_the_same_owner(self):
        for kind in ('calls','ancestors'):
            with self.subTest(kind=kind):
                self.exercise_transport({'module_at':0,'module_kind':kind})

    def exercise_transport(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'Fixture.app';root.mkdir()
            (root/'main.js').write_text('obj.handle("channel",f)')
            marker=base/'owned-pids'
            with (base/'stderr.log').open('w') as stderr:
                process=subprocess.Popen([sys.executable,'-c',SCRIPT,str(root),str(base/'cache'),str(marker)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True,bufsize=1)
                inbox=queue.Queue();pending={}
                reader=threading.Thread(target=lambda:[inbox.put(json.loads(line)) for line in process.stdout],daemon=True)
                reader.start()
                def send(method,params=None,identifier=None):
                    data={'jsonrpc':'2.0','method':method,'params':params or {}}
                    if identifier is not None:data['id']=identifier
                    process.stdin.write(json.dumps(data)+'\n');process.stdin.flush()
                def receive(identifier):
                    deadline=time.monotonic()+5
                    while identifier not in pending:
                        value=inbox.get(timeout=max(.001,deadline-time.monotonic()))
                        pending[value['id']]=value
                    return pending.pop(identifier)
                def started(count):
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        if marker.exists() and len(marker.read_text().splitlines())>=count:return
                        time.sleep(.005)
                    self.fail('owned stand-in never started')
                try:
                    send('tools/call',{'name':'inventory_application','arguments':{}},1)
                    inv=receive(1)
                    component=json.loads(inv['result']['content'][0]['text'])['data']['items'][0]['component_id']
                    params={'name':'inspect_javascript','arguments':dict(component_id=component,**mode)}
                    send('tools/call',params,2);started(1)
                    send('tools/call',{'name':'select_component','arguments':{'component_id':component}},3)
                    busy=receive(3)['result']
                    self.assertTrue(busy['isError'])
                    self.assertIn('Another selected-root operation is active',json.dumps(busy))
                    start=time.monotonic()
                    send('notifications/cancelled',{'requestId':2})
                    send('ping',identifier=4)
                    self.assertEqual(receive(4)['result'],{})
                    self.assertLess(time.monotonic()-start,.8)
                    self.assertTrue(receive(2)['result']['isError'])
                    send('tools/call',params,5);started(2)
                    process.stdin.close();process.wait(timeout=3)
                    reader.join(2)
                    self.assertEqual(process.returncode,0)
                    for pid in marker.read_text().splitlines():
                        with self.assertRaises(ProcessLookupError):os.kill(int(pid),0)
                    self.assertFalse(list((base/'cache').rglob('current.json')))
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=3)
                    process.stdout.close()
