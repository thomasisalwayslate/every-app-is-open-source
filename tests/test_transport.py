import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest


class ResponsiveTransport(unittest.TestCase):
    def test_terminal_calculation_does_not_initialize_native_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'target';target.write_bytes(b'not executable')
            result=subprocess.run([sys.executable,'-m','eaos.cli','call',str(target),'calculate',
                '--args','{"expression":"6*7"}'],capture_output=True,text=True,timeout=10,
                env={**os.environ,'EAOS_RUNTIME_DIR':str(Path(temporary)/'missing-runtime')})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['data']['value'],'42')

    def server(self,timeout=10,target=None,discovery=False,pause=None):
        if target is None:
            temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
            target=Path(temp.name)/'target';target.write_bytes(b'fake native owner, never executed')
        command=[sys.executable,str(Path(__file__).with_name('session_server_fixture.py')),str(target),'--timeout',str(timeout)]
        if discovery:command+=['--discovery']
        if pause:command+=['--pause-index',str(pause)]
        process=subprocess.Popen(command,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.addCleanup(lambda: self.close(process))
        self.send(process,1,'tools/call',{'name':'open_program'})
        opened=self.read(process);self.assertEqual(opened['id'],1)
        pid=json.loads(opened['result']['content'][0]['text'])['data']['worker_pid']
        return process,pid

    @staticmethod
    def send(process,identifier,method,params=None):
        value={'jsonrpc':'2.0','method':method,'params':params or {}}
        if identifier is not None:value['id']=identifier
        process.stdin.write((json.dumps(value)+'\n').encode());process.stdin.flush()

    def read(self,process,timeout=5):
        if not select.select([process.stdout],[],[],timeout)[0]:
            self.fail('Transport response deadline exceeded')
        line=process.stdout.readline()
        if not line:self.fail('Server closed: '+process.stderr.read().decode())
        return json.loads(line)

    @staticmethod
    def close(process):
        if not process.stdin.closed:process.stdin.close()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stdout.close();process.stderr.close()

    def test_ping_status_cancellation_and_owned_worker_shutdown(self):
        process,pid=self.server()
        self.send(process,None,'notifications/cancelled',['invalid parameters'])
        self.send(process,2,'tools/call',{'name':'search'})
        time.sleep(0.1)
        start=time.monotonic()
        self.send(process,3,'ping');self.send(process,4,'tools/call',{'name':'open_program'})
        replies={}
        for _ in range(2):
            reply=self.read(process);replies[reply['id']]=reply
        self.assertEqual(replies[3]['result'],{})
        status=json.loads(replies[4]['result']['content'][0]['text'])['data']['analysis']
        self.assertEqual(status['operation']['tool'],'search')
        self.assertLess(time.monotonic()-start,1)
        self.send(process,None,'notifications/cancelled',{'requestId':2})
        reply=self.read(process)
        self.assertEqual(reply['id'],2);self.assertTrue(reply['result']['isError'])
        self.send(process,5,'ping');self.assertEqual(self.read(process)['id'],5)
        process.stdin.close();process.wait(timeout=5)
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_deadline_and_eof_stop_owned_native_work(self):
        for timeout,eof in [(0.2,False),(10,True)]:
            with self.subTest(timeout=timeout):
                process,pid=self.server(timeout)
                self.send(process,2,'tools/call',{'name':'search'})
                if eof:
                    time.sleep(0.1);process.stdin.close();process.wait(timeout=5)
                else:
                    reply=self.read(process)
                    failure=json.loads(reply['result']['content'][0]['text'])
                    self.assertIn('deadline',failure['error'])
                    process.stdin.close();process.wait(timeout=5)
                with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_back_to_back_cancel_and_ping_do_not_wait_for_worker_shutdown(self):
        process,pid=self.server()
        self.send(process,2,'tools/call',{'name':'search'})
        time.sleep(0.1)
        start=time.monotonic()
        self.send(process,None,'notifications/cancelled',{'requestId':2})
        self.send(process,3,'ping')
        replies={}
        while 3 not in replies:
            reply=self.read(process,timeout=0.5);replies[reply['id']]=reply
        elapsed=time.monotonic()-start
        self.assertEqual(replies[3]['result'],{})
        self.assertLess(elapsed,0.5,'Ping waited for worker shutdown')
        print(f'Cancellation-to-ping: {elapsed:.4f}s',flush=True)
        # Cancellation is already accepted, but its worker is still being reaped.
        self.send(process,4,'tools/call',{'name':'search'})
        self.send(process,5,'tools/call',{'name':'open_program','arguments':{'analysis_mode':'quick'}})
        while not {2,4,5}<=replies.keys():
            reply=self.read(process);replies[reply['id']]=reply
        self.assertTrue(replies[2]['result']['isError'])
        self.assertTrue(replies[4]['result']['isError'])
        status=json.loads(replies[5]['result']['content'][0]['text'])['data']['analysis']
        self.assertEqual(status['state'],'cancelling')
        self.assertTrue(status['worker_alive'])
        process.stdin.close();process.wait(timeout=5)
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_cancelled_index_transaction_reopens_old_prefix_and_evidence(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        target=Path(temporary.name)/'target';target.write_bytes(b'portable index cancellation fixture')
        marker=target.parent/'paused'
        process,pid=self.server(target=target,discovery=True,pause=marker)
        self.send(process,2,'tools/call',{'name':'search','arguments':{'kind':'functions'}})
        first=json.loads(self.read(process)['result']['content'][0]['text'])
        cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
        self.send(process,3,'tools/call',{'name':'search','arguments':{'kind':'functions','index_cursor':cursor}})
        deadline=time.monotonic()+5
        while not marker.exists()and time.monotonic()<deadline:time.sleep(0.01)
        self.assertTrue(marker.exists(),'Expansion never reached the uncommitted row')
        self.send(process,4,'tools/call',{'name':'search','arguments':{'kind':'functions'}})
        conflict=self.read(process)
        self.assertEqual(conflict['id'],4);self.assertTrue(conflict['result']['isError'])
        status=json.loads(conflict['result']['content'][0]['text'])['analysis']
        self.assertEqual(status['operation']['tool'],'search')
        began=time.monotonic()
        self.send(process,None,'notifications/cancelled',{'requestId':3});self.send(process,5,'ping')
        replies={}
        while 5 not in replies:
            reply=self.read(process,0.5);replies[reply['id']]=reply
        self.assertLess(time.monotonic()-began,0.5)
        process.stdin.close();process.wait(timeout=5)
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        reopened,_=self.server(target=target,discovery=True)
        self.send(reopened,2,'tools/call',{'name':'search','arguments':{'kind':'functions'}})
        restored=json.loads(self.read(reopened)['result']['content'][0]['text'])
        self.assertEqual(restored['data']['coverage']['function_candidates']['candidates_indexed'],2)
        self.send(reopened,3,'tools/call',{'name':'read_evidence','arguments':{'id':first['evidence']['id']}})
        evidence=json.loads(self.read(reopened)['result']['content'][0]['text'])
        self.assertIn(first['evidence']['id'],evidence['text'])
        self.send(reopened,4,'tools/call',{'name':'search','arguments':{'kind':'functions','index_cursor':cursor}})
        continued=json.loads(self.read(reopened)['result']['content'][0]['text'])
        self.assertEqual(continued['data']['coverage']['function_candidates']['candidates_indexed'],4)
        self.assertEqual([r['address']for r in continued['data']['items']],['00000100','00000104','00000108','0000010c'])


if __name__=='__main__':unittest.main()
