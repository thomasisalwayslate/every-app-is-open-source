"""Transport test server with a deliberately blocking fake native operation."""
import argparse
import os
import time
from pathlib import Path
from types import SimpleNamespace
from eaos.backend import Backend
from eaos.session import McpSession
from eaos.cli import serve


class BlockingBackend(Backend):
    def _load(self):pass

    def open_program(self, full=False, **kwargs):
        return self.result('open_program','computed',{'worker_pid':os.getpid()})

    def search(self, **kwargs):
        self._report_stage('fixture_blocking_operation')
        time.sleep(30)
        return self.result('search','computed',{'items':[]})


class FixtureSymbols:
    def __init__(self,pause):self.pause=pause
    def getPrimarySymbol(self,address):
        if self.pause and address=='0000010c':
            Path(self.pause).write_text('expansion has an uncommitted row')
            time.sleep(30)
        return None
    def getSymbols(self,address):return []


class DiscoveryBackend(Backend):
    def __init__(self,target,pause):
        super().__init__(target,analysis_mode='quick');self.pause=pause

    def _load(self):
        if self.program is not None:return
        from eaos import quick
        quick.MAX_NAME_CANDIDATES=2
        manager=SimpleNamespace(getFunctions=lambda _:[],getExternalFunctions=lambda:[],getFunctionAt=lambda _:None)
        space=SimpleNamespace(getAddress=lambda n:f'{n:08x}')
        symbols=FixtureSymbols(self.pause)
        self.program=SimpleNamespace(getFunctionManager=lambda:manager,getSymbolTable=lambda:symbols,
            getAddressFactory=lambda:SimpleNamespace(getDefaultAddressSpace=lambda:space),
            getLanguageID=lambda:'fixture',getCompilerSpec=lambda:SimpleNamespace(getCompilerSpecID=lambda:'fixture'),
            release=lambda _:None)
        self.quick_metadata={'function_starts':[0x100,0x104,0x108,0x10c,0x110]}
        self.metadata_status='portable synthetic metadata fixture'

    def open_program(self,full=False,**kwargs):
        return self.result('open_program','computed',{'worker_pid':os.getpid()})


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('target');parser.add_argument('--timeout',type=float,default=10)
    parser.add_argument('--discovery',action='store_true');parser.add_argument('--pause-index')
    args=parser.parse_args()
    backend=DiscoveryBackend(args.target,args.pause_index)if args.discovery else BlockingBackend(args.target)
    session=McpSession(backend,initial_wait=2,request_timeout=args.timeout)
    try:serve(session)
    finally:session.close()
