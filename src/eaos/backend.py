"""Small PyGhidra adapter. A digest-keyed persistent project lives beside the binary."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from .evidence import Evidence
from .swift import decode_small_string
from .runtime import configure


class Backend:
    def __init__(self, target: str):
        self.target = Path(target).expanduser().resolve(strict=True)
        if not self.target.is_file():
            raise ValueError("Target must be a regular file")
        self.digest = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.directory = self.target.parent / 'eaos-analysis' / self.digest
        self.directory.mkdir(parents=True, exist_ok=True)
        self.evidence = Evidence(self.directory / 'evidence', self.digest)
        self.program = self.project = self.consumer = self.decompiler = None
        self.lock = None

    def _load(self):
        if self.program is not None:
            return
        self.lock = (self.directory / 'session.lock').open('a+')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            self.lock = None
            raise RuntimeError("Program is already open in another EAOS process; close it before retrying")
        tools, ghidra, jdk = configure()
        from pyghidra.launcher import HeadlessPyGhidraLauncher
        import pyghidra
        if not pyghidra.started():
            launcher = HeadlessPyGhidraLauncher(install_dir=ghidra)
            state = tools / 'java-state'; state.mkdir(parents=True, exist_ok=True)
            launcher.add_vmargs('-Xmx4G', f'-Duser.home={state}')
            launcher.start()
        from ghidra.util.task import TaskMonitor
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.decompiler import DecompInterface
        monitor = TaskMonitor.DUMMY
        project_dir = self.directory / 'ghidra'; project_dir.mkdir(exist_ok=True)
        self.project = pyghidra.open_project(project_dir, 'program', create=True)
        started = time.monotonic()
        imported = self.project.getProjectData().getFile('/'+self.target.name) is None
        if imported:
            results = pyghidra.program_loader().project(self.project).source(str(self.target)).name(self.target.name).load()
            try:
                results.getPrimary().save(monitor)
            finally:
                results.close()
        self.program, self.consumer = pyghidra.consume_program(self.project, '/'+self.target.name)
        analyzed = False
        if imported or not GhidraProgramUtilities.isAnalyzed(self.program):
            log = pyghidra.analyze(self.program)
            (self.directory / 'analysis.log').write_text(str(log))
            self.program.save('EAOS initial analysis', monitor)
            analyzed = True
        metadata_path = self.directory / 'analysis.json'
        metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
        metadata.update(target=str(self.target), sha256=self.digest,
            ghidra_version='12.1.4', language=str(self.program.getLanguageID()))
        if analyzed:
            metadata['analysis_count'] = metadata.get('analysis_count', 0) + 1
            metadata['analysis_seconds'] = time.monotonic() - started
        metadata_path.write_text(json.dumps(metadata, indent=2))
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(self.program)

    def close(self):
        if self.decompiler is not None:
            self.decompiler.dispose()
            self.decompiler = None
        if self.program is not None:
            self.program.release(self.consumer)
            self.program = None
        if self.project is not None:
            self.project.close()
            self.project = None
        if self.lock is not None:
            fcntl.flock(self.lock, fcntl.LOCK_UN); self.lock.close(); self.lock = None

    def result(self, operation, classification, data, limitations=None, preview=None):
        evidence = self.evidence.save(operation, classification, data, limitations)
        return {'classification': classification, 'data': data if preview is None else preview,
                'limitations': limitations or [],
                'evidence': {'id': evidence['id'], 'uri': evidence['uri']}}

    def address(self, address):
        result = self.program.getAddressFactory().getAddress(str(address))
        if result is None:
            raise ValueError('Invalid program address')
        return result

    def function(self, address):
        addr = self.address(address)
        fn = self.program.getFunctionManager().getFunctionContaining(addr)
        if fn is None:
            raise ValueError('No analyzed function contains this address; inspect references or memory')
        return fn

    def fn_info(self, fn):
        return {'address': str(fn.getEntryPoint()), 'name': str(fn.getName()),
                'signature': str(fn.getSignature()), 'size': int(fn.getBody().getNumAddresses())}

    def open_program(self, full=False):
        self._load()
        blocks = [{'name':str(b.getName()),'start':str(b.getStart()),'end':str(b.getEnd()),
            'read':bool(b.isRead()),'write':bool(b.isWrite()),'execute':bool(b.isExecute())}
            for b in self.program.getMemory().getBlocks()]
        data = {'target': str(self.target), 'sha256': self.digest,
                'language': str(self.program.getLanguageID()),
                'function_count': int(self.program.getFunctionManager().getFunctionCount()),
                'memory': blocks, 'cache':json.loads((self.directory/'analysis.json').read_text())}
        preview = data if full else {k:data[k] for k in ('sha256','language','function_count')}
        if not full:
            preview['analysis_count'] = data['cache'].get('analysis_count')
            preview['memory'] = [{'name':b['name'],'start':b['start'],'end':b['end'],
                'permissions': ''.join(c if b[k] else '-' for c,k in [('r','read'),('w','write'),('x','execute')])} for b in blocks]
        return self.result('open_program','computed',data,
            ['Recovered functions/types are computed, not original source.'], preview)

    def search(self, kind='strings', pattern='', offset=0, limit=30, full=False):
        self._load()
        if not 0 <= offset or not 1 <= limit <= 200:
            raise ValueError('offset must be nonnegative and limit 1..200')
        pattern = pattern.casefold()
        rows = []
        if kind == 'functions':
            for fn in self.program.getFunctionManager().getFunctions(True):
                item = self.fn_info(fn)
                if pattern in (item['name']+' '+item['signature']).casefold(): rows.append(item)
        elif kind == 'strings':
            from java.lang import String
            for item in self.program.getListing().getDefinedData(True):
                value = item.getValue()
                if not isinstance(value, (str, String)): continue
                text = str(value)
                if pattern not in text.casefold(): continue
                refs = list(self.program.getReferenceManager().getReferencesTo(item.getAddress()))
                rows.append({'address':str(item.getAddress()),'text':text,
                    'references':[{'address':str(r.getFromAddress()),
                       'function':self.fn_info(fn) if (fn:=self.program.getFunctionManager().getFunctionContaining(r.getFromAddress())) else None}
                       for r in refs]})
        else:
            raise ValueError('kind must be strings or functions')
        page = rows[offset:offset+limit]
        data = {'kind':kind,'matches':len(rows),'items':page,
                'next_offset':offset+limit if offset+limit<len(rows) else None}
        preview = json.loads(json.dumps(data))
        if not full:
            for item in preview['items']:
                item.pop('signature',None); item.pop('size',None)
                for ref in item.get('references',[]):
                    if ref['function']:
                        ref['function'] = {'address':ref['function']['address']}
        return self.result('search','computed',data,
            ['Only Ghidra-defined strings/functions; other text may be absent.'], preview)

    def inspect(self, addresses, mode='decompile', full=False):
        self._load()
        if not 1 <= len(addresses) <= 8: raise ValueError('Supply 1..8 addresses')
        if mode not in {'decompile','assembly','references','calls','all'}:
            raise ValueError('mode must be decompile, assembly, references, calls or all')
        from ghidra.util.task import TaskMonitor
        rows = []
        for address in addresses:
            addr = self.address(address)
            if mode == 'references':
                refs = [{'from':str(r.getFromAddress()),'to':str(r.getToAddress()),
                    'type':str(r.getReferenceType()),
                    'function':self.fn_info(fn) if (fn:=self.program.getFunctionManager().getFunctionContaining(r.getFromAddress())) else None}
                    for r in self.program.getReferenceManager().getReferencesTo(addr)]
                rows.append({'address':str(addr),'references':refs});continue
            fn = self.function(address); row = self.fn_info(fn)
            if mode in {'decompile','all'}:
                result = self.decompiler.decompileFunction(fn, 60, TaskMonitor.DUMMY)
                if not result.decompileCompleted(): raise RuntimeError(str(result.getErrorMessage()))
                code = str(result.getDecompiledFunction().getC())
                row['pseudocode'] = code
                path = self.directory/'evidence'/f'function-{fn.getEntryPoint()}.c'
                path.write_text(code)
            if mode in {'assembly','all'}:
                row['instructions'] = [{'address':str(i.getAddress()), 'text':str(i),
                    'bytes':bytes((int(b)&255) for b in i.getBytes()).hex()}
                    for i in self.program.getListing().getInstructions(fn.getBody(),True)]
            if mode in {'calls','all'} or (mode=='decompile' and full):
                row['callers'] = sorted([self.fn_info(f) for f in fn.getCallingFunctions(TaskMonitor.DUMMY)],key=lambda f:f['address'])
                row['callees'] = sorted([self.fn_info(f) for f in fn.getCalledFunctions(TaskMonitor.DUMMY)],key=lambda f:f['address'])
            rows.append(row)
        preview = json.loads(json.dumps(rows))
        for row in preview:
            if 'pseudocode' in row:
                cap = 32000 if full else 5000
                row['truncated'] = len(row['pseudocode']) > cap
                row['pseudocode'] = row['pseudocode'][:cap]
            for field in ['instructions','references','callers','callees']:
                if field in row:
                    count = 500 if full else (64 if field=='instructions' else 30)
                    row[field+'_total'] = len(row[field]);row[field] = row[field][:count]
        return self.result('inspect','fact' if mode=='assembly' else 'computed',rows,
            ['Pseudocode, types and call graph are computed static interpretations; indirect calls may be unresolved.'] if mode!='assembly' else [], preview)

    def read_memory(self, address, length=64, format='hex'):
        self._load()
        if format not in {'hex','utf8','both'}: raise ValueError('format must be hex, utf8 or both')
        if not 1 <= length <= 65536: raise ValueError('length must be 1..65536')
        import jpype
        raw = jpype.JArray(jpype.JByte)(length)
        count = self.program.getMemory().getBytes(self.address(address),raw)
        data = bytes(int(x)&255 for x in raw[:count])
        record = {'address':address,'length':count,'hex':data.hex(),
            'utf8':data.decode('utf-8',errors='replace')}
        preview = {k:v for k,v in record.items() if k not in {'hex','utf8'} or format=='both' or k==format}
        return self.result('read_memory','fact',record,preview=preview)

    def calculate(self, expression):
        process = subprocess.run([sys.executable,'-I',str(Path(__file__).with_name('calculator.py'))],
            input=json.dumps({'expression':expression}),capture_output=True,text=True,timeout=4)
        if process.returncode: raise ValueError(process.stderr.strip())
        return self.result('calculate','computed',{'expression':expression,'value':process.stdout.strip()},
            ['Arithmetic establishes the supplied expression, not whether its premises match the binary.'])

    def decode_swift_string(self, words=None, address=None):
        limitations = ['Supports Swift small String storage only; no pointer-backed or Objective-C tagged strings.']
        if address is not None:
            raw = bytes.fromhex(self.read_memory(address,16)['data']['hex'])
            words = [int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:],'little')]
        else:
            limitations.append('Words were supplied by the caller; their presence in this binary is not established.')
        if words is None: raise ValueError('Supply words or a program address')
        return self.result('decode_swift_string','computed',decode_small_string(words),limitations)

    def read_evidence(self, id, offset=0, limit=12000):
        return self.evidence.read(id,offset,limit)
