"""Small PyGhidra adapter. A digest-keyed persistent project lives beside the binary."""
from __future__ import annotations

import fcntl
from bisect import bisect_left
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tempfile
from pathlib import Path

from .contracts import validated_tool
from .evidence import Evidence
from .swift import decode_small_string
from .runtime import configure
from . import golang


class ProgramBusyError(RuntimeError):
    """Another EAOS process currently owns this program's analysis lock."""


class Backend:
    def __init__(self, target: str):
        self.target = Path(target).expanduser().resolve(strict=True)
        if not self.target.is_file():
            raise ValueError("Target must be a regular file")
        analysis_root = self.target.parent / 'eaos-analysis'
        analysis_root.mkdir(exist_ok=True)
        # Hash the bytes that Ghidra will actually import, not a path read later.
        with tempfile.TemporaryDirectory(prefix='capture-', dir=analysis_root) as temporary:
            captured = Path(temporary) / self.target.name
            digest = hashlib.sha256()
            with self.target.open('rb') as source, captured.open('wb') as output:
                before = os.fstat(source.fileno())
                while block := source.read(1024 * 1024):
                    output.write(block)
                    digest.update(block)
                after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise RuntimeError('Target changed during capture; retry with a stable file')
            self.digest = digest.hexdigest()
            self.directory = analysis_root / self.digest
            snapshot_dir = self.directory / 'input'
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            self.snapshot = snapshot_dir / self.target.name
            if self.snapshot.exists():
                with self.snapshot.open('rb') as existing:
                    if hashlib.file_digest(existing, 'sha256').hexdigest() != self.digest:
                        raise RuntimeError('Stored input snapshot is corrupt; move this analysis directory aside before retrying')
            else:
                captured.chmod(0o444)
                captured.replace(self.snapshot)
        self.evidence = Evidence(self.directory / 'evidence', self.digest)
        self.program = self.project = self.consumer = self.decompiler = None
        self.lock = None
        self.on_stage = None
        self.go_index = None
        self.go_functions = {}
        self.go_literals = []
        self.go_status = None

    def _report_stage(self, stage):
        if self.on_stage is not None:
            self.on_stage(stage)

    def _load(self):
        if self.program is not None:
            return
        self.lock = (self.directory / 'session.lock').open('a+')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            self.lock = None
            raise ProgramBusyError("Program is already open in another EAOS process; close it before retrying")
        try:
            self._load_project()
        except BaseException:
            self.close()
            raise

    def _load_project(self):
        self._report_stage('starting')
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
        self._report_stage('importing' if imported else 'loading_cache')
        if imported:
            results = pyghidra.program_loader().project(self.project).source(str(self.snapshot)).name(self.target.name).load()
            try:
                results.getPrimary().save(monitor)
            finally:
                results.close()
        self.program, self.consumer = pyghidra.consume_program(self.project, '/'+self.target.name)
        imported_digest = str(self.program.getExecutableSHA256()).lower()
        if imported_digest != self.digest:
            raise RuntimeError(
                'Ghidra program hash does not match the captured input. '
                'The cache may be from an affected 0.1.0 session; move this '
                'analysis directory aside and retry. Existing evidence was preserved.'
            )
        analyzed = False
        if imported or not GhidraProgramUtilities.isAnalyzed(self.program):
            self._report_stage('analyzing')
            log = pyghidra.analyze(self.program)
            self._report_stage('saving')
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
        self._load_go()
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(self.program)

    def _block_bytes(self, block, maximum=golang.MAX_TABLE_BYTES):
        import jpype
        size = int(block.getSize())
        if size > maximum:
            raise golang.UnsupportedGo('Go memory block exceeds the read budget')
        buffer = jpype.JArray(jpype.JByte)(size)
        count = self.program.getMemory().getBytes(block.getStart(), buffer)
        if count != size:
            raise golang.UnsupportedGo('Could not read complete Go memory block')
        # Conversion through Java's byte buffer avoids one Python call per byte.
        return bytes(buffer)

    def _load_go(self):
        self.go_index, self.go_functions, self.go_literals, self.go_status = None, {}, [], None
        blocks = list(self.program.getMemory().getBlocks())
        named = [b for b in blocks if 'gopclntab' in str(b.getName())]
        build = [b for b in blocks if 'go_buildinfo' in str(b.getName()) or str(b.getName())=='.go.buildinfo']
        detected = bool(named or build or str(self.program.getCompilerSpec().getCompilerSpecID())=='golang')
        if not detected:
            return
        self._report_stage('indexing_go')
        self.go_status = {'version':None, 'names':'unavailable', 'literal_search':'unavailable',
                          'parser_version':golang.PARSER_VERSION}
        for block in build:
            try:self.go_status['version'] = golang.build_version(self._block_bytes(block, 1024*1024))
            except golang.UnsupportedGo:pass
        executable = [(int(b.getStart().getOffset()), int(b.getEnd().getOffset())+1)
                      for b in blocks if b.isExecute() and b.isInitialized()]
        text = [int(b.getStart().getOffset()) for b in blocks
                if str(b.getName()) in ('__text','.text') and b.isExecute()]
        candidates = named or [b for b in blocks if b.isInitialized() and b.isRead() and not b.isExecute()]
        try:
            budget = golang.MAX_TABLE_BYTES
            found = False
            for block in candidates:
                size = int(block.getSize())
                if size > budget:continue
                raw = self._block_bytes(block); budget -= size
                # Named sections start at the header; other containers may embed it.
                offsets = [0] if named else golang.header_offsets(raw)
                for at in offsets:
                    table = raw[at:]
                    try:
                        table_address = int(block.getStart().getOffset())+at
                        table_hash = hashlib.sha256(table).hexdigest()
                        path = self.directory/'go-index-v1.json'
                        index = golang.read_cache(path, self.digest, table_hash)
                        # The memory map is checked even when reusing an index.
                        if index and not all(any(low <= int(f['address'],16) < int(f['end'],16) <= high
                                                for low, high in executable) for f in index['functions']):
                            index = None
                        if index is None:
                            index = golang.parse_pclntab(table, table_address, text[0] if len(text)==1 else None, executable)
                            index['target_sha256'] = self.digest
                            if path.exists():
                                # Retain invalid/stale cache bytes instead of hiding the failed attempt.
                                retained = self.directory/('go-index-replaced-'+str(time.time_ns())+'.json')
                                path.rename(retained)
                                if path.with_suffix('.sha256').exists():
                                    path.with_suffix('.sha256').rename(retained.with_suffix('.sha256'))
                            golang.write_cache(path, index)
                        self.go_index = index
                        self.go_functions = {f['address']:f for f in index['functions']}
                        self.go_status.update(names='available',function_count=index['function_count'],format=index['format'])
                        self.go_status.pop('names_error',None)
                        found = True
                        break
                    except golang.UnsupportedGo as error:
                        self.go_status['names_error'] = str(error)
                if found:break
            if not found:
                self.go_status.setdefault('names_error','No supported Go function table within the 64 MiB scan budget')
        except golang.UnsupportedGo as error:
            self.go_status['names_error'] = str(error)
        budget = golang.MAX_TABLE_BYTES
        skipped = []
        for block in blocks:
            if not block.isInitialized() or not block.isRead() or block.isWrite() or block.isExecute():continue
            if 'gopclntab' in str(block.getName()):continue
            size = int(block.getSize())
            if size > budget:
                skipped.append(str(block.getStart()));continue
            self.go_literals.append((int(block.getStart().getOffset()),self._block_bytes(block)))
            budget -= size
        self.go_status.update(literal_search='partial' if skipped else 'available',
                              literal_bytes=golang.MAX_TABLE_BYTES-budget)
        if skipped:self.go_status['literal_skipped_blocks'] = skipped

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
        go = self.go_functions.get(f'{int(addr.getOffset()):x}')
        if go and fn is not None and fn.getEntryPoint() != addr:
            raise ValueError('Go metadata identifies '+go['name']+
                             ', but Ghidra has an overlapping function with a different entry; '
                             'inspect references or memory instead of attributing its pseudocode to this name')
        if fn is None:
            extra = ' Go metadata identifies '+go['name']+', but this is not an analyzed Ghidra function.' if go else ''
            raise ValueError('No analyzed function contains this address; inspect references or memory.'+extra)
        return fn

    def fn_info(self, fn):
        item = {'address': str(fn.getEntryPoint()), 'name': str(fn.getName()),
                'signature': str(fn.getSignature()), 'size': int(fn.getBody().getNumAddresses())}
        go = self.go_functions.get(f'{int(fn.getEntryPoint().getOffset()):x}')
        if go:
            item.update(name=go['name'],ghidra_name=item['name'],source='go_pclntab',end=go['end'],
                        name_address=go['name_address'],record_address=go['record_address'])
        return item

    @validated_tool('open_program')
    def open_program(self, full=False):
        self._load()
        blocks = [{'name':str(b.getName()),'start':str(b.getStart()),'end':str(b.getEnd()),
            'read':bool(b.isRead()),'write':bool(b.isWrite()),'execute':bool(b.isExecute())}
            for b in self.program.getMemory().getBlocks()]
        data = {'target': str(self.target), 'sha256': self.digest,
                'language': str(self.program.getLanguageID()),
                'function_count': int(self.program.getFunctionManager().getFunctionCount()),
                'memory': blocks, 'cache':json.loads((self.directory/'analysis.json').read_text())}
        if self.go_status is not None:data['go'] = self.go_status
        preview = data if full else {k:data[k] for k in ('sha256','language','function_count')}
        if not full:
            preview['analysis_count'] = data['cache'].get('analysis_count')
            preview['memory'] = [{'name':b['name'],'start':b['start'],'end':b['end'],
                'permissions': ''.join(c if b[k] else '-' for c,k in [('r','read'),('w','write'),('x','execute')])} for b in blocks]
            if self.go_status is not None:preview['go'] = self.go_status
        return self.result('open_program','computed',data,
            ['Recovered functions/types are computed, not original source.'], preview)

    @validated_tool('search')
    def search(self, kind='strings', pattern='', offset=0, limit=30, full=False):
        self._load()
        if not 0 <= offset or not 1 <= limit <= 200:
            raise ValueError('offset must be nonnegative and limit 1..200')
        query = pattern
        pattern = pattern.casefold()
        rows = []
        limitations = ['Search is static discovery, not proof of runtime behavior or absence of other text.']
        coverage = None
        if kind == 'functions':
            seen = set()
            for fn in self.program.getFunctionManager().getFunctions(True):
                item = self.fn_info(fn)
                seen.add(f'{int(fn.getEntryPoint().getOffset()):x}')
                if pattern in (item['name']+' '+item['signature']+' '+item.get('ghidra_name','')).casefold(): rows.append(item)
            for item in self.go_functions.values():
                if item['address'] not in seen and pattern in item['name'].casefold():
                    rows.append({**item,'source':'go_pclntab','analyzed_function':False})
        elif kind == 'strings':
            from java.lang import String
            literals, complete = golang.literal_matches(self.go_literals,query) if self.go_status and query else ([],True)
            literals.sort(key=lambda item:int(item['address'],16))
            raw_addresses = [int(item['address'],16) for item in literals]
            for item in self.program.getListing().getDefinedData(True):
                value = item.getValue()
                if not isinstance(value, (str, String)): continue
                text = str(value)
                if pattern not in text.casefold(): continue
                start = int(item.getAddress().getOffset());end = start+int(item.getLength())
                contained = range(bisect_left(raw_addresses,start),bisect_left(raw_addresses,end))
                if contained:
                    for i in contained:
                        literals[i]['defined_data'] = {'address':str(item.getAddress()),'text':text,'byte_length':int(item.getLength())}
                else:
                    rows.append({'address':str(item.getAddress()),'text':text,'source':'ghidra_defined','extent':'defined_data'})
            rows.extend(literals)
            if self.go_status:
                coverage = {'literal_bytes':self.go_status['literal_bytes'],
                    'scope':'initialized read-only non-executable blocks, excluding named pclntab',
                    'literal_search_performed':bool(query),
                    'complete':bool(query) and complete and self.go_status['literal_search']=='available',
                    'literal_ranges':[{'start':f'{address:x}','end':f'{address+len(raw):x}'} for address,raw in self.go_literals],
                    'case_matching':'ASCII-insensitive; other UTF-8 literals exact'}
                if not complete:limitations.append('Literal matches stopped at 10000; refine the pattern. matches is a lower bound.')
                if not query:limitations.append('Empty patterns list defined strings only; raw Go literal search requires a pattern.')
                limitations.append('literal_bytes rows are matched slices, not complete Go string objects; references are Ghidra computations.')
        else:
            raise ValueError('kind must be strings or functions')
        rows.sort(key=lambda item:int(item['address'],16))
        page = rows[offset:offset+limit]
        if kind=='strings':
            for item in page:
                refs = []
                for ref in self.program.getReferenceManager().getReferencesTo(self.address(item['address'])):
                    if len(refs)==4096:
                        item['references_complete']=False;break
                    fn = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                    refs.append({'address':str(ref.getFromAddress()),'type':str(ref.getReferenceType()),
                                 'function':self.fn_info(fn) if fn else None})
                item['references']=refs
                refs.sort(key=lambda ref:(ref['function'] is None,int(ref['address'],16),ref['type']))
                item['reference_count']=len(refs)
                item.setdefault('references_complete',True)
        if self.go_index:
            provenance = {k:v for k,v in self.go_index.items() if k!='functions'}
        else:provenance=None
        data = {'kind':kind,'matches':len(rows),'items':page,
                'next_offset':offset+limit if offset+limit<len(rows) else None}
        if coverage is not None:data['coverage']=coverage
        if provenance is not None:data['go_metadata']=provenance
        if self.go_status and self.go_status['names']=='unavailable' and kind=='functions':
            limitations.append('Go metadata names unavailable: '+self.go_status['names_error'])
        preview = json.loads(json.dumps(data))
        if not full and 'coverage' in preview:preview['coverage'].pop('literal_ranges',None)
        if not full:
            for item in preview['items']:
                item.pop('signature',None); item.pop('size',None)
                item.pop('name_address',None);item.pop('record_address',None)
                item.pop('defined_data',None)
                cap = 256
                if 'text' in item and len(item['text'])>cap:
                    item['text_total']=len(item['text']);item['text']=item['text'][:cap];item['text_truncated']=True
                if 'references' in item:
                    item['references_truncated']=len(item['references'])>8 or not item['references_complete']
                    item['references']=item['references'][:8]
                for ref in item.get('references',[]):
                    if ref['function']:
                        ref['function'] = {'address':ref['function']['address']}
        preview.pop('go_metadata',None)
        return self.result('search','computed',data,limitations, preview if not full else data)

    @validated_tool('inspect')
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
        if self.go_index:
            for row in rows:
                if row.get('source')=='go_pclntab':
                    row['go_metadata']={k:v for k,v in self.go_index.items() if k!='functions'}
        preview = json.loads(json.dumps(rows))
        for row in preview:
            if not full:
                row.pop('go_metadata',None);row.pop('name_address',None);row.pop('record_address',None)
            if 'pseudocode' in row:
                cap = 32000 if full else 5000
                row['truncated'] = len(row['pseudocode']) > cap
                row['pseudocode'] = row['pseudocode'][:cap]
            for field in ['instructions','references','callers','callees']:
                if field in row:
                    count = 500 if full else (64 if field=='instructions' else 30)
                    row[field+'_total'] = len(row[field]);row[field] = row[field][:count]
        computed_names = any(row.get('source')=='go_pclntab' for row in rows)
        return self.result('inspect','fact' if mode=='assembly' and not computed_names else 'computed',rows,
            ['Pseudocode, recovered names, types and call graph are computed static interpretations; indirect calls may be unresolved.'] if mode!='assembly' or computed_names else [], preview)

    @validated_tool('read_memory')
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

    @validated_tool('calculate')
    def calculate(self, expression):
        process = subprocess.run([sys.executable,'-I',str(Path(__file__).with_name('calculator.py'))],
            input=json.dumps({'expression':expression}),capture_output=True,text=True,timeout=4)
        if process.returncode: raise ValueError(process.stderr.strip())
        return self.result('calculate','computed',{'expression':expression,'value':process.stdout.strip()},
            ['Arithmetic establishes the supplied expression, not whether its premises match the binary.'])

    @validated_tool('decode_swift_string')
    def decode_swift_string(self, words=None, address=None):
        limitations = ['Supports Swift small String storage only; no pointer-backed or Objective-C tagged strings.']
        if address is not None:
            raw = bytes.fromhex(self.read_memory(address,16)['data']['hex'])
            words = [int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:],'little')]
        else:
            limitations.append('Words were supplied by the caller; their presence in this binary is not established.')
        if words is None: raise ValueError('Supply words or a program address')
        return self.result('decode_swift_string','computed',decode_small_string(words),limitations)

    @validated_tool('read_evidence')
    def read_evidence(self, id, offset=0, limit=12000):
        return self.evidence.read(id,offset,limit)
