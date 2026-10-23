"""Small PyGhidra adapter. A digest-keyed persistent project lives beside the binary."""
from __future__ import annotations

import fcntl
from bisect import bisect_left
from collections import OrderedDict
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tempfile
from pathlib import Path

from .contracts import validated_tool, validate_search_profile
from .evidence import Evidence
from .swift import decode_small_string
from .runtime import configure
from . import golang
from . import inspection, native_inspection, memory, identity


class ProgramBusyError(RuntimeError):
    """Another EAOS process currently owns this program's analysis lock."""


class Backend:
    def __init__(self, target: str, architecture='auto', analysis_mode='full'):
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
        self.capture_directory = self.directory
        self.evidence = Evidence(self.capture_directory / 'evidence', self.digest)
        self.selection = identity.select(self.snapshot, architecture)
        self.architecture = architecture
        self.import_snapshot = self.snapshot
        if self.selection and self.selection['universal']:
            self.import_snapshot = self.snapshot.parent / ('slice-'+self.selection['sha256'])
            if not self.import_snapshot.exists():
                with self.snapshot.open('rb') as source, self.import_snapshot.open('xb') as output:
                    source.seek(self.selection['offset'])
                    remaining = self.selection['size']
                    while remaining:
                        block = source.read(min(1024*1024, remaining))
                        if not block:
                            raise ValueError('Captured universal slice is truncated')
                        output.write(block)
                        remaining -= len(block)
                self.import_snapshot.chmod(0o444)
            with self.import_snapshot.open('rb') as source:
                if hashlib.file_digest(source, 'sha256').hexdigest() != self.selection['sha256']:
                    raise ValueError('Stored selected slice is corrupt; original evidence was preserved')
        self.analysis_mode = analysis_mode
        self._set_profile(analysis_mode)
        self.program = self.project = self.consumer = self.decompiler = None
        self.lock = None
        self.on_stage = None
        self.go_index = None
        self.go_functions = {}
        self.go_literals = []
        self.go_status = None
        self.inspection_cache = OrderedDict()
        self.inspection_cache_bytes = 0
        self.zero_fill_metadata = None
        self.revision = 0
        self.function_readiness = {}
        self.quick_metadata = None
        self.discovery_index = None
        self.quick_name_coverage = None
        self.literal_blocks = []
        self.metadata_status = 'not_started'
        self.monitor = None

    def _set_profile(self, mode):
        self.identity = identity.context(self.digest, self.selection, mode)
        self.analysis_mode = mode
        self.directory = self.capture_directory / 'profiles' / identity.key(self.identity)
        self.directory.mkdir(parents=True, exist_ok=True)

    def coverage(self):
        return {'profile': self.analysis_mode, 'scope': 'partial' if self.analysis_mode=='quick' else
                'whole_program_pass' if self.metadata_status=='full_pass_finished' else 'not_ready',
                'revision': self.revision, 'functions_prepared': len(self.function_readiness),
                'references': 'incomplete; absence is not established', 'metadata': self.metadata_status}

    def provenance(self):
        return {**self.coverage(), 'identity': self.identity,
                **({'language': str(self.program.getLanguageID()),
                    'compiler': str(self.program.getCompilerSpec().getCompilerSpecID())} if self.program is not None else {})}

    def _report_stage(self, stage):
        if self.on_stage is not None:
            self.on_stage(stage)

    def _load(self):
        if self.program is not None:
            return
        self.lock = (self.capture_directory / 'session.lock').open('a+')
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
        from ghidra.util.task import TaskMonitorAdapter
        self.monitor = monitor = TaskMonitorAdapter()
        manifest = self.directory / 'identity.json'
        if manifest.exists():
            if json.loads(manifest.read_text()) != self.identity:
                raise RuntimeError('Analysis cache identity mismatch; cache and evidence were preserved')
        elif (self.directory / 'ghidra').exists():
            raise RuntimeError('Analysis cache identity missing; cache was preserved')
        else:
            manifest.write_text(json.dumps(self.identity, sort_keys=True, indent=2))
        project_dir = self.directory / 'ghidra'; project_dir.mkdir(exist_ok=True)
        self.project = pyghidra.open_project(project_dir, 'program', create=True)
        started = time.monotonic()
        imported = self.project.getProjectData().getFile('/target') is None
        self._report_stage('importing' if imported else 'loading_cache')
        if imported:
            loader = pyghidra.program_loader().project(self.project).source(str(self.import_snapshot)).name('target')
            if self.selection and self.selection['language']:
                loader = loader.language(self.selection['language'])
            results = loader.load()
            try:
                results.getPrimary().save(monitor)
            finally:
                results.close()
        self.program, self.consumer = pyghidra.consume_program(self.project, '/target')
        imported_digest = str(self.program.getExecutableSHA256()).lower()
        expected_digest = self.selection['sha256'] if self.selection else self.digest
        if imported_digest != expected_digest:
            raise RuntimeError(
                'Ghidra program hash does not match the captured input. '
                'The cache may be from an affected 0.1.0 session; move this '
                'analysis directory aside and retry. Existing evidence was preserved.'
            )
        if self.selection and self.selection['language'] and str(self.program.getLanguageID()) != self.selection['language']:
            raise RuntimeError('Wrong-architecture cache language; project was preserved')
        loaded_path = self.directory / 'loaded.json'
        loaded_identity = {'input_sha256':expected_digest,'language':str(self.program.getLanguageID()),
                           'compiler':str(self.program.getCompilerSpec().getCompilerSpecID())}
        if imported:
            loaded_path.write_text(json.dumps(loaded_identity,sort_keys=True))
        else:
            try:
                if json.loads(loaded_path.read_text()) != loaded_identity:
                    raise ValueError('Loaded identity differs')
            except (ValueError,OSError) as error:
                raise RuntimeError('Cache language/compiler/input provenance missing or corrupt; preserved') from error
        self.quick_metadata = identity.metadata(self.import_snapshot)
        self._verify_selected_bytes()
        metadata_path = self.directory / 'analysis.json'
        if metadata_path.exists():
            try:
                previous = json.loads(metadata_path.read_text())
            except ValueError as error:
                raise RuntimeError('Corrupt analysis cache provenance; preserved without reuse') from error
            if (previous.get('identity') != self.identity or
                    previous.get('language') != str(self.program.getLanguageID()) or
                    previous.get('compiler') != str(self.program.getCompilerSpec().getCompilerSpecID())):
                raise RuntimeError('Cache language/compiler/profile identity mismatch; preserved without reuse')
        analyzed = False
        if self.analysis_mode == 'quick':
            from . import quick
            quick.initialize(self, imported)
        elif imported or not GhidraProgramUtilities.isAnalyzed(self.program):
            self._report_stage('analyzing')
            log = pyghidra.analyze(self.program)
            self._report_stage('saving')
            (self.directory / 'analysis.log').write_text(str(log))
            self.program.save('EAOS initial analysis', monitor)
            analyzed = True
        metadata_path = self.directory / 'analysis.json'
        metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
        metadata.update(target=str(self.target), sha256=self.digest, identity=self.identity,
            ghidra_version='12.1.4', language=str(self.program.getLanguageID()),
            compiler=str(self.program.getCompilerSpec().getCompilerSpecID()))
        if analyzed:
            metadata['analysis_count'] = metadata.get('analysis_count', 0) + 1
            metadata['analysis_seconds'] = time.monotonic() - started
        metadata_path.write_text(json.dumps(metadata, indent=2))
        if self.analysis_mode == 'full':
            self.metadata_status = 'full_pass_finished'
        self._load_go()
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(self.program)

    def _verify_selected_bytes(self):
        if not self.quick_metadata:
            return
        import jpype
        for section in self.quick_metadata['sections']:
            if section['name'] != '__text' or not section['size']:
                continue
            size = min(64, section['size'])
            address = self.program.getAddressFactory().getDefaultAddressSpace().getAddress(section['address'])
            raw = jpype.JArray(jpype.JByte)(size)
            self.program.getMemory().getBytes(address, raw)
            with self.import_snapshot.open('rb') as source:
                source.seek(section['offset'])
                if bytes(raw) != source.read(size):
                    raise RuntimeError('Selected-slice executable bytes do not match imported memory; cache preserved')

    def invalidate_views(self):
        self.inspection_cache.clear()
        self.inspection_cache_bytes = 0
        self.zero_fill_metadata = None
        self.quick_name_coverage = None
        if self.discovery_index is not None:
            self.discovery_index.close()
            self.discovery_index = None
        if self.decompiler is not None:
            self.decompiler.flushCache()

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
        if self.discovery_index is not None:
            self.discovery_index.close()
            self.discovery_index = None
        self.inspection_cache.clear()
        self.inspection_cache_bytes = 0
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
        affected = operation in {'open_program','search','inspect','read_memory','decode_swift_string'}
        provenance = self.provenance() if affected else None
        evidence = self.evidence.save(operation, classification, data, limitations, provenance)
        result = {'classification': classification, 'data': data if preview is None else preview,
                'limitations': limitations or [],
                'evidence': {'id': evidence['id'], 'uri': evidence['uri']}}
        if affected:
            result['analysis'] = self.coverage()
        return result

    def address(self, address):
        result = self.program.getAddressFactory().getAddress(str(address))
        if result is None:
            raise ValueError('Invalid program address')
        return result

    def function(self, address):
        addr = self.address(address)
        if self.analysis_mode == 'quick':
            from . import quick
            return quick.prepare(self, addr)
        manager = self.program.getFunctionManager()
        fn = manager.getFunctionAt(addr) or manager.getFunctionContaining(addr)
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
        qualified = str(fn.getName(True))
        if qualified != item['name']:
            item['qualified_name'] = qualified
        aliases = set()
        for index, symbol in enumerate(self.program.getSymbolTable().getSymbols(fn.getEntryPoint())):
            if index == 128:
                item['aliases_truncated'] = True
                break
            for name in (str(symbol.getName()), str(symbol.getName(True))):
                if name not in (item['name'], qualified):
                    aliases.add(name)
        if aliases:
            item['aliases'] = sorted(aliases)[:128]
            if len(aliases) > 128:
                item['aliases_truncated'] = True
        if fn.isExternal():
            item['external'] = True
        if self.analysis_mode == 'quick':
            item['analysis'] = ({'state':'external_no_body'} if fn.isExternal() else
                self.function_readiness.get(str(fn.getEntryPoint()), {'state':'not_prepared'}))
        go = self.go_functions.get(f'{int(fn.getEntryPoint().getOffset()):x}') if not fn.isExternal() else None
        if go:
            item.update(name=go['name'],ghidra_name=item['name'],source='go_pclntab',end=go['end'],
                        name_address=go['name_address'],record_address=go['record_address'])
        return item

    @validated_tool('open_program')
    def open_program(self, full=False, analysis_mode=None, cancel=False):
        if cancel:
            raise ValueError('Cancellation is handled by the owning session')
        if analysis_mode is not None and analysis_mode != self.analysis_mode:
            self.close()
            self._set_profile(analysis_mode)
            self.revision, self.function_readiness, self.quick_metadata = 0, {}, None
            self.quick_name_coverage = None
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
    def search(self, kind='strings', pattern='', offset=0, limit=30, full=False,
               index_cursor=None, view=None):
        profile_arguments={'kind':kind,'offset':offset}
        if index_cursor is not None:profile_arguments['index_cursor']=index_cursor
        if view is not None:profile_arguments['view']=view
        validate_search_profile(profile_arguments,self.analysis_mode)
        self._load()
        if not 0 <= offset or not 1 <= limit <= 200:
            raise ValueError('offset must be nonnegative and limit 1..200')
        query = pattern
        pattern = pattern.casefold()
        rows = []
        limitations = ['Search is static discovery, not proof of runtime behavior or absence of other text.']
        coverage = None
        index = page_view = None
        if kind == 'functions':
            if self.analysis_mode == 'quick':
                from . import function_discovery
                index,page_view=function_discovery.open_index(self,index_cursor,view)
                self._report_stage('searching_function_names')
            seen = set()
            seen_identities = set()
            import itertools
            manager = self.program.getFunctionManager()
            for fn in itertools.chain(manager.getFunctions(True), manager.getExternalFunctions()):
                item = self.fn_info(fn)
                if item['address'] in seen_identities:
                    continue
                seen_identities.add(item['address'])
                if self.analysis_mode=='quick':
                    item.setdefault('source','external_function' if fn.isExternal() else 'ghidra_function')
                if not fn.isExternal():
                    seen.add(int(fn.getEntryPoint().getOffset()))
                names = [item['name'],item['signature'],item.get('qualified_name',''),item.get('ghidra_name',''),*item.get('aliases',[])]
                if pattern in ' '.join(names).casefold(): rows.append(item)
            for item in self.go_functions.values():
                if int(item['address'],16) not in seen and pattern in item['name'].casefold():
                    rows.append({**item,'source':'go_pclntab','analyzed_function':False})
            if self.analysis_mode == 'quick':
                coverage = {'function_candidates': self.quick_name_coverage}
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
            if self.analysis_mode == 'quick' and query:
                extra, complete = golang.literal_matches(self.literal_blocks, query)
                existing = {item['address'] for item in rows}
                rows.extend({**item,'source':'literal_bytes'} for item in extra if item['address'] not in existing)
                coverage = {'literal_search_complete_within_budget': complete,
                            'scope':'bounded initialized read-only non-executable blocks',
                            'references':'partial; empty does not establish absence'}
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
        result_view = None
        if index is not None:
            page,matches,result_view=index.matches(pattern,rows,offset,limit,page_view)
        else:
            rows.sort(key=lambda item:(item['address'].split(':')[0] if ':' in item['address'] else '', int(item['address'].split(':')[-1],16)))
            matches=len(rows)
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
                item.setdefault('references_complete',self.analysis_mode != 'quick')
        if self.go_index:
            provenance = {k:v for k,v in self.go_index.items() if k!='functions'}
        else:provenance=None
        data = {'kind':kind,'matches':matches,'items':page,
                'next_offset':offset+limit if offset+limit<matches else None}
        if result_view is not None:
            data.update(view=result_view,has_more_results=data['next_offset'] is not None,
                matches_scope='matches within available metadata plus committed candidate prefix; incomplete discovery is a lower bound, never proof of absence')
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
                for field in ('name','qualified_name','ghidra_name'):
                    if field in item and len(item[field]) > 160:
                        item[field] = item[field][:160]
                        item[field+'_truncated'] = True
                if 'aliases' in item:
                    item['aliases_truncated'] = item.get('aliases_truncated',False) or len(item['aliases']) > 4 or any(len(a)>160 for a in item['aliases'])
                    item['aliases'] = [a[:160] for a in item['aliases'][:4]]
                if 'analysis' in item:
                    item['analysis'] = {k:v for k,v in item['analysis'].items() if k in ('state','revision')}
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

    def _function_view(self, fn):
        key = str(fn.getEntryPoint())
        if key in self.inspection_cache:
            self.inspection_cache.move_to_end(key)
            return self.inspection_cache[key][0]
        row = native_inspection.build(self, fn)
        if self.go_index and row.get('source') == 'go_pclntab':
            row['go_metadata'] = {k: v for k, v in self.go_index.items() if k != 'functions'}
        size = len(json.dumps(row, ensure_ascii=False).encode())
        maximum = 32 * 1024 * 1024
        while self.inspection_cache and (len(self.inspection_cache) >= 64 or
                                         self.inspection_cache_bytes + size > maximum):
            _, (_, removed) = self.inspection_cache.popitem(last=False)
            self.inspection_cache_bytes -= removed
        if size <= maximum:
            self.inspection_cache[key] = (row, size)
            self.inspection_cache_bytes += size
        return row

    @staticmethod
    def _item_page(items, offset, limit):
        page = []
        for item in items[offset:offset + limit]:
            item = dict(item)
            if 'function' in item and item['function']:
                item['function'] = inspection.compact(item['function'])
            if 'name' in item:
                item = inspection.compact(item)
            page.append(item)
        return page

    def _focus_assembly(self, fn, shown, context, limit, include_mapped=False, assembly_only=False):
        match = shown.get('focus', {}).get('match')
        if match is None or (match['line'] is not None and not include_mapped):
            return
        address = self.address(match['address'])
        if not fn.getBody().contains(address):
            raise ValueError('Focus address is outside the selected function')
        listing = self.program.getListing()
        center = listing.getInstructionContaining(address)
        if center is None:
            shown['focus']['mapping'] = ('pseudocode only; no instruction mapping' if match['line'] is not None
                                         else 'no pseudocode or instruction mapping')
            return
        first = center
        for _ in range(min(context, (limit - 1) // 2)):
            previous = listing.getInstructionBefore(first.getAddress())
            if previous is None or not fn.getBody().contains(previous.getAddress()):
                break
            first = previous
        instructions, current = [], first
        for _ in range(min(limit, context * 2 + 1)):
            if current is None or not fn.getBody().contains(current.getAddress()):
                break
            text = str(current)
            item = {'address': str(current.getAddress()), 'text': text[:256],
                    'bytes': bytes((int(b) & 255) for b in current.getBytes()).hex()}
            if len(text) > 256:
                item['text_truncated'] = True
            instructions.append(item)
            current = listing.getInstructionAfter(current.getAddress())
        if assembly_only:
            shown['focus']['mapping'] = 'assembly'
        elif match['line'] is None:
            shown['focus']['mapping'] = 'assembly only; no matching decompiler line'
        else:
            shown['focus']['mapping'] = 'pseudocode and assembly'
        shown['instructions'] = instructions

    @validated_tool('inspect')
    def inspect(self, addresses, mode='decompile', full=False, offset=0, column=0,
                limit=40, focus=None, context=None, find=None):
        context = (2 if find else 6) if context is None else context
        self._load()
        from ghidra.util.task import TaskMonitor
        rows, preview = [], []
        for address in addresses:
            addr = self.address(address)
            if mode == 'references':
                import itertools
                native_refs = self.program.getReferenceManager().getReferencesTo(addr)
                if self.analysis_mode == 'quick':
                    native_refs = itertools.islice(native_refs,4096)
                refs = [{'from':str(r.getFromAddress()),'to':str(r.getToAddress()),
                    'type':str(r.getReferenceType()),
                    'function':self.fn_info(fn) if (fn:=self.program.getFunctionManager().getFunctionContaining(r.getFromAddress())) else None}
                    for r in native_refs]
                row = {'address':str(addr),'references':refs}
                if self.analysis_mode == 'quick':
                    row['analysis'] = {'state':'partial_references','limit':4096}
                fn = None
            else:
                fn = self.function(address)
                row = self.fn_info(fn)
                if mode in {'decompile', 'outline', 'all'}:
                    try:
                        if fn.isExternal():
                            raise ValueError('External function has no imported instruction body')
                        if self.analysis_mode == 'quick' and row.get('analysis',{}).get('state') != 'flow_prepared':
                            raise ValueError('Safe complete flow was not established in quick mode; use assembly or full analysis')
                        row = dict(self._function_view(fn))
                    except Exception as error:
                        row['decompile_error'] = str(error)
                        row['hint'] = 'Available instructions below; explicitly choose full analysis if more recovery is needed.'
            if mode in {'assembly','all'} or row.get('decompile_error'):
                row['instructions'] = [{'address':str(i.getAddress()), 'text':str(i),
                    'bytes':bytes((int(b)&255) for b in i.getBytes()).hex()}
                    for i in self.program.getListing().getInstructions(fn.getBody(),True)]
                if mode == 'assembly' and focus:
                    row.update(call_sites=[], string_references=[])
                    if focus['kind'] != 'address':
                        row.update(native_inspection.scan_references(self, fn))
            if mode in {'calls','all'}:
                row['callers'] = sorted([self.fn_info(f) for f in fn.getCallingFunctions(TaskMonitor.DUMMY)],key=lambda f:f['address'])
                row['callees'] = sorted([self.fn_info(f) for f in fn.getCalledFunctions(TaskMonitor.DUMMY)],key=lambda f:f['address'])
            if self.go_index and row.get('source') == 'go_pclntab':
                row.setdefault('go_metadata', {k: v for k, v in self.go_index.items() if k != 'functions'})
            rows.append(row)
            if row.get('decompile_error'):
                shown = {**inspection.compact(row), 'decompile_error':row['decompile_error'], 'hint':row['hint']}
            elif find:
                shown = inspection.find_view(row, find, assembly=mode == 'assembly',
                                             offset=offset, limit=limit, context=context)
            elif mode == 'assembly' and focus:
                shown = inspection.compact(row)
                shown['focus'] = inspection.focus_metadata(row, focus,
                    inspection.instruction_lines(row['instructions']))
                self._focus_assembly(fn, shown, context, limit, include_mapped=True, assembly_only=True)
            elif 'pseudocode' in row:
                if mode == 'outline' or len(addresses) > 1:
                    shown = inspection.compact(row)
                    shown['outline'] = inspection.outline(row, offset, limit)
                    shown['hint'] = 'One address: find/focus next; page last. Batches return outlines even with full=true.'
                else:
                    shown = inspection.code_view(row, full=full, offset=offset, column=column,
                                                 limit=limit, focus=focus, context=context)
                    # Combined context is explicit; code-only focus stays small.
                    self._focus_assembly(fn, shown, context, limit, include_mapped=mode == 'all')
            else:
                shown = inspection.compact(row)
            for field in ('instructions', 'references', 'callers', 'callees'):
                if field not in row:
                    continue
                if (find or (focus and field in {'instructions', 'callers', 'callees'})) and not row.get('decompile_error'):
                    continue
                count = min(limit, 8 if 'pseudocode' in row else 40)
                if mode == 'calls':
                    count = limit
                shown[field] = self._item_page(row[field], offset, count)
                shown[field+'_total'] = len(row[field])
                shown[field+'_next_offset'] = offset + count if offset + count < len(row[field]) else None
            maximum = inspection.REPLY_CHARS // len(addresses)
            inspection.fit_outline(shown, maximum)
            while len(json.dumps(shown, ensure_ascii=False, separators=(',', ':'))) > maximum:
                fields = [f for f in ('instructions','references','callers','callees') if shown.get(f)]
                if not fields:
                    break
                field = max(fields, key=lambda f: len(json.dumps(shown[f])))
                shown[field].pop()
                shown[field+'_next_offset'] = offset + len(shown[field])
            row['view'] = shown
            preview.append(shown)
        computed_names = any(row.get('source')=='go_pclntab' for row in rows)
        return self.result('inspect','computed',rows,
            ['Pseudocode, recovered names, types and call graph are computed static interpretations; indirect calls may be unresolved.',
             'Focused snippets are not control-flow slices; omitted code can affect the result. '
             'String previews are bounded; error sites are name-based hints. Missing mappings do not prove absence.']
            if mode!='assembly' or computed_names else [], preview)

    def _static_read(self, address, length):
        import jpype
        image = self.program.getMemory()
        if self.zero_fill_metadata is None:
            try:
                expected = self.selection['sha256'] if self.selection else self.digest
                ranges, error = memory.macho_zero_fill(self.import_snapshot, int(self.program.getImageBase().getOffset()), expected)
                if self.selection:
                    for item in ranges:
                        item['container_section_header_file_offset'] = item['section_header_file_offset']+self.selection['offset']
                self.zero_fill_metadata = (ranges, error)
            except ValueError as error:
                self.zero_fill_metadata = ([], str(error))
        ranges, metadata_error = self.zero_fill_metadata

        def locate(value):
            block = image.getBlock(self.address(f'{value:x}'))
            if block is None:
                return None
            return {'end': int(block.getEnd().getOffset())+1,
                    'initialized': bool(block.isInitialized()), 'name': str(block.getName())}

        def read_bytes(value, count):
            raw = jpype.JArray(jpype.JByte)(count)
            try:
                size = image.getBytes(self.address(f'{value:x}'), raw)
            except Exception as error:
                raise ValueError(f'Analyzed-image read failed at {value:x}: {error}') from None
            return bytes(raw[:size])

        return memory.read_static(address, length, locate, read_bytes, ranges, metadata_error)

    @validated_tool('read_memory')
    def read_memory(self, address, length=64, format='hex', layout=None, count=None, offset=0):
        self._load()
        start = int(self.address(address).getOffset())
        if layout == 'go_strings':
            record = memory.go_strings(start, count, offset, int(self.program.getDefaultPointerSize()),
                'big' if self.program.getLanguage().isBigEndian() else 'little', self._static_read)
            preview = {k:v for k,v in record.items() if k not in {'items','classification','limitations'}}
            preview['items'] = []
            for item in record['items']:
                shown = {k:v for k,v in item.items() if k not in {'descriptor','payload','classification'}}
                if payload := item.get('payload'):
                    shown.update(utf8=payload['utf8'], utf8_valid=payload['utf8_valid'],
                                 complete=payload['complete'], origins=sorted({s['origin'] for s in payload['segments']}))
                    if format in {'hex','both'}:
                        shown['hex'] = payload['hex']
                if len(json.dumps(preview, ensure_ascii=False))+len(json.dumps(shown, ensure_ascii=False)) > inspection.REPLY_CHARS-256:
                    break
                preview['items'].append(shown)
            next_offset = offset + len(preview['items'])
            preview['next_offset'] = next_offset if next_offset < count else None
        else:
            record = self._static_read(start, length)
            if record['complete'] and all(s['origin'] == 'analyzed_image' for s in record['segments']):
                # Ordinary reads keep their existing wire shape. Full static provenance,
                # UTF-8 validity and loader caveats remain in retrievable evidence.
                preview = {'address': address, 'length': record['length']}
                preview.update({k:record[k] for k in ('hex','utf8') if format=='both' or k==format})
                return self.result('read_memory','fact',record,preview=preview)
            preview = {k:v for k,v in record.items() if k not in {'classification','limitations'} and
                       (k not in {'hex','utf8'} or format=='both' or k==format)}
        return self.result('read_memory',record['classification'],record,record['limitations'],preview)

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
            self._load()
            observed = self._static_read(int(self.address(address).getOffset()),16)
            if not observed.get('complete') or any(s['origin'] != 'analyzed_image' for s in observed['segments']):
                raise ValueError('Swift storage requires 16 initialized analyzed-image bytes; initial zeros or unknown memory are not runtime storage.')
            raw = bytes.fromhex(observed['hex'])
            words = [int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:],'little')]
        else:
            limitations.append('Words were supplied by the caller; their presence in this binary is not established.')
        if words is None: raise ValueError('Supply words or a program address')
        return self.result('decode_swift_string','computed',decode_small_string(words),limitations)

    @validated_tool('read_evidence')
    def read_evidence(self, id, offset=0, limit=12000):
        return self.evidence.read(id,offset,limit)
