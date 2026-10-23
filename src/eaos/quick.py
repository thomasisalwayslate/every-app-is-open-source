"""Opt-in bounded Mach-O metadata and reachable-instruction preparation.

LC_FUNCTION_STARTS is only a candidate ceiling. A function body is built from
validated reachable instructions, never from the whole interval between starts.
"""
from __future__ import annotations

from bisect import bisect_right
import json
import os
import tempfile
import threading
import hashlib
import time

MAX_BYTES = 65536
MAX_INSTRUCTIONS = 8192
MAX_BRANCH_DEPTH = 128
MAX_FUNCTIONS = 1024
MAX_LITERAL_BYTES = 16 * 1024 * 1024
MAX_NAME_CANDIDATES = 50000
NAME_INDEX_SECONDS = 2


def _write_state(backend):
    data = {'identity': backend.identity, 'revision': backend.revision,
            'functions': backend.function_readiness, 'metadata': backend.metadata_status}
    canonical = json.dumps(data,sort_keys=True,separators=(',',':')).encode()
    transaction = backend.program.startTransaction('EAOS quick state provenance')
    try:
        backend.program.getOptions('EAOS').setString('quick_state_sha256',hashlib.sha256(canonical).hexdigest())
    finally:
        backend.program.endTransaction(transaction,True)
    backend.program.save('EAOS bounded quick analysis', backend.monitor)
    with tempfile.NamedTemporaryFile('w', dir=backend.directory, delete=False) as output:
        temporary = output.name
        json.dump(data, output, sort_keys=True)
    os.replace(temporary, backend.directory / 'quick.json')


def body_hash(backend, fn):
    if int(fn.getBody().getNumAddresses()) > MAX_BYTES:
        raise RuntimeError('Cached quick body exceeds byte budget')
    digest = hashlib.sha256()
    for index, instruction in enumerate(backend.program.getListing().getInstructions(fn.getBody(), True)):
        if index >= MAX_INSTRUCTIONS:
            raise RuntimeError('Cached quick body exceeds instruction budget')
        digest.update(str(instruction.getAddress()).encode())
        digest.update(bytes((int(b)&255) for b in instruction.getBytes()))
    return digest.hexdigest()



def initialize(backend, imported):
    if not backend.quick_metadata or not backend.selection or backend.selection['cpu_type'] not in (0x100000c, 0x1000007):
        raise ValueError('Quick analysis supports 64-bit ARM64/x86-64 Mach-O; use full mode for this input')
    from ghidra.util.task import TaskMonitorAdapter
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.plugin.core.analysis import ObjcTypeMetadataAnalyzer
    from ghidra.app.util.importer import MessageLog
    if GhidraProgramUtilities.isAnalyzed(backend.program):
        raise RuntimeError('Quick cache is incorrectly marked fully analyzed; preserved without reuse')
    options = backend.program.getOptions('EAOS')
    state = backend.directory / 'quick.json'
    if state.exists():
        try:
            data = json.loads(state.read_text())
        except ValueError as error:
            raise RuntimeError('Stale/corrupt quick cache state; preserved') from error
        if (data.get('identity') != backend.identity or
                data.get('revision') != int(options.getLong('revision', 0)) or
                hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest() !=
                    str(options.getString('quick_state_sha256','')) or
                not options.getBoolean('metadata_ready', False)):
            raise RuntimeError('Stale/corrupt quick cache state; project and evidence preserved')
        functions = data.get('functions')
        if not isinstance(functions, dict) or len(functions) > MAX_FUNCTIONS:
            raise RuntimeError('Invalid quick function-readiness cache')
        for address, record in functions.items():
            fn = backend.program.getFunctionManager().getFunctionAt(backend.address(address))
            if (not isinstance(record,dict) or record.get('state') not in ('flow_prepared','assembly_partial') or
                    fn is None or record.get('body_sha256') != body_hash(backend,fn)):
                raise RuntimeError('Stale/corrupt quick function body; project preserved')
        backend.revision, backend.function_readiness = data['revision'], functions
        backend.metadata_status = data['metadata']
    else:
        if options.getBoolean('metadata_ready', False) or options.getLong('revision', 0):
            raise RuntimeError('Quick cache provenance missing; project and evidence preserved')
        backend._report_stage('indexing_metadata')
        monitor = TaskMonitorAdapter()
        timer = threading.Timer(30, monitor.cancel)
        timer.daemon = True
        transaction = backend.program.startTransaction('EAOS quick metadata')
        accepted = False
        try:
            timer.start()
            analyzer = ObjcTypeMetadataAnalyzer()
            log = MessageLog()
            success = analyzer.added(backend.program, backend.program.getMemory(), monitor, log)
            if monitor.isCancelled():
                raise RuntimeError('Objective-C metadata exceeded 30-second budget; use full mode')
            backend.metadata_status = 'objc_metadata; other Swift names only if supplied by loader'
            if not success:
                raise RuntimeError('Objective-C metadata recovery failed; use full mode')
            options.setBoolean('metadata_ready', True)
            options.setLong('revision', 0)
            accepted = True
        finally:
            timer.cancel()
            backend.program.endTransaction(transaction, accepted)
        _write_state(backend)
    backend.literal_blocks = literal_blocks(backend)


def literal_blocks(backend):
    """Initialized read-only non-executable blocks within the literal budget, as reported in search coverage."""
    remaining = MAX_LITERAL_BYTES
    selected = []
    for block in backend.program.getMemory().getBlocks():
        size = int(block.getSize())
        if block.isInitialized() and block.isRead() and not block.isWrite() and not block.isExecute() and size <= remaining:
            selected.append((int(block.getStart().getOffset()), backend._block_bytes(block, remaining)))
            remaining -= size
    return selected


def walk(entry, ceiling, decode, owner, known_starts):
    """Pure bounded CFG validation, shared by native preparation and failure tests.

    decode returns (last_byte, targets, fallthrough, terminal, indirect_jump).
    Calls do not traverse callees. External direct jumps are reported as tail
    edges only when their target is an independently known entry.
    """
    queue, visited, issues = [(entry, 0)], {}, []
    while queue:
        address, depth = queue.pop()
        if address in visited:
            continue
        if depth > MAX_BRANCH_DEPTH or len(visited) >= MAX_INSTRUCTIONS:
            issues.append('Traversal depth/instruction budget reached')
            break
        if not entry <= address < ceiling:
            if address in known_starts and address != entry:
                issues.append('Direct tail edge; target signature/control flow not recovered')
                continue
            issues.append('Control flow escapes candidate extent; safe complete body unavailable')
            continue
        existing = owner(address)
        if existing is not None and existing != entry:
            raise ValueError('Instruction belongs to another function; refusing overlapping ownership')
        instruction = decode(address)
        if instruction is None:
            issues.append('Missing/invalid instruction; body incomplete')
            continue
        end, targets, fallthrough, terminal, indirect = instruction
        if end < address or end >= ceiling or end-address > 31:
            raise ValueError('Instruction crosses candidate function boundary')
        if any(low <= address <= high or address <= low <= end for low, high in visited.items()):
            raise ValueError('Overlapping instruction streams; body cannot be established')
        visited[address] = end
        if indirect:
            issues.append('Indirect jump unresolved; body incomplete')
        for target in targets:
            queue.append((target, depth+1))
        if fallthrough is not None:
            queue.append((fallthrough, depth))
        elif not terminal and not targets and not indirect:
            issues.append('No verified terminal or continuation')
    if not visited:
        raise ValueError('No safely decoded instructions at candidate entry')
    # A known tail edge still lacks calling-convention/return proof. Keep assembly,
    # require full analysis for pseudocode rather than guessing a complete body.
    return visited, sorted(set(issues))


def prepare(backend, address):
    from ghidra.util.task import TaskMonitorAdapter
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.symbol import SourceType
    fm = backend.program.getFunctionManager()
    fn = fm.getFunctionAt(address) or fm.getFunctionContaining(address)
    if fn is not None and fn.isExternal():
        return fn
    entry = fn.getEntryPoint() if fn is not None else address
    number = int(entry.getOffset())
    key = str(entry)
    if key in backend.function_readiness:
        if fn is None or not fn.getBody().contains(address):
            raise ValueError('Requested address is outside the validated reachable function body')
        return fn
    if len(backend.function_readiness) >= MAX_FUNCTIONS:
        raise ValueError('Quick function budget reached; explicitly select full analysis')
    starts = backend.quick_metadata['function_starts']
    if fn is None and number not in starts:
        raise ValueError('No metadata/loader function entry at this address; full analysis required')
    block = backend.program.getMemory().getBlock(entry)
    if block is None or not block.isInitialized() or not block.isExecute():
        raise ValueError('Function entry is not in initialized executable memory')
    index = bisect_right(starts, number)
    ceiling = min(int(block.getEnd().getOffset())+1, number+MAX_BYTES,
                  starts[index] if index < len(starts) else number+MAX_BYTES)
    if ceiling <= number:
        raise ValueError('No safe candidate function bound')
    space = entry.getAddressSpace()
    region = AddressSet(entry, space.getAddress(ceiling-1))
    monitor = TaskMonitorAdapter()
    timer = threading.Timer(15, monitor.cancel)
    timer.daemon = True
    transaction = backend.program.startTransaction('EAOS requested function')
    accepted = False
    backend._report_stage('preparing_function:'+key)
    try:
        timer.start()
        command = DisassembleCommand(entry, region, True)
        command.applyTo(backend.program, monitor)
        listing = backend.program.getListing()

        def decode(value):
            if monitor.isCancelled():
                raise ValueError('Function preparation exceeded 15-second budget')
            instruction = listing.getInstructionAt(space.getAddress(value))
            if instruction is None:
                return None
            flow = instruction.getFlowType()
            targets = [] if flow.isCall() else [int(a.getOffset()) for a in instruction.getFlows()]
            fall = instruction.getFallThrough()
            return (int(instruction.getMaxAddress().getOffset()), targets,
                    int(fall.getOffset()) if fall is not None else None,
                    bool(flow.isTerminal()), bool(flow.isJump() and flow.isComputed()))

        def owner(value):
            other = fm.getFunctionContaining(space.getAddress(value))
            return int(other.getEntryPoint().getOffset()) if other is not None else None

        reached, issues = walk(number, ceiling, decode, owner, set(starts))
        body = AddressSet()
        for low, high in reached.items():
            body.add(space.getAddress(low), space.getAddress(high))
        if not body.contains(address):
            raise ValueError('Requested address is not reachable from the candidate entry')
        if fn is None:
            fn = fm.createFunction(None, entry, body, SourceType.ANALYSIS)
        else:
            fn.setBody(body)
        backend.revision += 1
        backend.program.getOptions('EAOS').setLong('revision', backend.revision)
        accepted = True
    finally:
        timer.cancel()
        backend.program.endTransaction(transaction, accepted)
        # Even rollback/disassembly attempts can make the decompiler's view stale.
        backend.invalidate_views()
    backend.function_readiness[key] = {'state':'assembly_partial' if issues else 'flow_prepared',
        'revision':backend.revision, 'instructions':len(reached), 'body_bytes':int(body.getNumAddresses()),
        'body_sha256':body_hash(backend,fn),
        'candidate_ceiling':f'{ceiling:x}', 'limitations':issues,
        'scope':'reachable instructions; not whole-program or semantic completeness'}
    _write_state(backend)
    return fn
