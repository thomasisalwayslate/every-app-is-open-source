"""Extract address-linked function views from Ghidra, without changing its database."""
from __future__ import annotations

MAX_INSTRUCTIONS = 100000
MAX_STRINGS = 2048


def _read(backend, address, length):
    import jpype
    memory = backend.program.getMemory()
    block = memory.getBlock(address)
    if block is None or not block.isInitialized() or not block.isRead() or block.isExecute():
        return b''
    length = min(length, int(block.getEnd().subtract(address)) + 1)
    raw = jpype.JArray(jpype.JByte)(length)
    count = memory.getBytes(address, raw)
    return bytes(raw[:count])


def _text(raw):
    raw = raw.split(b'\0', 1)[0]
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        # A bounded read may cut the final UTF-8 character, but never invent it.
        if error.end != len(raw) or error.reason != 'unexpected end of data':
            return None
        text = raw[:error.start].decode('utf-8')
    if len(text) < 3 or not all(c.isprintable() or c in '\n\r\t' for c in text):
        return None
    return text


def string_preview(backend, address):
    raw = _read(backend, address, 256)
    if text := _text(raw):
        return {'address': str(address), 'text': text, 'source': 'literal_bytes_preview',
                'classification': 'fact'}
    if backend.go_index:
        width = int(backend.program.getDefaultPointerSize())
        if len(raw) >= 2 * width:
            order = 'big' if backend.program.getLanguage().isBigEndian() else 'little'
            pointer = int.from_bytes(raw[:width], order)
            length = int.from_bytes(raw[width:2 * width], order)
            if pointer and 0 < length <= 1048576:
                destination = backend.program.getAddressFactory().getAddress(f'{pointer:x}')
                if destination is None:
                    return None
                if text := _text(_read(backend, destination, min(length, 256))):
                    return {'address': str(destination), 'text': text,
                            'descriptor': str(address), 'source': 'go_descriptor_candidate',
                            'classification': 'guess'}
    return None


def build(backend, fn):
    from ghidra.util.task import TaskMonitor
    from ghidra.app.decompiler import (PrettyPrinter, ClangToken, ClangFuncNameToken,
                                      ClangVariableToken, ClangTypeToken,
                                      ClangFieldToken, ClangLabelToken)
    from ghidra.program.model.symbol import IllegalCharCppTransformer

    backend._report_stage('decompiling:'+str(fn.getEntryPoint()))
    result = backend.decompiler.decompileFunction(fn, 20 if backend.analysis_mode=='quick' else 60,
                                                 backend.monitor or TaskMonitor.DUMMY)
    if not result.decompileCompleted():
        raise RuntimeError(str(result.getErrorMessage()))
    markup = result.getCCodeMarkup()
    if markup is None:
        raise RuntimeError('Decompiler returned no address-linked markup')
    # These are the same printer and transformer used by getDecompiledFunction().
    # Raw Clang text can contain '+' or '%' inside symbol names: returning that
    # text would change the apparent meaning of the rendered pseudocode.
    transformer = IllegalCharCppTransformer()
    printer = PrettyPrinter(fn, markup, transformer)
    original = str(printer.print_().getC())
    named_tokens = (ClangFuncNameToken, ClangVariableToken, ClangTypeToken,
                    ClangFieldToken, ClangLabelToken)
    lines = []
    for native in printer.getLines():
        text = str(native.getIndentString())
        columns = {}
        for token in native.getAllTokens():
            addresses = []
            op = token.getPcodeOp()
            if op is not None:
                addresses.append(op.getSeqnum().getTarget())
            address = token.getMinAddress()
            if address is not None:
                addresses.append(address)
            for address in addresses:
                if fn.getBody().contains(address):
                    columns.setdefault(str(address), len(text))
            rendered = token.getText()
            if isinstance(token, named_tokens) and token.getSyntaxType() != ClangToken.CONST_COLOR:
                rendered = transformer.simplify(rendered)
            text += str(rendered)
        lines.append({'line': len(lines) + 1, 'text': text,
                      'addresses': sorted(columns),
                      'columns': columns})

    mapping = 'Clang tokens/pcode PCs; optimized instructions can be unmapped'
    if '\n'.join(line['text'] for line in lines) + '\n' != original:
        # Preserve C even for an unsupported printer layout; never invent its map.
        lines = [{'line': i + 1, 'text': text, 'addresses': [], 'columns': {}}
                 for i, text in enumerate(original.splitlines())]
        mapping = 'unavailable: rendered C and token layout differ; use assembly focus'
    references = scan_references(backend, fn)

    row = backend.fn_info(fn)
    row.update(pseudocode=original, lines=lines,
               **references)
    row['coverage']['line_mapping'] = mapping
    row['pseudocode_artifact'] = backend.evidence.artifact(original)
    return row


def scan_references(backend, fn):
    """Instruction metadata for assembly focus; never requires decompilation."""
    calls, strings, string_cache, seen = [], [], {}, set()
    complete, strings_complete = True, True
    for index, instruction in enumerate(backend.program.getListing().getInstructions(fn.getBody(), True)):
        if index == MAX_INSTRUCTIONS:
            complete = False
            break
        site = str(instruction.getAddress())
        if instruction.getFlowType().isCall():
            flows = list(instruction.getFlows())
            for target in flows or [None]:
                called = (backend.program.getFunctionManager().getFunctionAt(target)
                          if target is not None else None)
                info = backend.fn_info(called) if called is not None else (
                    {'address': str(target), 'name': str(target)} if target is not None else None)
                calls.append({'address': site, 'target': info})
        for reference in instruction.getReferencesFrom():
            if not reference.getReferenceType().isData():
                continue
            destination = reference.getToAddress()
            key = str(destination)
            if key not in string_cache:
                string_cache[key] = string_preview(backend, destination)
            preview = string_cache[key]
            if preview is None or (site, preview['address']) in seen:
                continue
            if len(strings) == MAX_STRINGS:
                strings_complete = False
                continue
            strings.append({**preview, 'reference': site})
            seen.add((site, preview['address']))

    return {'call_sites': calls, 'string_references': strings,
            'coverage': {'instruction_scan_complete': complete,
                         'string_reference_scan_complete': complete and strings_complete,
                         'strings': 'bounded read-only previews; Go descriptor candidates are guesses'}}
