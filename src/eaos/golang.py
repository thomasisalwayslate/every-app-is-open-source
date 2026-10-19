"""Bounded Go pclntab discovery, independent of Ghidra's RTTI bootstrap.

Layout references: Go's debug/gosym/pclntab.go and internal/abi/symtab.go.
This implements the Go 1.18/1.20 table families; it is not an RTTI parser.
"""
from __future__ import annotations

import hashlib
import json
import struct

PARSER_VERSION = 1
MAX_TABLE_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 500_000
MAX_NAME_BYTES = 4096
MAGICS = {0xFFFFFFF0: 'go1.18-family', 0xFFFFFFF1: 'go1.20-family'}


class UnsupportedGo(ValueError):
    """Malformed, unsupported or resource-limited metadata; no partial names."""


def header_offsets(raw, maximum=64):
    """Bound candidate work without allowing a false first magic to hide a later header."""
    found = set()
    for magic in MAGICS:
        for order in ('little','big'):
            needle = magic.to_bytes(4,order)
            start = 0
            while (start := raw.find(needle,start)) >= 0:
                if (start+8 <= len(raw) and raw[start+4:start+6]==b'\0\0'
                        and raw[start+6] in (1,2,4) and raw[start+7] in (4,8)):
                    found.add(start)
                    if len(found)>maximum:
                        raise UnsupportedGo('Too many candidate Go function tables')
                start += 1
    return sorted(found)


def parse_pclntab(raw, table_address, text_start, executable_ranges):
    """Parse recognized metadata. All returned addresses use the caller's memory map."""
    if len(raw) > MAX_TABLE_BYTES or len(raw) < 72:
        raise UnsupportedGo('Go function table is truncated or exceeds 64 MiB')
    endian = next((e for e in ('<', '>') if struct.unpack_from(e+'I', raw)[0] in MAGICS), None)
    if endian is None:
        raise UnsupportedGo('Unsupported Go pclntab magic')
    magic = struct.unpack_from(endian+'I', raw)[0]
    pointer_size = raw[7]
    if raw[4:6] != b'\0\0' or raw[6] not in (1, 2, 4) or pointer_size not in (4, 8):
        raise UnsupportedGo('Invalid Go pclntab header')
    word = 'Q' if pointer_size == 8 else 'I'
    nfunc, _, header_text, names, cutab, filetab, pctab, funcs = struct.unpack_from(endian+8*word, raw, 8)
    if not 0 < nfunc <= MAX_FUNCTIONS:
        raise UnsupportedGo('Go function count is invalid or exceeds 500000')
    header_size = 8 + 8 * pointer_size
    if not header_size <= names <= cutab <= filetab <= pctab <= funcs < len(raw):
        raise UnsupportedGo('Go table offsets are unordered or outside metadata')
    table_size = (2*nfunc+1)*4
    if funcs + table_size > len(raw):
        raise UnsupportedGo('Truncated Go function entry table')
    # A header may contain an unrelocated zero, notably external-link Mach-O.
    base = header_text or text_start
    if not isinstance(base, int) or base <= 0:
        raise UnsupportedGo('No unambiguous mapped Go text start')
    def executable(start, end):
        return any(low <= start < end <= high for low, high in executable_ranges)
    rows = []
    for i in range(nfunc):
        entry_off, record_off, end_off = struct.unpack_from(endian+'III', raw, funcs+i*8)
        entry, end = base+entry_off, base+end_off
        if end >= 1 << (pointer_size*8) or not executable(entry, end):
            raise UnsupportedGo('Go function range is unordered or outside executable memory')
        at = funcs+record_off
        if record_off < table_size or at+8 > len(raw):
            raise UnsupportedGo('Go function record is outside metadata')
        record_entry, name_off = struct.unpack_from(endian+'Ii', raw, at)
        if record_entry != entry_off or not 0 <= name_off < cutab-names:
            raise UnsupportedGo('Go function record disagrees with entry or name table')
        start = names+name_off
        stop = raw.find(b'\0', start, min(cutab, start+MAX_NAME_BYTES+1))
        if stop < 0 or stop == start:
            raise UnsupportedGo('Go function name is empty, unterminated or too long')
        try:
            name = raw[start:stop].decode('utf-8', errors='strict')
        except UnicodeDecodeError as error:
            raise UnsupportedGo('Invalid UTF-8 in Go function name') from error
        if any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise UnsupportedGo('Control character in Go function name')
        rows.append({'address':f'{entry:x}', 'end':f'{end:x}', 'name':name,
                     'name_address':f'{table_address+start:x}',
                     'record_address':f'{table_address+at:x}'})
    return {'parser_version':PARSER_VERSION, 'format':MAGICS[magic],
            'table_address':f'{table_address:x}', 'table_sha256':hashlib.sha256(raw).hexdigest(),
            'text_start':f'{base:x}', 'text_start_source':'header' if header_text else 'mapped_text_section',
            'pointer_size':pointer_size, 'byte_order':'little' if endian=='<' else 'big',
            'function_count':len(rows), 'functions':rows}


def build_version(raw):
    """Read bounded inline Go build-info version; historical encoding stays unknown."""
    marker = b'\xff Go buildinf:'
    at = raw.find(marker)
    if at < 0 or at+32 >= len(raw) or not raw[at+15] & 2:
        return None
    pos = at+32
    length = 0
    for shift in range(0, 35, 7):
        if pos >= len(raw):return None
        byte = raw[pos]; pos += 1
        length |= (byte & 127) << shift
        if byte < 128:
            if not 1 <= length <= 128 or pos+length > len(raw):return None
            try:return raw[pos:pos+length].decode('ascii')
            except UnicodeDecodeError:return None
    return None


def write_cache(path, record):
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    temporary = path.with_suffix('.tmp')
    temporary.write_bytes(raw)
    temporary.replace(path)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest()+'\n')


def read_cache(path, target_sha256, table_sha256):
    """A corrupt cache is ignored; caller rebuilds from captured artifact memory."""
    try:
        if path.stat().st_size > MAX_TABLE_BYTES:return None
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != path.with_suffix('.sha256').read_text().strip():return None
        record = json.loads(raw)
        if (record['target_sha256'] != target_sha256 or record['parser_version'] != PARSER_VERSION
                or record['table_sha256'] != table_sha256):return None
        rows = record['functions']
        if record['format'] not in MAGICS.values():return None
        for key in ('table_address','text_start'):
            if not isinstance(record[key],str) or int(record[key],16)<0:return None
        if not isinstance(rows, list) or not 0 < len(rows) <= MAX_FUNCTIONS or record['function_count'] != len(rows):return None
        for row in rows:
            if not isinstance(row['name'], str) or not 0 < len(row['name'].encode()) <= MAX_NAME_BYTES:return None
            if any(ord(c)<32 or ord(c)==127 for c in row['name']):return None
            for key in ('address','end','name_address','record_address'):
                if not isinstance(row[key],str) or int(row[key],16)<0:return None
            if not 0 <= int(row['address'],16) < int(row['end'],16):return None
        return record
    except (OSError, ValueError, KeyError, TypeError):
        return None


def literal_matches(blocks, pattern, maximum=10000):
    """Return matched slices, never invented Go string boundaries; no null requirement."""
    needle = pattern.encode('utf-8')
    if not needle:return [], True
    # ASCII case folding preserves byte offsets. Unicode literals use exact UTF-8.
    folded = needle.lower() if needle.isascii() else needle
    rows = []
    for address, raw in blocks:
        haystack = raw.lower() if needle.isascii() else raw
        position = 0
        while (position := haystack.find(folded, position)) >= 0:
            if len(rows) == maximum:return rows, False
            rows.append({'address':f'{address+position:x}',
                         'text':raw[position:position+len(needle)].decode('utf-8'),
                         'byte_length':len(needle), 'source':'literal_bytes', 'extent':'match'})
            position += 1
    return rows, True
