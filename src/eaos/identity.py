"""Validated Mach-O selection and versioned analysis identity; never executes inputs."""
from __future__ import annotations

import hashlib
import json
import platform
import struct

ENGINE = '12.1.4'
INDEX_VERSION = 2
ARCHITECTURES = ('auto', 'arm64', 'arm64e', 'x86_64')
LANGUAGES = {'arm64': 'AARCH64:LE:64:AppleSilicon',
             'arm64e': 'AARCH64:LE:64:AppleSilicon', 'x86_64': 'x86:LE:64:default'}
THIN = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xcf': ('>', 32),
        b'\xce\xfa\xed\xfe': ('<', 28), b'\xfe\xed\xfa\xce': ('>', 28)}
FAT = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
       b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}


def _architecture(cpu, subtype):
    if cpu == 0x100000c:
        return 'arm64e' if subtype & 0xffffff == 2 else 'arm64'
    return 'x86_64' if cpu == 0x1000007 else f'cpu-{cpu:x}-{subtype:x}'


def _hash_range(source, offset, size):
    source.seek(offset)
    digest = hashlib.sha256()
    while size:
        chunk = source.read(min(size, 1024 * 1024))
        if not chunk:
            raise ValueError('Truncated Mach-O slice')
        digest.update(chunk)
        size -= len(chunk)
    return digest.hexdigest()


def select(path, requested='auto', host=None):
    if requested not in ARCHITECTURES:
        raise ValueError('Unsupported architecture choice')
    with path.open('rb') as source:
        source.seek(0, 2)
        total = source.tell()
        source.seek(0)
        magic = source.read(4)
        candidates = []
        if magic in FAT:
            order, wide = FAT[magic]
            raw = source.read(4)
            if len(raw) != 4:
                raise ValueError('Truncated universal Mach-O header')
            count = struct.unpack(order+'I', raw)[0]
            if not 1 <= count <= 128:
                raise ValueError('Universal slice count exceeds 1..128')
            width = 32 if wide else 20
            table_end = 8 + count * width
            for _ in range(count):
                raw = source.read(width)
                if len(raw) != width:
                    raise ValueError('Truncated universal slice table')
                values = struct.unpack(order+('IIQQII' if wide else 'IIIII'), raw)
                cpu, subtype, offset, size, alignment = values[:5]
                if (wide and values[5]) or alignment > 31 or offset % (1 << alignment):
                    raise ValueError('Invalid universal slice alignment/reserved field')
                if offset < table_end or size < 28 or offset + size > total:
                    raise ValueError('Universal slice escapes its container')
                candidates.append({'cpu_type': cpu, 'cpu_subtype': subtype,
                                   'offset': offset, 'size': size})
            ordered = sorted(candidates, key=lambda r: r['offset'])
            if any(a['offset']+a['size'] > b['offset'] for a, b in zip(ordered, ordered[1:])):
                raise ValueError('Overlapping universal slices')
        elif magic in THIN:
            candidates = [{'offset': 0, 'size': total}]
        else:
            if requested != 'auto':
                raise ValueError('Explicit architecture selection requires a supported Mach-O')
            return None
        for candidate in candidates:
            source.seek(candidate['offset'])
            header = source.read(32)
            if header[:4] not in THIN:
                raise ValueError('Invalid Mach-O slice header')
            order, header_size = THIN[header[:4]]
            if len(header) < header_size:
                raise ValueError('Truncated Mach-O header')
            cpu, subtype = struct.unpack_from(order+'II', header, 4)
            if 'cpu_type' in candidate and (cpu != candidate['cpu_type'] or subtype != candidate['cpu_subtype']):
                raise ValueError('Universal table and slice CPU disagree')
            candidate.update(cpu_type=cpu, cpu_subtype=subtype, architecture=_architecture(cpu, subtype))
        if requested == 'auto':
            host = host or platform.machine()
            desired = 'arm64' if host in ('arm64', 'aarch64') and any(c['architecture']=='arm64' for c in candidates) else None
            if desired is None and host in ('arm64', 'aarch64') and any(c['architecture']=='arm64e' for c in candidates):
                desired = 'arm64e'
            matches = [c for c in candidates if c['architecture']==desired] if desired else candidates[:1]
        else:
            matches = [c for c in candidates if c['architecture']==requested]
        if len(matches) != 1:
            raise ValueError('Requested architecture unavailable or ambiguous; available: '+', '.join(c['architecture'] for c in candidates))
        chosen = dict(matches[0])
        chosen.update(container_bytes=total, universal=magic in FAT,
                      sha256=_hash_range(source, chosen['offset'], chosen['size']))
        chosen['language'] = LANGUAGES.get(chosen['architecture'])
        return chosen


def metadata(path):
    """Thin selected image: bounded command/section records and function-start candidates."""
    with path.open('rb') as source:
        header = source.read(32)
        if header[:4] not in THIN:
            return None
        order, header_size = THIN[header[:4]]
        count, size = struct.unpack_from(order+'II', header, 16)
        if count > 8192 or size > 16*1024*1024:
            raise ValueError('Mach-O load commands exceed metadata budget')
        source.seek(header_size)
        commands = source.read(size)
        if len(commands) != size:
            raise ValueError('Truncated Mach-O load commands')
        source.seek(0, 2)
        file_size = source.tell()
        cursor, sections, text_base, starts = 0, [], None, None
        for _ in range(count):
            if cursor+8 > size:
                raise ValueError('Truncated Mach-O command')
            command, length = struct.unpack_from(order+'II', commands, cursor)
            if length < 8 or cursor+length > size:
                raise ValueError('Invalid Mach-O command size')
            if command == 0x19:
                if length < 72:
                    raise ValueError('Truncated Mach-O segment')
                segment = commands[cursor+8:cursor+24].split(b'\0')[0].decode('ascii', 'replace')
                vmaddr, vmsize, offset, extent = struct.unpack_from(order+'QQQQ', commands, cursor+24)
                nsects = struct.unpack_from(order+'I', commands, cursor+64)[0]
                if nsects > 4096 or 72+nsects*80 > length or offset+extent > file_size:
                    raise ValueError('Invalid Mach-O segment/section bounds')
                if segment == '__TEXT':
                    text_base = vmaddr
                for i in range(nsects):
                    at = cursor+72+i*80
                    name = commands[at:at+16].split(b'\0')[0].decode('ascii', 'replace')
                    address, nbytes, file_offset = struct.unpack_from(order+'QQI', commands, at+32)
                    flags = struct.unpack_from(order+'I', commands, at+64)[0]
                    if nbytes and not vmaddr <= address < address+nbytes <= vmaddr+vmsize:
                        raise ValueError('Mach-O section escapes segment')
                    if (flags & 0xff) not in (1, 0xc, 0x12) and file_offset+nbytes > file_size:
                        raise ValueError('Mach-O section escapes file')
                    sections.append({'name': name, 'address': address, 'size': nbytes,
                                     'offset': file_offset, 'flags': flags})
            if command == 0x26:
                if length < 16:
                    raise ValueError('Truncated function-start command')
                starts = struct.unpack_from(order+'II', commands, cursor+8)
            cursor += length
        if cursor != size:
            raise ValueError('Incomplete Mach-O command table')
        addresses = []
        if starts:
            offset, length = starts
            if length > 16*1024*1024 or offset+length > file_size:
                raise ValueError('Function starts exceed file/metadata budget')
        if starts and text_base is not None:
            source.seek(offset)
            value = shift = 0
            address = text_base
            for byte in source.read(length):
                value |= (byte & 127) << shift
                if byte & 128:
                    shift += 7
                    if shift >= 64:
                        raise ValueError('Overflow in function-start ULEB')
                    continue
                if not value:
                    break
                address += value
                if address >= 1 << 64 or len(addresses) >= 1000000:
                    raise ValueError('Function-start index exceeds budget')
                addresses.append(address)
                value = shift = 0
            else:
                if length:
                    raise ValueError('Unterminated function-start index')
        return {'sections': sections, 'function_starts': addresses, 'image_base': text_base}


def context(digest, selection, profile):
    if profile not in ('full', 'quick'):
        raise ValueError('analysis_mode must be full or quick')
    return {'target_sha256': digest, 'selection': selection, 'analysis_profile': profile,
            'ghidra_version': ENGINE, 'index_version': INDEX_VERSION}


def key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]
