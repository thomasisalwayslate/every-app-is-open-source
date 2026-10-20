"""Bounded static memory reads and explicit Go descriptors; no target execution."""
from __future__ import annotations

import struct
import hashlib
import os

INITIAL_STATE = 'Initial loader state only; current runtime contents are unknown.'
MAX_SEGMENTS = 64
MAX_DESCRIPTORS = 32
MAX_STRING_PREVIEW = 256
MAX_PAYLOAD = 8192


def macho_zero_fill(path, image_base, expected_sha256=None):
    """Validate thin Mach-O section metadata before deriving any initial zeros."""
    with path.open('rb') as source:
        before = os.fstat(source.fileno())
        header = source.read(32)
        formats = {b'\xcf\xfa\xed\xfe': ('<', 64), b'\xfe\xed\xfa\xcf': ('>', 64),
                   b'\xce\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xce': ('>', 32)}
        if header[:4] not in formats:
            return [], 'Zero-fill provenance unavailable: unsupported executable header (thin Mach-O required).'
        order, bits = formats[header[:4]]
        header_size = 32 if bits == 64 else 28
        if len(header) < header_size:
            raise ValueError('Truncated Mach-O header')
        commands, size = struct.unpack_from(order + 'II', header, 16)
        if commands > 8192 or size > 16 * 1024 * 1024:
            raise ValueError('Mach-O load commands exceed metadata budget')
        source.seek(header_size)
        raw = source.read(size)
        if expected_sha256 is not None:
            source.seek(0)
            if hashlib.file_digest(source, 'sha256').hexdigest() != expected_sha256:
                raise ValueError('Captured input hash changed; zero-fill provenance unavailable')
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Captured input changed while reading loader metadata')
    if len(raw) != size:
        raise ValueError('Truncated Mach-O load commands')
    cursor, sections, preferred = 0, [], None
    maximum = 1 << bits
    for _ in range(commands):
        if cursor + 8 > size:
            raise ValueError('Truncated Mach-O load command')
        cmd, length = struct.unpack_from(order + 'II', raw, cursor)
        if length < 8 or cursor + length > size:
            raise ValueError('Invalid Mach-O load command size')
        segment = 0x19 if bits == 64 else 1
        if cmd == segment:
            fixed, section_size = (72, 80) if bits == 64 else (56, 68)
            if length < fixed:
                raise ValueError('Truncated Mach-O segment')
            fmt = 'QQQQ' if bits == 64 else 'IIII'
            start, extent, file_offset, file_size = struct.unpack_from(order + fmt, raw, cursor + 24)
            count = struct.unpack_from(order + 'I', raw, cursor + (64 if bits == 64 else 48))[0]
            if count > 4096 or fixed + count * section_size > length or start + extent > maximum:
                raise ValueError('Invalid Mach-O section table')
            if file_offset == 0 and file_size:
                if preferred is not None and preferred != start:
                    raise ValueError('Ambiguous Mach-O preferred base')
                preferred = start
            for i in range(count):
                pos = cursor + fixed + i * section_size
                address, nbytes = struct.unpack_from(order + ('QQ' if bits == 64 else 'II'), raw, pos + 32)
                flags = struct.unpack_from(order + 'I', raw, pos + (64 if bits == 64 else 56))[0]
                # mach-o/loader.h: S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL.
                if (flags & 0xff) in {1, 0xc, 0x12} and nbytes:
                    if not start <= address < address + nbytes <= start + extent:
                        raise ValueError('Zero-fill section escapes its segment')
                    name = raw[pos:pos+16].split(b'\0', 1)[0].decode('ascii', errors='replace')
                    sections.append({'start': address, 'end': address + nbytes, 'section': name,
                                     'section_type': flags & 0xff, 'source': 'Mach-O section load command',
                                     'section_header_file_offset': header_size + pos})
        cursor += length
    if cursor != size or preferred is None:
        raise ValueError('Incomplete Mach-O load commands or missing preferred image base')
    slide = image_base - preferred
    sections.sort(key=lambda s: s['start'])
    for previous, section in zip(sections, sections[1:]):
        if previous['end'] > section['start']:
            raise ValueError('Overlapping zero-fill sections')
    for section in sections:
        section['start'] += slide
        section['end'] += slide
        section['image_slide'] = slide
        if not 0 <= section['start'] < section['end'] <= (1 << 64):
            raise ValueError('Invalid relocated zero-fill range')
    return sections, None


def read_static(address, length, locate, read_bytes, zero_ranges=(), metadata_error=None):
    """Callbacks expose an analyzed image, not process memory. Gaps stay explicit."""
    if not 0 <= address < address + length <= (1 << 64) or not 1 <= length <= 65536:
        raise ValueError('Invalid static memory range')
    cursor, stop, segments, payload = address, address + length, [], bytearray()
    while cursor < stop and len(segments) < MAX_SEGMENTS:
        block = locate(cursor)
        if block is None:
            if cursor == address:
                raise ValueError(f'Unmapped virtual address: {cursor:x}')
            segments.append({'address': f'{cursor:x}', 'length': 1, 'origin': 'unmapped',
                             'status': 'unavailable', 'classification': 'computed',
                             'reason': 'Read stopped at an unmapped byte; later requested bytes were not inspected.'})
            break
        end = min(stop, block['end'])
        if end <= cursor:
            raise ValueError('Invalid analyzed memory block extent')
        proof = next((r for r in zero_ranges if r['start'] <= cursor < r['end']), None)
        if block['initialized']:
            origin, label = 'analyzed_image', 'fact'
            raw = read_bytes(cursor, end-cursor)
            if len(raw) != end-cursor:
                raise ValueError('Incomplete analyzed-image read')
        elif proof:
            end = min(end, proof['end'])
            origin, label = 'loader_zero_fill', 'computed'
            raw = b'\0' * (end-cursor)
        else:
            segments.append({'address': f'{cursor:x}', 'length': end-cursor, 'origin': 'uninitialized',
                             'status': 'unavailable', 'classification': 'computed',
                             'reason': metadata_error or 'No validated loader zero-fill provenance.'})
            break
        segment = {'address': f'{cursor:x}', 'length': len(raw), 'origin': origin,
                   'status': 'available', 'classification': label, 'block': block['name']}
        if proof and origin == 'loader_zero_fill':
            segment['provenance'] = dict(proof)
        segments.append(segment)
        payload.extend(raw)
        cursor = end
    raw = bytes(payload)
    return {'address': f'{address:x}', 'requested_length': length, 'length': len(raw),
            'hex': raw.hex(), 'utf8': raw.decode('utf-8', errors='replace'),
            'utf8_valid': _valid_utf8(raw), 'segments': segments, 'complete': cursor == stop,
            'next_address': f'{cursor:x}' if cursor < stop and len(segments) == MAX_SEGMENTS and segments[-1]['status'] == 'available' else None,
            'unavailable_address': f'{cursor:x}' if cursor < stop and segments[-1]['status'] == 'unavailable' else None,
            'classification': 'fact' if cursor == stop and all(s['classification']=='fact' for s in segments) else 'computed',
            'limitations': [INITIAL_STATE, 'Initialized bytes are from the analyzed image; loader fixups may be present.']}


def _valid_utf8(raw):
    try:
        raw.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def go_strings(address, count, offset, width, order, reader):
    """Explicit pointer+length layout; never guesses extents from null bytes."""
    if width not in {4, 8} or order not in {'little', 'big'}:
        raise ValueError('Unsupported Go descriptor pointer size or endianness')
    if not 1 <= count <= 1000000 or not 0 <= offset <= count:
        raise ValueError('Invalid Go descriptor count or offset')
    if not 0 <= address < (1 << (width*8)) or address + count*2*width > (1 << (width*8)):
        raise ValueError('Go descriptor table address overflow')
    items, used = [], 0
    stop = min(count, offset + MAX_DESCRIPTORS)
    for index in range(offset, stop):
        entry_address = address + index*width*2
        item = {'index': index, 'descriptor_address': f'{entry_address:x}', 'classification': 'computed'}
        try:
            descriptor = reader(entry_address, width*2)
            item['descriptor'] = descriptor
            if not descriptor['complete'] or any(s['origin'] != 'analyzed_image' for s in descriptor['segments']):
                item.update(status='unavailable', reason='Descriptor is not fully backed by initialized analyzed-image bytes.')
            else:
                raw = bytes.fromhex(descriptor['hex'])
                pointer, length = (int.from_bytes(raw[i*width:(i+1)*width], order) for i in range(2))
                item.update(pointer=f'{pointer:x}', byte_length=length)
                if length == 0:
                    item.update(status='empty', hex='', utf8='', truncated=False)
                elif pointer == 0 or pointer + length > (1 << (width*8)):
                    item.update(status='invalid', reason='Null pointer or string range overflow.')
                elif used >= MAX_PAYLOAD:
                    break
                else:
                    nbytes = min(length, MAX_STRING_PREVIEW, MAX_PAYLOAD-used)
                    payload = reader(pointer, nbytes)
                    status = 'available' if payload['complete'] else ('partial' if payload['length'] else 'unavailable')
                    item.update(status=status, payload=payload,
                                truncated=length>payload['length'], preview_limit=nbytes)
                    used += payload['length']
        except ValueError as error:
            item.update(status='unavailable', reason=str(error))
        items.append(item)
    next_index = offset + len(items)
    return {'layout': 'go_strings', 'address': f'{address:x}', 'count': count, 'offset': offset,
            'pointer_size': width, 'byte_order': order, 'items': items,
            'next_offset': next_index if next_index < count else None,
            'preview_payload_bytes': used, 'classification': 'computed',
            'limitations': ['Explicit static Go pointer/length decoding, not observed runtime values.',
                             'At most 32 descriptors and 256 bytes per string per page; 8192 payload bytes total.', INITIAL_STATE]}
