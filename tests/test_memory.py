"""Memory provenance, malformed loaders and bounded explicit Go layouts; no JVM."""
import json
import struct
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eaos import memory
from eaos.backend import Backend
from eaos.contracts import validate_arguments


def macho(bits=64, order='<', flags=1, address=0x1100, size=32):
    magic = 0xfeedfacf if bits == 64 else 0xfeedface
    fixed, section_size = (72, 80) if bits == 64 else (56, 68)
    command = bytearray(fixed + section_size)
    struct.pack_into(order+'II', command, 0, 0x19 if bits == 64 else 1, len(command))
    command[8:14] = b'__DATA'
    struct.pack_into(order+('QQQQ' if bits == 64 else 'IIII'), command, 24, 0x1000, 0x1000, 0, 256)
    struct.pack_into(order+'I', command, 64 if bits == 64 else 48, 1)
    command[fixed:fixed+5] = b'__bss'
    struct.pack_into(order+('QQ' if bits == 64 else 'II'), command, fixed+32, address, size)
    struct.pack_into(order+'I', command, fixed+(64 if bits == 64 else 56), flags)
    header = struct.pack(order+'IIIIIII', magic, 0, 0, 2, 1, len(command), 0)
    if bits == 64:
        header += b'\0'*4
    return header+command


def image_reader(blocks, zero=()):
    def locate(address):
        for start,end,raw in blocks:
            if start <= address < end:
                return {'end':end,'initialized':raw is not None,'name':'fixture'}
    def read(address,length):
        for start,end,raw in blocks:
            if start <= address < end and raw is not None:
                return raw[address-start:address-start+length]
        raise AssertionError('Native reads must never be attempted for unavailable memory')
    return lambda address,length: memory.read_static(address,length,locate,read,zero)


class StaticMemory(unittest.TestCase):
    def test_ordinary_tool_reads_keep_wire_shape_and_full_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'fixture';target.write_bytes(b'fixture')
            backend=Backend(str(target))
            try:
                read=image_reader([(0x1000,0x1002,b'\xffa')])
                with patch.object(backend,'_load'),patch.object(backend,'_static_read',side_effect=read),patch.object(backend,'address') as address:
                    address.return_value.getOffset.return_value=0x1000
                    for mode in ('hex','utf8','both'):
                        result=backend.read_memory('0x1000',length=2,format=mode)
                        expected={'address':'0x1000','length':2}
                        if mode in {'hex','both'}:expected['hex']='ff61'
                        if mode in {'utf8','both'}:expected['utf8']='\ufffda'
                        self.assertEqual(result['data'],expected)
                        self.assertEqual(result['classification'],'fact')
                        self.assertEqual(result['limitations'],[])
                        saved=json.loads(backend.read_evidence(result['evidence']['id'],limit=40000)['text'])
                        self.assertFalse(saved['data']['utf8_valid'])
                        self.assertEqual(saved['data']['segments'][0]['origin'],'analyzed_image')
                        self.assertIn('runtime contents are unknown',saved['data']['limitations'][0])
            finally:backend.close()

    def test_swift_address_decode_checks_static_record_not_compact_preview(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'fixture';target.write_bytes(b'fixture')
            backend=Backend(str(target))
            try:
                raw=b'hello'+b'\0'*10+b'\xe5'
                read=image_reader([(0x1000,0x1010,raw)])
                with patch.object(backend,'_load'),patch.object(backend,'_static_read',side_effect=read),patch.object(backend,'address') as address:
                    address.return_value.getOffset.return_value=0x1000
                    self.assertEqual(backend.decode_swift_string(address='1000')['data']['text'],'hello')
                partial=image_reader([(0x1000,0x1008,raw[:8])])(0x1000,16)
                with patch.object(backend,'_load'),patch.object(backend,'_static_read',return_value=partial),patch.object(backend,'address') as address:
                    address.return_value.getOffset.return_value=0x1000
                    with self.assertRaisesRegex(ValueError,'initialized'):backend.decode_swift_string(address='1000')
            finally:backend.close()

    def test_thin_headers_all_endianness_widths_and_relocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'fixture'
            for bits in (32,64):
                for order in ('<','>'):
                    for flags in (1,0xc,0x12):
                        path.write_bytes(macho(bits,order,flags))
                        rows,error=memory.macho_zero_fill(path,0x2000)
                        self.assertIsNone(error)
                        self.assertEqual((rows[0]['start'],rows[0]['end']),(0x2100,0x2120))
                        self.assertEqual(rows[0]['section_type'],flags)
            path.write_bytes(macho(flags=0))
            self.assertEqual(memory.macho_zero_fill(path,0x1000)[0],[])

    def test_malformed_metadata_cannot_authorize_zeros(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'fixture'
            for data in (macho()[:-1],macho(address=0x2000),macho(size=1<<63),macho()[:20]):
                path.write_bytes(data)
                with self.assertRaises(ValueError):memory.macho_zero_fill(path,0x1000)
            data=bytearray(macho());struct.pack_into('<I',data,36,0)
            path.write_bytes(data)
            with self.assertRaises(ValueError):memory.macho_zero_fill(path,0x1000)
            path.write_bytes(b'not a Mach-O')
            self.assertIn('unavailable',memory.macho_zero_fill(path,0x1000)[1])

    def test_loader_provenance_is_bound_to_the_captured_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'fixture';path.write_bytes(macho())
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(memory.macho_zero_fill(path,0x1000,digest)[0])
            path.write_bytes(macho(address=0x1200))
            with self.assertRaisesRegex(ValueError,'hash changed'):
                memory.macho_zero_fill(path,0x1000,digest)

    def test_multiple_sections_relocate_and_overlap_is_rejected(self):
        data=bytearray(macho());section=bytes(data[104:184])
        data.extend(section)
        struct.pack_into('<I',data,20,232)
        struct.pack_into('<I',data,36,232)
        struct.pack_into('<I',data,96,2)
        struct.pack_into('<Q',data,216,0x1200)
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'fixture';path.write_bytes(data)
            rows,_=memory.macho_zero_fill(path,0x3000)
            self.assertEqual([r['start'] for r in rows],[0x3100,0x3200])
            struct.pack_into('<Q',data,216,0x1101);path.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'Overlapping'):
                memory.macho_zero_fill(path,0x3000)

    def test_mixed_image_and_zero_fill_is_computed_and_provenanced(self):
        read=image_reader([(0x1000,0x1004,b'ABCD'),(0x1004,0x1008,None)],
                          [{'start':0x1004,'end':0x1008,'section':'__bss'}])
        result=read(0x1000,8)
        self.assertEqual(result['hex'],'4142434400000000')
        self.assertTrue(result['complete'])
        self.assertEqual(result['classification'],'computed')
        self.assertEqual([s['origin'] for s in result['segments']],['analyzed_image','loader_zero_fill'])
        self.assertIn('runtime contents are unknown',result['limitations'][0])

    def test_unknown_and_unmapped_are_not_zero_filled_or_silently_skipped(self):
        read=image_reader([(0x1000,0x1004,b'ABCD'),(0x1004,0x1008,None)])
        result=read(0x1000,8)
        self.assertEqual(result['hex'],'41424344')
        self.assertFalse(result['complete'])
        self.assertEqual(result['unavailable_address'],'1004')
        self.assertIsNone(result['next_address'])
        self.assertEqual(read(0x1004,2)['length'],0)
        with self.assertRaisesRegex(ValueError,'Unmapped'):read(0x999,1)
        self.assertFalse(read(0x1000,10)['complete'])

    def test_range_and_fragment_limits(self):
        blocks=[(0x1000+i,0x1001+i,b'a') for i in range(100)]
        read=image_reader(blocks)
        result=read(0x1000,100)
        self.assertEqual(result['length'],memory.MAX_SEGMENTS)
        self.assertEqual(result['next_address'],f'{0x1000+memory.MAX_SEGMENTS:x}')
        self.assertEqual(result['classification'],'computed')
        for a,n in ((-1,1),(0,0),(2**64-1,2),(0,65537)):
            with self.assertRaises(ValueError):read(a,n)

    def test_gap_does_not_claim_later_mapped_bytes_are_unmapped(self):
        read=image_reader([(0x1000,0x1002,b'ab'),(0x1003,0x1005,b'cd')])
        result=read(0x1000,5)
        self.assertEqual(result['hex'],'6162')
        self.assertEqual(result['segments'][-1]['address'],'1002')
        self.assertEqual(result['segments'][-1]['length'],1)
        self.assertFalse(result['complete'])

    def test_invalid_utf8_preserves_raw_bytes(self):
        result=image_reader([(0x1000,0x1002,b'\xffa')])(0x1000,2)
        self.assertEqual(result['hex'],'ff61');self.assertFalse(result['utf8_valid'])


class GoDescriptors(unittest.TestCase):
    def test_pointer_width_order_and_non_null_terminated_text(self):
        for width in (4,8):
            for order in ('little','big'):
                data=b'a\0b'
                raw=(0x2000).to_bytes(width,order)+len(data).to_bytes(width,order)
                read=image_reader([(0x1000,0x1000+len(raw),raw),(0x2000,0x2003,data)])
                result=memory.go_strings(0x1000,1,0,width,order,read)
                self.assertEqual(result['items'][0]['payload']['utf8'],'a\0b')
                self.assertEqual(result['items'][0]['classification'],'computed')

    def test_bad_entry_does_not_hide_later_entries(self):
        values=[(0,3),(0,0),(0x3000,2),(2**64-1,100),(0x2000,3)]
        raw=b''.join(struct.pack('<QQ',*v) for v in values)
        read=image_reader([(0x1000,0x1000+len(raw),raw),(0x2000,0x2003,b'yes')])
        result=memory.go_strings(0x1000,5,0,8,'little',read)
        self.assertEqual([i['status'] for i in result['items']],['invalid','empty','unavailable','invalid','available'])
        self.assertEqual(result['items'][-1]['payload']['utf8'],'yes')

    def test_descriptor_initial_zeros_are_not_a_runtime_empty_string(self):
        read=image_reader([(0x1000,0x1010,None)],[{'start':0x1000,'end':0x1010}])
        item=memory.go_strings(0x1000,1,0,8,'little',read)['items'][0]
        self.assertEqual(item['status'],'unavailable')
        self.assertNotIn('pointer',item)

    def test_pagination_payload_cap_long_strings_partial_and_utf8(self):
        raw=struct.pack('<QQ',0x2000,100000)*40
        read=image_reader([(0x1000,0x1000+len(raw),raw),(0x2000,0x2400,b'\xff'*1024)])
        result=memory.go_strings(0x1000,40,0,8,'little',read)
        self.assertEqual(len(result['items']),32);self.assertEqual(result['next_offset'],32)
        self.assertEqual(result['preview_payload_bytes'],8192)
        self.assertTrue(all(i['truncated'] and not i['payload']['utf8_valid'] for i in result['items']))
        self.assertIsNone(memory.go_strings(0x1000,40,32,8,'little',read)['next_offset'])
        raw=struct.pack('<QQ',0x2000,10)
        read=image_reader([(0x1000,0x1010,raw),(0x2000,0x2002,b'ok')])
        item=memory.go_strings(0x1000,1,0,8,'little',read)['items'][0]
        self.assertEqual(item['status'],'partial');self.assertEqual(item['payload']['hex'],'6f6b')

    def test_contract_rejections_before_native_work(self):
        invalid=[{'layout':'go_strings'}, {'layout':'go_strings','count':1,'length':16},
                 {'layout':'go_strings','count':1,'offset':2}, {'count':1}, {'offset':1},
                 {'layout':'go_strings','count':True}, {'layout':'go_strings','count':33,'offset':-1}]
        for args in invalid:
            with self.assertRaises(ValueError):validate_arguments('read_memory',{'address':'1000',**args})
        for args in ((0x1000,1,0,3,'little'),(2**32-1,2,0,4,'little')):
            with self.assertRaises(ValueError):memory.go_strings(*args,lambda a,n:None)

    def test_tool_preview_bound_evidence_and_swift_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'fixture';target.write_bytes(b'fixture')
            backend=Backend(str(target))
            try:
                raw=struct.pack('<QQ',0x2000,256)*32
                read=image_reader([(0x1000,0x1200,raw),(0x2000,0x2100,b'\x01'*256)])
                with patch.object(backend,'_load'),patch.object(backend,'_static_read',side_effect=read),patch.object(backend,'address') as address:
                    address.return_value.getOffset.return_value=0x1000
                    backend.program=unittest.mock.Mock()
                    backend.program.getDefaultPointerSize.return_value=8
                    backend.program.getLanguage.return_value.isBigEndian.return_value=False
                    result=backend.read_memory('1000',layout='go_strings',count=32)
                    self.assertLessEqual(len(json.dumps(result['data'],ensure_ascii=False)),16000)
                    text, cursor = '', 0
                    while cursor is not None:
                        page=backend.read_evidence(result['evidence']['id'],offset=cursor,limit=40000)
                        text+=page['text'];cursor=page['next_offset']
                    saved=json.loads(text)
                    self.assertEqual(saved['classification'],'computed')
                    self.assertEqual(len(saved['data']['items']),32)
                    self.assertEqual(result['data']['next_offset'],len(result['data']['items']))
                unavailable=memory.read_static(0x1000,16,lambda a:{'end':0x1010,'name':'bss','initialized':False},lambda a,n:b'', [{'start':0x1000,'end':0x1010}])
                with patch.object(backend,'_load'),patch.object(backend,'address') as address,patch.object(backend,'_static_read',return_value=unavailable):
                    address.return_value.getOffset.return_value=0x1000
                    with self.assertRaisesRegex(ValueError,'initialized'):backend.decode_swift_string(address='1000')
            finally:
                backend.program=None;backend.close()


if __name__=='__main__':unittest.main()
