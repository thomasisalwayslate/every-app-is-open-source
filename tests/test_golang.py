"""Portable malformed-metadata and literal-boundary regressions; no Go/JVM needed."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from eaos.golang import (UnsupportedGo, build_version, header_offsets, literal_matches,
                         parse_pclntab, read_cache, write_cache)


def table(*, endian='<', pointer=8, magic=0xfffffff1, text=0x1000, names=b'main.alpha\0main.beta\0'):
    header = 8+8*pointer
    end_names = header+len(names)
    funcs = end_names
    prefix = struct.pack(endian+'I',magic)+b'\0\0\x04'+bytes([pointer])
    word = 'Q' if pointer==8 else 'I'
    prefix += struct.pack(endian+8*word,2,1,text,header,end_names,end_names,end_names,funcs)
    entries = struct.pack(endian+'IIIII',0,24,32,32,64)+b'\0'*4
    records = struct.pack(endian+'IiIi',0,0,32,11)
    return bytearray(prefix+names+entries+records)


def parse(raw, mapped=0x1000):
    return parse_pclntab(bytes(raw),0x8000,mapped,[(0x1000,0x2000)])


class GoMetadata(unittest.TestCase):
    def test_inspect_rejects_a_different_overlapping_ghidra_function(self):
        from eaos.backend import Backend
        backend=object.__new__(Backend)
        backend.analysis_mode='full'
        address=Mock();address.getOffset.return_value=0x1000
        backend.address=Mock(return_value=address)
        backend.go_functions={'1000':{'name':'main.expected'}}
        backend.program=Mock()
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value.getEntryPoint.return_value=Mock()
        with self.assertRaisesRegex(ValueError,'overlapping function'):
            backend.function('1000')

    def test_supported_families_byte_orders_and_pointer_sizes(self):
        for magic in (0xfffffff0,0xfffffff1):
            for endian in ('<','>'):
                for pointer in (4,8):
                    with self.subTest(magic=magic,endian=endian,pointer=pointer):
                        index=parse(table(magic=magic,endian=endian,pointer=pointer))
                        self.assertEqual([f['name'] for f in index['functions']],['main.alpha','main.beta'])
                        self.assertEqual([f['address'] for f in index['functions']],['1000','1020'])
                        self.assertEqual(index['functions'][-1]['end'],'1040')

    def test_unrelocated_header_needs_unambiguous_mapped_text(self):
        self.assertEqual(parse(table(text=0))['text_start_source'],'mapped_text_section')
        with self.assertRaisesRegex(UnsupportedGo,'text start'):parse(table(text=0),None)

    def test_bad_magic_headers_offsets_counts_names_and_ranges_fail_closed(self):
        examples=[]
        for offset,value in [(0,0),(4,1),(6,3),(7,3)]:
            raw=table();raw[offset]=value;examples.append(raw)
        raw=table();struct.pack_into('<Q',raw,8,500001);examples.append(raw)
        raw=table();struct.pack_into('<Q',raw,32,len(raw)+1);examples.append(raw)
        raw=table();struct.pack_into('<Q',raw,24,0x3000);examples.append(raw)
        funcs=struct.unpack_from('<Q',table(),64)[0]
        raw=table();struct.pack_into('<I',raw,funcs+4,1);examples.append(raw)
        raw=table();struct.pack_into('<I',raw,funcs+24,4);examples.append(raw)
        raw=table();struct.pack_into('<i',raw,funcs+28,-1);examples.append(raw)
        raw=table();raw[72]=255;examples.append(raw)
        raw=table();raw[72]=10;examples.append(raw)
        raw=table();raw[72:93]=b'x'*21;examples.append(raw)
        for raw in [b'',table()[:60],table()[:-5],*examples]:
            with self.subTest(raw=bytes(raw)[:12]),self.assertRaises(UnsupportedGo):parse(raw)

    def test_duplicate_names_keep_distinct_entries(self):
        raw=table();funcs=struct.unpack_from('<Q',raw,64)[0]
        struct.pack_into('<i',raw,funcs+36,0)
        self.assertEqual([r['name'] for r in parse(raw)['functions']],['main.alpha','main.alpha'])

    def test_candidate_scan_skips_false_magic_and_bounds_work(self):
        raw=b'\xf1\xff\xff\xffgarbage'+table()
        self.assertEqual(header_offsets(raw),[11])
        with self.assertRaisesRegex(UnsupportedGo,'candidate'):
            header_offsets(bytes(table())*3,maximum=2)

    def test_oversized_unterminated_name_fails(self):
        with self.assertRaisesRegex(UnsupportedGo,'name'):
            parse(table(names=b'x'*4097+b'\0main.beta\0'))

    def test_inline_build_version_is_bounded_and_rejects_historical_pointer_encoding(self):
        raw=b'\xff Go buildinf:'+b'\x08\x02'+b'\0'*16+b'\x08go1.27.1'
        self.assertEqual(build_version(raw),'go1.27.1')
        self.assertIsNone(build_version(raw[:35]))
        self.assertIsNone(build_version(raw[:15]+b'\0'+raw[16:]))
        self.assertIsNone(build_version(raw[:32]+b'\xff'*7))

    def test_cache_is_bound_to_input_parser_and_metadata_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'go-index-v1.json';record=parse(table());record['target_sha256']='a'*64
            write_cache(path,record)
            self.assertEqual(read_cache(path,'a'*64,record['table_sha256']),record)
            self.assertIsNone(read_cache(path,'b'*64,record['table_sha256']))
            self.assertIsNone(read_cache(path,'a'*64,'b'*64))
            record['parser_version']=99;write_cache(path,record)
            self.assertIsNone(read_cache(path,'a'*64,record['table_sha256']))
            path.write_bytes(b'corrupt')
            self.assertIsNone(read_cache(path,'a'*64,record['table_sha256']))


class GoLiterals(unittest.TestCase):
    def test_packed_repeated_substrings_and_null_are_matched_slices(self):
        rows,complete=literal_matches([(0x1000,b'alphaBeta\x00Beta with tail')],'beta')
        self.assertTrue(complete)
        self.assertEqual([r['address'] for r in rows],['1005','100a'])
        self.assertTrue(all(r['extent']=='match' and r['text']=='Beta' for r in rows))
        self.assertEqual(literal_matches([(0x1000,b'A\x00B')],'A\x00B')[0][0]['byte_length'],3)

    def test_utf8_offsets_are_bytes_and_matches_do_not_cross_blocks(self):
        rows,_=literal_matches([(0x1000,'é世界'.encode())],'世界')
        self.assertEqual(rows[0]['address'],'1002')
        self.assertEqual(rows[0]['byte_length'],6)
        self.assertEqual(literal_matches([(0x1000,b'al'),(0x1002,b'pha')],'alpha')[0],[])

    def test_empty_pattern_and_resource_limit_are_explicit(self):
        self.assertEqual(literal_matches([(0,b'abc')],''),([],True))
        rows,complete=literal_matches([(0,b'aaa')],'a',maximum=2)
        self.assertFalse(complete)
        self.assertEqual(len(rows),2)


class GoSearchCoverage(unittest.TestCase):
    def test_go_and_quick_literal_completion_are_independent(self):
        from eaos.backend import Backend
        cases=[('quick','available',False,True),('quick','available',True,False),
               ('quick','partial',True,True),('full','available',True,None),
               ('full','available',False,None)]
        for mode,status,go_complete,quick_complete in cases:
            with self.subTest(mode=mode,status=status,go=go_complete,quick=quick_complete),tempfile.TemporaryDirectory() as folder:
                target=Path(folder)/'input';target.write_bytes(b'controlled bytes, never executed')
                backend=Backend(str(target),analysis_mode=mode)
                backend._load=Mock();backend.program=program=Mock()
                program.getListing.return_value.getDefinedData.return_value=[]
                program.getReferenceManager.return_value.getReferencesTo.return_value=[]
                backend.go_literals=[(0x100,b'go match')]
                backend.literal_blocks=[(0x200,b'quick match')]
                backend.go_status={'literal_bytes':8,'literal_search':status,'names':'available'}
                row=lambda address:{'address':address,'text':'match','source':'literal_bytes','extent':'match','byte_length':5}
                def matches(blocks,query):
                    self.assertEqual(query,'match')
                    if blocks is backend.go_literals:return [row('100')],go_complete
                    self.assertEqual(mode,'quick')
                    self.assertIs(blocks,backend.literal_blocks)
                    return [row('200')],quick_complete
                try:
                    for full in (False,True):
                        with patch.dict('sys.modules',{'java.lang':SimpleNamespace(String=str)}),patch('eaos.golang.literal_matches',side_effect=matches) as scan:
                            result=backend.search(kind='strings',pattern='match',full=full)
                        coverage=result['data']['coverage']
                        self.assertEqual(coverage['complete'],go_complete and status=='available')
                        if mode=='quick':
                            self.assertEqual(coverage['quick_literal_search']['literal_search_complete_within_budget'],quick_complete)
                            self.assertEqual(coverage['quick_literal_search']['scope'],'bounded initialized read-only non-executable blocks')
                        else:self.assertNotIn('quick_literal_search',coverage)
                        self.assertEqual(scan.call_count,2 if mode=='quick' else 1)
                        self.assertEqual(result['data']['matches'],2 if mode=='quick' else 1)
                        saved=json.loads(backend.read_evidence(result['evidence']['id'])['text'])
                        expected=saved['data']['coverage']
                        if not full:expected.pop('literal_ranges')
                        self.assertEqual(expected,coverage)
                        stopped=not go_complete or (mode=='quick' and not quick_complete)
                        self.assertEqual(any('matches is a lower bound' in text for text in result['limitations']),stopped)
                finally:
                    backend.program=None;backend.close()


if __name__=='__main__':unittest.main()
