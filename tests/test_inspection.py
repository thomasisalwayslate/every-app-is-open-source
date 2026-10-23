"""View/pagination failures without a JVM; native mapping is checked separately."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from eaos.backend import Backend
from eaos.contracts import TOOLS, validate_arguments
from eaos.inspection import (PAGE_CHARS, code_view, find_view, fit_outline,
                             focus_metadata, instruction_lines, outline, page)
from eaos.native_inspection import _text


def function(count=200, text=None):
    lines = []
    for i in range(count):
        value = text if text is not None else f'  value_{i} = helper(value_{i});'
        address = f'{0x1000 + i * 4:x}'
        lines.append({'line': i + 1, 'text': value, 'addresses': [address],
                      'columns': {address: 2}})
    return {'address': '1000', 'name': 'main.example', 'signature': 'int example()',
            'size': count * 4, 'lines': lines,
            'pseudocode': ''.join(l['text'] + '\n' for l in lines),
            'coverage': {'instruction_scan_complete': True},
            'call_sites': [{'address': '1028', 'target': {'address': '3000', 'name': 'main.helper'}},
                           {'address': '1050', 'target': {'address': '3000', 'name': 'main.helper'}}],
            'string_references': [{'address': '8000', 'reference': '1028',
                                   'text': 'an error message', 'source': 'literal_bytes_preview'},
                                  {'address': '8000', 'reference': '1050',
                                   'text': 'an error message', 'source': 'literal_bytes_preview'}]}


class InspectionViews(unittest.TestCase):
    def test_bounded_utf8_preview_does_not_invent_bytes_or_drop_valid_prefix(self):
        raw = 'readable 日本語'.encode()
        for cut in (1, 2):
            self.assertEqual(_text(raw[:-cut]), 'readable 日本')
        self.assertIsNone(_text(b'prefix\xffmiddle'))

    def test_function_cache_reuses_native_work_and_evicts_least_recent(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'target'
            target.write_bytes(b'fixture')
            backend = Backend(str(target))
            functions = []
            for index in range(65):
                fn = Mock()
                fn.getEntryPoint.return_value = f'{0x1000+index*4:x}'
                functions.append(fn)
            try:
                with patch('eaos.backend.native_inspection.build', return_value=function(1)) as build:
                    for fn in functions[:64]:
                        backend._function_view(fn)
                    backend._function_view(functions[0])
                    self.assertEqual(build.call_count, 64)
                    backend._function_view(functions[64])
                    self.assertEqual(len(backend.inspection_cache), 64)
                    self.assertIn('1000', backend.inspection_cache)
                    self.assertNotIn('1004', backend.inspection_cache)
                    self.assertLessEqual(backend.inspection_cache_bytes, 32*1024*1024)
            finally:
                backend.close()
            self.assertFalse(backend.inspection_cache)

    def test_paired_focus_reports_missing_instruction_mapping_and_bounds_text(self):
        backend=Backend.__new__(Backend)
        backend.program=Mock();backend.address=Mock(return_value='1010')
        fn=Mock();fn.getBody.return_value.contains.return_value=True
        listing=backend.program.getListing.return_value
        listing.getInstructionContaining.return_value=None
        for line,expected in ((11,'pseudocode only; no instruction mapping'),
                              (None,'no pseudocode or instruction mapping')):
            shown={'focus':{'match':{'address':'1010','line':line}}}
            backend._focus_assembly(fn,shown,2,5,include_mapped=True)
            self.assertEqual(shown['focus']['mapping'],expected)
        from unittest.mock import MagicMock
        instruction=MagicMock();instruction.__str__.return_value='x'*1000
        instruction.getAddress.return_value='1010';instruction.getBytes.return_value=[1,2,3,4]
        listing.getInstructionContaining.return_value=instruction
        listing.getInstructionAfter.return_value=None
        shown={'focus':{'match':{'address':'1010','line':11}}}
        backend._focus_assembly(fn,shown,2,1,include_mapped=True)
        self.assertEqual(len(shown['instructions'][0]['text']),256)
        self.assertTrue(shown['instructions'][0]['text_truncated'])
        self.assertEqual(shown['instructions'][0]['bytes'],'01020304')
        fn.getBody.return_value.contains.return_value=False
        with self.assertRaisesRegex(ValueError,'outside'):
            backend._focus_assembly(fn,shown,2,1,include_mapped=True)

    def test_small_default_and_large_outline(self):
        small = function(8)
        self.assertEqual(code_view(small)['pseudocode'], small['pseudocode'])
        large = function()
        large['string_references'][0]['classification'] = 'guess'
        shown = code_view(large)
        self.assertNotIn('pseudocode', shown)
        self.assertEqual(shown['outline']['code_lines'], 200)
        self.assertEqual(shown['outline']['callees']['items'][0]['sites'], ['1028', '1050'])
        self.assertIn('not Go string boundaries', shown['outline']['strings']['items'][0]['extent'])
        self.assertEqual(shown['outline']['strings']['items'][0]['classification'], 'guess')

    def test_all_code_is_reachable_without_gaps_or_duplicates(self):
        for row in [function(), function(3, 'x' * 20000), function(2, 'x' * (PAGE_CHARS - 1)),
                    function(1, 'x' * PAGE_CHARS), function(3, '')]:
            with self.subTest(length=len(row['pseudocode'])):
                cursor, recovered = {'offset': 0, 'column': 0}, ''
                seen = set()
                while cursor is not None:
                    key = tuple(cursor.values())
                    self.assertNotIn(key, seen)
                    seen.add(key)
                    result = page(row['lines'], **cursor, limit=7)
                    self.assertLessEqual(len(result['pseudocode']), PAGE_CHARS)
                    recovered += result['pseudocode']
                    cursor = result['next']
                self.assertEqual(recovered, row['pseudocode'])

    def test_focus_by_address_string_and_call_and_occurrence(self):
        row = function()
        for focus in [{'kind': 'address', 'value': '0x01028'},
                      {'kind': 'string', 'value': 'AN error'},
                      {'kind': 'string', 'value': '0x8000'},
                      {'kind': 'call', 'value': 'helper'},
                      {'kind': 'call', 'value': '0x3000'}]:
            with self.subTest(focus=focus):
                result = code_view(row, focus=focus, context=2)
                self.assertIn('value_10', result['pseudocode'])
                self.assertEqual(result['focus']['match']['line'], 11)
                self.assertEqual(result['line_start'], 9)
        result = code_view(row, focus={'kind': 'call', 'value': 'helper', 'occurrence': 1})
        self.assertEqual(result['focus']['match']['line'], 21)
        self.assertIsNone(result['focus']['next_occurrence'])
        # Adjacent packed Go text must not acquire the previous string's reference.
        self.assertEqual(code_view(row, focus={'kind': 'string', 'value': 'message'})['focus']['matches'], 0)

    def test_focus_never_replaces_an_unmapped_site_with_a_guess(self):
        row = function()
        row['lines'][10]['addresses'] = []
        result = code_view(row, focus={'kind': 'address', 'value': '1028'})
        self.assertEqual(result['pseudocode'], '')
        self.assertEqual(result['focus']['unmapped_sites'], ['1028'])
        self.assertIn('No nearest-line guess', result['limitations'][0])

    def test_focus_includes_match_with_small_limit_or_long_context_line(self):
        row = function()
        result = code_view(row, focus={'kind': 'address', 'value': '1028'}, limit=1, context=20)
        self.assertIn('value_10', result['pseudocode'])
        self.assertEqual(result['line_start'], result['line_end'])
        row['lines'][9]['text'] = 'x' * 20000
        self.assertIn('value_10', code_view(row, focus={'kind': 'address', 'value': '1028'})['pseudocode'])
        row['lines'][10]['text'] = 'x' * 30000 + 'TARGET' + 'y' * 20000
        row['lines'][10]['columns']['1028'] = 30000
        result = code_view(row, focus={'kind': 'address', 'value': '1028'})
        self.assertIn('TARGET', result['pseudocode'])
        self.assertGreater(result['start_column'], 0)

    def test_outline_has_computed_hints_and_paginates_trimmed_categories(self):
        row = function()
        row['lines'][40]['text'] = 'return result;'
        row['call_sites'] += [{'address': f'{0x1000+i*4:x}',
                              'target': {'address': f'{0x4000+i*4:x}', 'name': 'errorCandidate' + 'x'*200}}
                             for i in range(50)]
        shown = {'address': '1000', 'outline': outline(row, offset=3)}
        self.assertTrue(any(s['kind'] == 'error_candidate' for s in outline(row)['sites']['items']))
        original = copy.deepcopy(shown)
        fit_outline(shown, 1400)
        self.assertLessEqual(len(json.dumps(shown, separators=(',', ':'))), 1400)
        for key in ['callees', 'strings', 'sites']:
            category = shown['outline'][key]
            self.assertEqual(category['total'], original['outline'][key]['total'])
            if category['next_offset'] is not None:
                self.assertEqual(category['next_offset'], 3 + len(category['items']))

    def test_out_of_range_code_cursor_is_not_silently_clamped(self):
        for args in [{'offset': 201}, {'offset': 200, 'column': 1}, {'column': 10000}]:
            with self.assertRaises(ValueError):
                page(function()['lines'], **args)

    def test_find_literal_text_returns_context_and_matching_line_cursors(self):
        row = function(30)
        for index in (1, 8, 23):
            row['lines'][index]['text'] = '  if (READY) return value;'
        query = {'kind': 'text', 'value': '(ready)'}
        first = find_view(row, query, limit=2)['find']
        self.assertEqual(first['total_matching_lines'], 3)
        self.assertEqual([x['line'] for x in first['matches']], [2, 9])
        self.assertEqual(first['next_offset'], 2)
        self.assertEqual(first['matches'][0]['lines'][1]['addresses'], ['1004'])
        second = find_view(row, query, offset=first['next_offset'])['find']
        self.assertEqual([x['line'] for x in second['matches']], [24])
        self.assertIsNone(second['next_offset'])
        self.assertEqual(find_view(row, {'kind': 'text', 'value': '.*'})['find']['matches'], [])
        with self.assertRaises(ValueError):
            find_view(row, query, offset=4)

    def test_find_constants_normalizes_integers_without_matching_names_or_quotes(self):
        row = function(13)
        texts = ['return 422;', 'return 0x1a6UL;', 'return 1422;',
                 'param_422 = FUN_422();', 'return 422.0;', 'puts("422");',
                 '/* 422', 'still 422 */ return -17;', 'return -0x11;', '// 422',
                 'return 1e+422;', 'return 0x1p+422;', 'return .422;']
        for line, text in zip(row['lines'], texts):
            line['text'] = text
        result = find_view(row, {'kind': 'constant', 'value': '0x1A6'})['find']
        self.assertEqual([x['line'] for x in result['matches']], [1, 2])
        negatives = find_view(row, {'kind': 'constant', 'value': '-17'})['find']
        self.assertEqual([x['line'] for x in negatives['matches']], [8, 9])
        self.assertEqual(find_view(row, {'kind': 'text', 'value': '422'})['find']['total_matching_lines'], 11)

    def test_find_long_lines_budget_missing_mapping_and_full_continuation(self):
        row = function(25, 'x' * 20000 + ' needle ' + 'y' * 20000)
        row['lines'][0]['addresses'] = []
        offset, seen = 0, []
        while offset is not None:
            result = find_view(row, {'kind': 'text', 'value': 'needle'}, offset=offset, context=20)
            matches = result['find']['matches']
            self.assertLessEqual(len(json.dumps(matches, ensure_ascii=False)), PAGE_CHARS)
            self.assertTrue(matches)
            for match in matches:
                center = next(x for x in match['lines'] if x['line'] == match['line'])
                self.assertIn('needle', center['text'])
                self.assertTrue(center['text_truncated'])
                if match['line'] == 1:
                    self.assertEqual(center['addresses'], [])
            seen.extend(x['line'] for x in matches)
            offset = result['find']['next_offset']
        self.assertEqual(seen, list(range(1, 26)))

    def test_assembly_find_and_focus_use_instruction_addresses(self):
        row = function(1)
        row['instructions'] = [{'address': '1000', 'text': 'MOV W0,#0x1a6'},
                               {'address': '1004', 'text': 'RET'}]
        result = find_view(row, {'kind': 'constant', 'value': '422'}, assembly=True)['find']
        self.assertEqual(result['total_matching_lines'], 1)
        self.assertEqual(result['matches'][0]['lines'][0]['addresses'], ['1000'])
        match = focus_metadata(row, {'kind': 'address', 'value': '1004'},
                               instruction_lines(row['instructions']))['match']
        self.assertEqual(match['address'], '1004')
        self.assertEqual(match['line'], 2)

    def test_new_contract_validates_before_native_load(self):
        self.assertEqual(len(TOOLS), 8)
        bad = [dict(focus={'kind': 'address', 'value': ''}), dict(limit=81),
               dict(context=21), dict(focus={'kind': 'address', 'value': '1000'}, offset=1),
               dict(focus={'kind': 'call', 'value': 'x'}, mode='calls'),
               dict(context=3), dict(column=1, mode='outline'),
               dict(focus={'kind': 'string', 'value': 'x', 'path': '/private/key'}),
               dict(find={'kind': 'text', 'value': ''}),
               dict(find={'kind': 'constant', 'value': '1+1'}),
               dict(find={'kind': 'text', 'value': 'x'}, column=1),
               dict(find={'kind': 'text', 'value': 'x'}, mode='all'),
               dict(find={'kind': 'text', 'value': 'x'}, focus={'kind': 'address', 'value': '1000'}),
               dict(find={'kind': 'text', 'value': 'x', 'path': '/private/key'})]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'target'
            target.write_bytes(b'fixture')
            backend = Backend(str(target))
            try:
                with patch.object(backend, '_load') as load:
                    for kwargs in bad:
                        with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                            backend.inspect(['1000'], **kwargs)
                    with self.assertRaises(ValueError):
                        backend.inspect(['1000', '2000'], focus={'kind': 'address', 'value': '1000'})
                    load.assert_not_called()
            finally:
                backend.close()
        validate_arguments('inspect', {'addresses': ['1000'], 'full': True, 'offset': 1,
                                       'column': 200, 'limit': 10})
        validate_arguments('inspect', {'addresses': ['1000'], 'mode': 'assembly',
                                       'focus': {'kind': 'address', 'value': '1000'}})
        validate_arguments('inspect', {'addresses': ['1000'], 'mode': 'assembly',
                                       'find': {'kind': 'constant', 'value': '-0x11'}, 'offset': 1})
        with self.assertRaises(ValueError):
            validate_arguments('inspect', {'addresses': ['1000', '2000'],
                                           'find': {'kind': 'text', 'value': 'x'}})


if __name__ == '__main__':
    unittest.main()
