"""Opt-in real Ghidra checks; target is a compiled inspection_fixture.c, never executed."""
import argparse
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from eaos.backend import Backend
from eaos.inspection import PAGE_CHARS, REPLY_CHARS


def check(target, report):
    backend = Backend(str(target))
    receipts = []

    def tool(name, **arguments):
        result = getattr(backend, name)(**arguments)
        assert result['classification'] in {'fact', 'computed', 'guess'}
        evidence = result['evidence']
        path = backend.evidence.directory / (evidence['id'] + '.json')
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == path.with_suffix('.sha256').read_text().strip()
        assert json.loads(raw)['target_sha256'] == backend.digest
        assert backend.read_evidence(evidence['id'])['text'] == raw.decode()[:12000]
        receipts.append({'tool': name, 'arguments': arguments, 'result': result})
        return result

    try:
        opened = tool('open_program')
        large = tool('search', kind='functions', pattern='inspection_large')['data']['items'][0]['address']
        helper = tool('search', kind='functions', pattern='inspection_helper')['data']['items'][0]['address']
        result = tool('inspect', addresses=[large])
        row = result['data'][0]
        assert 'pseudocode' not in row and row['outline']['code_characters'] > 5000
        saved = json.loads((backend.evidence.directory / (result['evidence']['id'] + '.json')).read_text())['data'][0]
        assert saved['lines'] and saved['call_sites'] and saved['string_references']
        debug = backend.directory / 'evidence' / f'function-{large}.c'
        assert saved['pseudocode'] == debug.read_text(), 'Rendered C was altered'

        by_string = tool('inspect', addresses=[large], focus={'kind': 'string', 'value': 'inspection fixture large'})['data'][0]
        assert by_string['focus']['match'] is not None
        assert by_string.get('pseudocode') or by_string.get('instructions')
        by_call = tool('inspect', addresses=[large], focus={'kind': 'call', 'value': 'inspection_helper'})['data'][0]
        assert by_call['focus']['match'] is not None
        call_address = by_call['focus']['match']['address']
        by_address = tool('inspect', addresses=[large], focus={'kind': 'address', 'value': call_address}, context=2)['data'][0]
        assert by_address['focus']['match'] is not None
        assert by_address.get('pseudocode') or by_address.get('instructions')
        focused_all = tool('inspect', addresses=[large], mode='all',
                           focus={'kind': 'address', 'value': call_address}, context=2)['data'][0]
        assert any(i['address'] == call_address for i in focused_all['instructions'])
        assert focused_all['focus']['mapping'] == 'pseudocode and assembly'

        for focus in ({'kind': 'address', 'value': call_address},
                      {'kind': 'call', 'value': 'inspection_helper'},
                      {'kind': 'string', 'value': 'inspection fixture large'}):
            with patch.object(backend, '_function_view', side_effect=AssertionError('assembly decompiled')):
                assembly_focus = tool('inspect', addresses=[large], mode='assembly',
                                      focus=focus, context=2, limit=5)['data'][0]
            assert assembly_focus['focus']['mapping'] == 'assembly'
            assert any(i['address'] == assembly_focus['focus']['match']['address']
                       for i in assembly_focus['instructions'])
            assert len(assembly_focus['instructions']) <= 5
            assert 'pseudocode' not in assembly_focus
        found = tool('inspect', addresses=[large], find={'kind': 'text', 'value': 'inspection_helper'},
                     limit=2, context=1)['data'][0]
        assert found['find']['total_matching_lines'] > 2 and found['find']['next_offset'] == 2
        assert 'pseudocode' not in found
        more = tool('inspect', addresses=[large], find={'kind': 'text', 'value': 'inspection_helper'},
                    offset=found['find']['next_offset'], limit=2)['data'][0]
        assert more['find']['matches'][0]['line'] > found['find']['matches'][-1]['line']
        for mode in ('decompile', 'assembly'):
            constants = tool('inspect', addresses=[helper], mode=mode,
                             find={'kind': 'constant', 'value': '7'})['data'][0]
            assert constants['find']['total_matching_lines'] > 0
            assert len(json.dumps(constants['find']['matches'])) <= PAGE_CHARS
        assembly_search = tool('inspect', addresses=[large], mode='assembly',
                               find={'kind': 'text', 'value': 'bl '})['data'][0]
        assert assembly_search['find']['matches']
        assert all(line['addresses'] for match in assembly_search['find']['matches'] for line in match['lines'])

        cursor, recovered = {'offset': 0, 'column': 0}, ''
        while cursor is not None:
            row = tool('inspect', addresses=[large], full=True, limit=80, **cursor)['data'][0]
            assert len(row['pseudocode']) <= PAGE_CHARS
            recovered += row['pseudocode']
            cursor = row['next']
        assert recovered == saved['pseudocode']
        batch = tool('inspect', addresses=[large, helper], full=True)
        assert all('pseudocode' not in row and 'outline' in row for row in batch['data'])
        assert len(json.dumps(batch['data'], separators=(',', ':'))) <= REPLY_CHARS + 16
        maximum_batch = tool('inspect', addresses=[large] * 8, full=True)
        assert len(json.dumps(maximum_batch['data'], separators=(',', ':'))) <= REPLY_CHARS + 16
        for mode in ('decompile', 'assembly'):
            try:
                backend.inspect([large], mode=mode, focus={'kind': 'address', 'value': helper})
            except ValueError as error:
                assert 'outside the selected function' in str(error)
            else:
                raise AssertionError('Focus escaped its selected function')
        assembly = tool('inspect', addresses=[large], mode='assembly', offset=2, limit=4)['data'][0]
        assert len(assembly['instructions']) == 4 and assembly['instructions_next_offset'] == 6
        calls = tool('inspect', addresses=[large], mode='calls', limit=2)['data'][0]
        assert calls['callees_total'] > 0
        refs = tool('inspect', addresses=[helper], mode='references', limit=3)['data'][0]
        assert refs['references_total'] > 0
        assert tool('open_program')['data']['analysis_count'] == opened['data']['analysis_count']
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({'status': 'passed', 'model_sessions': 0, 'target_executed': False,
                                     'target_sha256': backend.digest, 'calls': receipts}, indent=2) + '\n')
        print('PASS: real native focus, outline, complete pagination, batch bound, old modes and evidence.')
    finally:
        backend.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    check(args.target.resolve(), args.report.resolve())
