"""Opt-in native checks against memory_fixture.c; never executes the target."""
import argparse
import hashlib
import json
from pathlib import Path
from eaos.backend import Backend
from eaos.inspection import REPLY_CHARS


def check(target, report):
    backend=Backend(str(target));receipts=[]
    def tool(name,**args):
        result=getattr(backend,name)(**args)
        evidence=result['evidence'];path=backend.evidence.directory/(evidence['id']+'.json')
        raw=path.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==path.with_suffix('.sha256').read_text().strip()
        text,cursor='',0
        while cursor is not None:
            page=backend.read_evidence(evidence['id'],offset=cursor,limit=40000)
            text+=page['text'];cursor=page['next_offset']
        assert text==raw.decode()
        assert json.loads(text)['target_sha256']==backend.digest
        receipts.append({'tool':name,'arguments':args,'result':result})
        return result
    try:
        tool('open_program')
        def symbol(name):
            for variant in (name,'_'+name):
                symbols=list(backend.program.getSymbolTable().getGlobalSymbols(variant))
                if symbols:return str(symbols[0].getAddress())
            raise AssertionError('Missing fixture symbol '+name)
        zeros=tool('read_memory',address=symbol('zero_fixture'),length=32)
        assert zeros['classification']=='computed' and zeros['data']['hex']=='00'*32
        assert zeros['data']['segments'][0]['origin']=='loader_zero_fill'
        strings=tool('read_memory',address=symbol('string_fixture'),layout='go_strings',count=6,format='both')
        items=strings['data']['items']
        assert [i['status'] for i in items]==['available','available','available','empty','invalid','unavailable']
        assert items[0]['utf8']=='hello' and items[1]['utf8']=='日本語'
        assert items[2]['hex']=='610062ff' and not items[2]['utf8_valid']
        uninitialized=tool('read_memory',address=symbol('zero_descriptors'),layout='go_strings',count=2)
        assert all(i['status']=='unavailable' for i in uninitialized['data']['items'])
        try:backend.decode_swift_string(address=symbol('zero_descriptors'))
        except ValueError as error:assert 'initialized' in str(error)
        else:raise AssertionError('Synthesized zeros became Swift storage')
        focus=symbol('memory_focus')
        for mode in ('decompile','all','assembly'):
            focused=tool('inspect',addresses=[focus],mode=mode,focus={'kind':'call','value':'memory_helper'},context=2)
            row=focused['data'][0]
            assert row['focus']['match']
            if mode in {'assembly','all'}:
                assert any(i['address']==row['focus']['match']['address'] for i in row['instructions'])
            if mode=='all':
                assert row['pseudocode'] and row['focus']['mapping']=='pseudocode and assembly'
                assert 'callees' not in row
            if mode=='decompile':
                assert row['pseudocode'] and 'instructions' not in row
        calls=tool('inspect',addresses=[symbol('call_page_fixture')],mode='calls',limit=80)['data'][0]
        assert calls['callees_total']==65 and len(calls['callees'])==65 and calls['callees_next_offset'] is None
        assert len(json.dumps(calls,separators=(',',':'))) <= REPLY_CHARS
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps({'status':'passed','target_executed':False,'model_sessions':0,'target_sha256':backend.digest,'receipts':receipts},ensure_ascii=False,indent=2)+'\n')
        print('PASS: real Mach-O zero-fill provenance, Go tables and invalid entries, paired focus, 65 callees, evidence integrity.')
    finally:backend.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True,type=Path);parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args();check(args.target.resolve(),args.report.resolve())
