"""Opt-in native MCP walkthrough. Discovers every inspection address through EAOS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time
from urllib.parse import unquote, urlparse


def check(command, target, report, ollama=False):
    report.parent.mkdir(parents=True,exist_ok=True)
    sha=hashlib.sha256(target.read_bytes()).hexdigest()
    strings=(['OLLAMA_HOST','OLLAMA_NUM_PARALLEL','OLLAMA_MAX_LOADED_MODELS','invalid model name','failed to load model']
             if ollama else ['EAOS_GO_PACKED_ALPHA','EAOS_GO_PACKED_BETA','EAOS_GO_SHARED_PHRASE',
                             'EAOS_GO_ZERO\0END','EAOS_GO_世界','EAOS_GO_STATIC_HEADER'])
    functions=(['envconfig','parseAndValidateModelRef','allowedHost'] if ollama else
               ['main.fixtureAlpha','main.fixtureStrings','main.main'])
    calls=[];sequence=0;started=time.monotonic();cache=target.parent/'eaos-analysis'/sha/'go-index-v1.json'
    existed=cache.exists();old_mtime=cache.stat().st_mtime_ns if existed else None
    with report.with_suffix('.stderr.log').open('w') as log:
        process=subprocess.Popen([command,'mcp',str(target)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                 stderr=log,text=True,bufsize=1,env=os.environ.copy())
        def request(method,params=None):
            nonlocal sequence
            sequence+=1;r={'jsonrpc':'2.0','id':sequence,'method':method,'params':params or {}}
            before=time.monotonic();process.stdin.write(json.dumps(r)+'\n');process.stdin.flush()
            assert select.select([process.stdout],[],[],180)[0],'MCP request timed out'
            reply=json.loads(process.stdout.readline());assert reply['id']==sequence and 'error' not in reply,reply
            calls.append({'request':r,'response':reply,'seconds':time.monotonic()-before})
            return reply['result']
        def tool(name,args=None):
            response=request('tools/call',{'name':name,'arguments':args or {}})
            assert not response.get('isError'),response
            result=json.loads(response['content'][0]['text'])
            if 'evidence' in result:
                file=Path(unquote(urlparse(result['evidence']['uri']).path));raw=file.read_bytes()
                assert hashlib.sha256(raw).hexdigest()==file.with_suffix('.sha256').read_text().strip()
                assert json.loads(raw)['target_sha256']==sha
                saved=json.loads(request('tools/call',{'name':'read_evidence','arguments':{'id':result['evidence']['id'],'limit':40000}})['content'][0]['text'])
                assert saved['text']==raw.decode()[:40000]
            return result
        output={'model_sessions':0,'target_sha256':sha,'address_source':'EAOS search results only','target_executed':False}
        try:
            request('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'go-discovery-walkthrough','version':'1'}})
            catalog=request('tools/list')['tools'];assert len(catalog)==7
            opened=tool('open_program');deadline=time.monotonic()+900
            while 'analysis' in opened['data']:
                assert time.monotonic()<deadline,'Native walkthrough exceeded observation budget'
                time.sleep(2);opened=tool('open_program')
            output['open_seconds']=time.monotonic()-started
            assert opened['data']['go']['names']=='available',opened
            output['open']=opened
            found=[]
            for pattern in strings:
                result=tool('search',{'kind':'strings','pattern':pattern})
                hits=[item for item in result['data']['items'] if item.get('source')=='literal_bytes']
                assert hits,pattern
                assert all(item['extent']=='match' and item['text']==pattern for item in hits)
                # Ollama's fixed probes must recover the known existing code refs.
                # Fixture literals may have no stored Ghidra reference: discovery
                # must report zero honestly, rather than infer a missing link.
                if ollama:assert any(any(ref['function'] for ref in item['references']) for item in hits),pattern
                found.append({'pattern':pattern,'literal_hits':len(hits),'code_references_in_preview':sum(bool(ref['function']) for item in hits for ref in item['references'])})
            output['strings']=found
            assert sum(item['code_references_in_preview'] for item in found)>0
            output['strings_without_stored_code_references']=[item['pattern'] for item in found if not item['code_references_in_preview']]
            discovered=[]
            for pattern in functions:
                result=tool('search',{'kind':'functions','pattern':pattern,'limit':200})
                items=result['data']['items'];assert items,pattern
                preferred=[i for i in items if i['name'].endswith('envconfig.Host')] if pattern=='envconfig' else items
                exact=[i for i in preferred if i['name']==pattern or i['name'].endswith('.'+pattern)]
                fn=(exact or preferred or items)[0]
                inspected=tool('inspect',{'addresses':[fn['address']]})
                row=inspected['data'][0]
                if 'outline' in row and not row.get('pseudocode'):
                    row=tool('inspect',{'addresses':[fn['address']],'full':True})['data'][0]
                assert row.get('pseudocode') and row['name']==fn['name'],row
                assert row['source']=='go_pclntab' and inspected['classification']=='computed'
                discovered.append({'query':pattern,'name':fn['name'],'address':fn['address'],'pseudocode_available':True})
            output['functions']=discovered
            again=tool('open_program');assert again['data']['analysis_count']==opened['data']['analysis_count']==1
            assert cache.is_file()
            if existed:assert cache.stat().st_mtime_ns==old_mtime,'Index was rebuilt instead of reused'
            output.update(status='passed',cache_existed=existed,cache_reused=existed,seconds=time.monotonic()-started)
        except BaseException as error:
            output.update(status='failed',error=str(error));raise
        finally:
            process.stdin.close()
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            output['calls']=calls;report.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in output.items() if k not in ['calls','open']},ensure_ascii=False),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--eaos',required=True)
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--ollama',action='store_true')
    args=parser.parse_args();check(args.eaos,args.target.resolve(),args.report.resolve(),args.ollama)
