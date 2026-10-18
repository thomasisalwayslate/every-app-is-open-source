#!/usr/bin/env python3
"""Exercise the real one-command installer in a fresh, isolated source snapshot.

No model calls or benchmark changes. Keeps raw logs under .cache/install-check-*.
Default exercises public downloads; --archive-cache reuses verified archives.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import unquote,urlparse

ROOT=Path(__file__).resolve().parents[1]
OVERLAY=['install.sh','eaos','.python-version','scripts/setup.py','scripts/check_install.py',
    'scripts/python-downloads.json','scripts/python-provenance.json','tests/test_setup.py',
    'pyproject.toml','uv.lock','src/eaos/distributions.json',
    *[str(path.relative_to(ROOT)) for path in sorted((ROOT/'src/eaos').glob('*.py'))]]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-cache',type=Path)
    args=parser.parse_args()
    cache=ROOT/'.cache';cache.mkdir(exist_ok=True)
    work=Path(tempfile.mkdtemp(dir=cache,prefix='install-check-'))
    checkout=work/'checkout with spaces';checkout.mkdir()
    source=subprocess.check_output(['git','archive','HEAD'],cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(source)) as archive:archive.extractall(checkout,filter='data')
    for name in OVERLAY:shutil.copy2(ROOT/name,checkout/name)
    installer_hashes={name:sha(checkout/name) for name in OVERLAY}
    print('Fresh source snapshot: '+str(checkout),flush=True)
    assert not (checkout/'.tools').exists() and not (checkout/'.venv').exists()
    before=sha(checkout/'uv.lock');started=time.monotonic()
    command=[str(checkout/'install.sh')]
    if args.archive_cache:command+=['--archive-cache',str(args.archive_cache.resolve())]
    with (work/'first-install.log').open('w') as log:
        subprocess.run(command,cwd=work,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1800)
    first_seconds=time.monotonic()-started
    first=json.loads((checkout/'.tools/setup.json').read_text())
    assert first['decompiler_built'] and len(first['verified_archives'])==2
    assert first['python']=='3.13.16' and first['pyghidra']=='3.1.0'
    assert (checkout/'.tools/python').is_dir()
    print(f'First installation passed in {first_seconds:.1f}s; testing offline rerun…',flush=True)
    output=checkout/'.tools/ghidra_12.1.4_PUBLIC/Ghidra/Features/Decompiler/os/mac_arm_64/decompile'
    mtime=output.stat().st_mtime_ns;decompiler_sha=sha(output);started=time.monotonic()
    with (work/'second-install.log').open('w') as log:
        subprocess.run(command,cwd=work,env={**os.environ,'UV_OFFLINE':'true'},stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
    second_seconds=time.monotonic()-started
    second=json.loads((checkout/'.tools/setup.json').read_text())
    assert not second['decompiler_built'] and not second['downloaded']
    assert output.stat().st_mtime_ns==mtime and sha(output)==decompiler_sha
    assert sha(checkout/'uv.lock')==before
    print('Offline rerun passed; testing CLI and MCP with real Ghidra…',flush=True)
    # Ghidra rejects a project directory with any dot-prefixed path component.
    # Keep the installation itself under .cache, but its input/project outside it.
    fixtures=ROOT/'private/install-fixtures'/work.name
    fixtures.mkdir(parents=True,exist_ok=False)
    target=fixtures/'program with spaces'
    subprocess.run(['/usr/bin/clang','-O2','-g0','-o',str(target),str(checkout/'tests/fixture.c')],check=True,capture_output=True)
    target_sha=sha(target);results={}
    # The launcher must select its local runtimes even with conflicting host values.
    env={**os.environ,'JAVA_HOME':'/invalid-host-java','GHIDRA_INSTALL_DIR':'/invalid-host-ghidra'}
    def call(name,arguments=None):
        p=subprocess.run([str(checkout/'eaos'),'call',str(target),name,'--args',json.dumps(arguments or {})],
            cwd=work,env=env,capture_output=True,text=True,timeout=180)
        with (work/'cli.log').open('a') as log:log.write(p.stderr)
        if p.returncode:raise RuntimeError(p.stderr[-2500:])
        value=json.loads(p.stdout);results[name]=value;return value
    first_open=call('open_program');assert first_open['data']['analysis_count']==1
    found=call('search',{'kind':'functions','pattern':'quote'})
    address=found['data']['items'][0]['address']
    code=call('inspect',{'addresses':[address]})
    assert code['classification']=='computed' and 'return' in code['data'][0]['pseudocode']
    memory=call('read_memory',{'address':address,'length':16})
    assert memory['classification']=='fact' and len(memory['data']['hex'])==32
    assert call('calculate',{'expression':'sum(range(10))'})['data']['value']=='45'
    stored=call('read_evidence',{'id':code['evidence']['id'],'limit':40000})
    assert json.loads(stored['text'])['data'][0]['pseudocode']==code['data'][0]['pseudocode']
    assert call('open_program')['data']['analysis_count']==1
    requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'install-check','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized'},
        {'jsonrpc':'2.0','id':2,'method':'tools/list'},
        {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'read_memory','arguments':{'address':address,'length':16}}}]
    p=subprocess.run([str(checkout/'eaos'),'mcp',str(target)],cwd=work,env=env,input='\n'.join(json.dumps(r) for r in requests)+'\n',capture_output=True,text=True,timeout=180)
    (work/'mcp.stderr').write_text(p.stderr)
    assert p.returncode==0,p.stderr[-2500:]
    responses={v['id']:v for line in p.stdout.splitlines() if (v:=json.loads(line))}
    assert len(responses[2]['result']['tools'])==7
    mcp=json.loads(responses[3]['result']['content'][0]['text']);assert mcp['data']['hex']==memory['data']['hex']
    results['mcp_memory']=mcp
    checked=0
    for value in results.values():
        if 'evidence' not in value:continue
        path=Path(unquote(urlparse(value['evidence']['uri']).path))
        assert path.is_file() and sha(path)==path.with_suffix('.sha256').read_text().strip()
        checked+=1
    assert sha(target)==target_sha
    core={str(p.relative_to(checkout)):sha(p) for p in sorted((checkout/'src/eaos').glob('*.py'))}
    protocol=json.loads((ROOT/'benchmark/protocol-round2.json').read_text())
    frozen_source_match=all(protocol['hashes'].get(name)==value for name,value in core.items())
    report={'status':'passed','benchmark_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'checkout':str(checkout),'fixture':str(target),'first_install_seconds':first_seconds,'offline_rerun_seconds':second_seconds,
        'actual_runtime_downloads':first['downloaded'],'first_receipt':first,'second_receipt':second,
        'checks':['Fresh checkout without .tools or .venv','Pinned local Python/JDK/Ghidra','ARM64 decompiler built from source','Archive sizes and SHA-256 verified','Offline rerun skips downloads and compilation','uv.lock unchanged','Paths with spaces and invocation outside checkout','Launcher overrides conflicting host runtime paths','Real CLI search/decompile/memory/calculator/evidence','Real MCP initialize/catalog/native read','Analysis reused with analysis_count=1','Target unchanged','Installed source matches the current installer snapshot'],
        'mcp_tools':7,'evidence_records_checked':checked,'core_hashes':core,
        'matches_frozen_benchmark_source':frozen_source_match,
        'installer_hashes':installer_hashes,'raw_logs':str(work)}
    assert all(sha(ROOT/name)==value for name,value in installer_hashes.items()),'Installer changed during the check'
    destination=ROOT/'reports/installation'/work.name;destination.mkdir(parents=True,exist_ok=False)
    (destination/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k in ['status','checkout','first_install_seconds','offline_rerun_seconds','actual_runtime_downloads','mcp_tools','evidence_records_checked']},indent=2),flush=True)


if __name__=='__main__':main()
