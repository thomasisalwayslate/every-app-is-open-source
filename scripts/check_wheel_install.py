#!/usr/bin/env python3
"""Test the unpublished wheel through uvx outside the checkout, with fresh caches.

Downloads Java/Ghidra from upstream; never uploads or publishes a distribution.
Retains the complete workspace and an immutable report for each invocation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-parent', type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    parent = args.work_parent.expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=parent, prefix='eaos-wheel-check-'))
    if work.is_relative_to(ROOT):
        raise RuntimeError('Wheel test must run outside the checkout')
    artifacts = sorted((ROOT/'dist').glob('*.whl'))
    if len(artifacts) != 1:
        raise RuntimeError('Build exactly one wheel first')
    wheel = work/artifacts[0].name
    shutil.copy2(artifacts[0], wheel)
    target = work/'program with spaces'
    source = work/'fixture.c'
    source.write_bytes((ROOT/'tests/fixture.c').read_bytes())
    subprocess.run(['/usr/bin/clang','-O2','-g0','-o',str(target),str(source)],check=True,capture_output=True)
    target_sha = sha(target)
    env = {key:value for key,value in os.environ.items()
           if not key.startswith(('PYTHON', 'UV_', 'EAOS_')) and key != 'VIRTUAL_ENV'}
    env.update({'UV_CACHE_DIR':str(work/'uv-cache'), 'UV_TOOL_DIR':str(work/'uv-tools'),
                'UV_TOOL_BIN_DIR':str(work/'uv-bin'), 'EAOS_RUNTIME_DIR':str(work/'runtimes'),
                'JAVA_HOME':'/invalid-host-java', 'GHIDRA_INSTALL_DIR':'/invalid-host-ghidra'})
    command = [shutil.which('uvx'),'--no-config','--python',sys.executable,
               '--from',str(wheel),'eaos','setup']
    assert not (work/'runtimes').exists() and not (work/'uv-cache').exists()
    print('Fresh external package workspace: '+str(work),flush=True)
    started = time.monotonic()
    with (work/'first-setup.log').open('w') as log:
        subprocess.run(command,cwd=work,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1800)
    first_seconds = time.monotonic()-started
    receipt_path = work/'runtimes/setup.json'
    first = json.loads(receipt_path.read_text())
    assert set(first['downloaded']) == {'ghidra.zip','jdk.tar.gz'}
    assert first['decompiler_built'] and first['pyghidra'] == '3.1.0'
    package_path = Path(first['package_location'])
    assert package_path.is_relative_to(work/'uv-cache') and not package_path.is_relative_to(ROOT)
    python = Path(first['python_executable'])
    probe = subprocess.check_output([str(python),'-I','-c',
        'import json,sys,eaos.runtime;from importlib.metadata import version;'
        'print(json.dumps({"package":eaos.runtime.__file__,"sys_path":sys.path,'
        '"versions":{p:version(p) for p in ["pyghidra","jpype1","packaging","tree-sitter","tree-sitter-javascript"]}}))'],
        cwd=work,env=env,text=True)
    probe = json.loads(probe)
    assert not any(Path(p).is_relative_to(ROOT) for p in probe['sys_path'] if p)
    assert probe['versions'] == {'pyghidra':'3.1.0','jpype1':'1.5.2','packaging':'26.3',
                                 'tree-sitter':'0.26.0','tree-sitter-javascript':'0.25.0'}
    print(f'Wheel setup downloaded both runtimes and built ARM64 in {first_seconds:.1f}s.',flush=True)
    native = Path(first['ghidra'])/'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'
    native_hash = sha(native)
    native_mtime = native.stat().st_mtime_ns
    started = time.monotonic()
    with (work/'offline-setup.log').open('w') as log:
        subprocess.run(command,cwd=work,env={**env,'UV_OFFLINE':'true'},stdout=log,
                       stderr=subprocess.STDOUT,check=True,timeout=120)
    offline_seconds = time.monotonic()-started
    second = json.loads(receipt_path.read_text())
    assert second['downloaded'] == [] and not second['decompiler_built']
    assert sha(native) == native_hash and native.stat().st_mtime_ns == native_mtime
    executable = python.parent/'eaos'
    results = []

    def call(tool, arguments=None):
        result = subprocess.run([str(executable),'call',str(target),tool,'--args',json.dumps(arguments or {})],
                                cwd=work,env=env,capture_output=True,text=True,timeout=180)
        with (work/'native.stderr').open('a') as log:
            log.write(result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr[-3000:])
        value = json.loads(result.stdout)
        results.append({'tool':tool,'result':value})
        return value

    assert call('open_program')['data']['analysis_count'] == 1
    found = call('search',{'kind':'functions','pattern':'quote'})
    address = found['data']['items'][0]['address']
    code = call('inspect',{'addresses':[address]})
    assert code['classification'] == 'computed' and 'return' in code['data'][0]['pseudocode']
    memory = call('read_memory',{'address':address,'length':16})
    assert memory['classification'] == 'fact' and len(memory['data']['hex']) == 32
    assert call('calculate',{'expression':'sum(range(10))'})['data']['value'] == '45'
    decoded = call('decode_swift_string',{'words':[int.from_bytes(b'hello\0\0\0','little'),0xE500000000000000]})
    assert decoded['data']['text'] == 'hello'
    stored = call('read_evidence',{'id':code['evidence']['id'],'limit':40000})
    assert json.loads(stored['text'])['data'][0]['pseudocode'] == code['data'][0]['pseudocode']
    assert call('open_program')['data']['analysis_count'] == 1
    requests = [
        {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05'}},
        {'jsonrpc':'2.0','id':2,'method':'tools/list'},
        {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'inspect','arguments':{'addresses':[address]}}},
    ]
    result = subprocess.run([str(executable),'mcp',str(target)],cwd=work,env=env,
        input='\n'.join(json.dumps(item) for item in requests)+'\n',capture_output=True,text=True,timeout=180)
    (work/'mcp.stderr').write_text(result.stderr)
    assert result.returncode == 0, result.stderr[-3000:]
    responses = {item['id']:item for line in result.stdout.splitlines() if (item:=json.loads(line))}
    assert len(responses[2]['result']['tools']) == 8
    mcp = json.loads(responses[3]['result']['content'][0]['text'])
    assert mcp['data'][0]['pseudocode'] == code['data'][0]['pseudocode']
    results.append({'tool':'mcp_inspect','result':mcp})
    checked = 0
    for record in results:
        value = record['result']
        if 'evidence' not in value:
            continue
        path = Path(unquote(urlparse(value['evidence']['uri']).path))
        assert path.is_relative_to(work) and path.is_file()
        assert sha(path) == path.with_suffix('.sha256').read_text().strip()
        checked += 1
    assert sha(target) == target_sha and sha(wheel) == sha(artifacts[0])
    report = {'status':'passed','workspace':str(work),'wheel':str(wheel),'wheel_sha256':sha(wheel),
              'first_setup_seconds':first_seconds,'offline_setup_seconds':offline_seconds,
              'first_receipt':first,'second_receipt':second,'isolation_probe':probe,
              'target_sha256':target_sha,'mcp_tools':8,'evidence_records_checked':checked,
              'results':results,'command':command,'uploaded':False,'pushed':False}
    destination = ROOT/'reports/package-installation'/work.name
    destination.mkdir(parents=True,exist_ok=False)
    (destination/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    for name in ['first-setup.log','offline-setup.log','native.stderr','mcp.stderr']:
        shutil.copy2(work/name,destination/name)
    shutil.copy2(work/'runtimes/decompiler-build.log',destination/'decompiler-build.log')
    print(json.dumps({key:report[key] for key in ['status','workspace','first_setup_seconds',
        'offline_setup_seconds','mcp_tools','evidence_records_checked']},indent=2),flush=True)
    print('Report: '+str(destination/'results.json'),flush=True)


if __name__ == '__main__':
    main()
