"""CLI and stdio MCP, using only the standard library for transport."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from .backend import Backend


def schema(properties=None, required=None):
    return {'type':'object','properties':properties or {},'required':required or [],'additionalProperties':False}


S = {'type':'string'}
B = {'type':'boolean','default':False}
TOOLS = [
    ('open_program','Selected target, memory map and analysis cache. full=true includes all metadata.',schema({'full':B})),
    ('search','Substring search of strings (with xrefs) or functions. Page with next_offset; full=true for signatures.',schema({'kind':{'type':'string','enum':['strings','functions']},'pattern':S,'offset':{'type':'integer','minimum':0},'limit':{'type':'integer','minimum':1,'maximum':200},'full':B})),
    ('inspect','Batch addresses. Default computed pseudocode. mode=calls, references, assembly or all; full=true expands. Omitted detail: read_evidence.',schema({'addresses':{'type':'array','items':S,'minItems':1,'maxItems':8},'mode':{'type':'string','enum':['decompile','assembly','references','calls','all']},'full':B},['addresses'])),
    ('read_memory','Fact: literal bytes at a virtual address. Default hex; format=utf8 or both for text display.',schema({'address':S,'length':{'type':'integer','minimum':1,'maximum':65536},'format':{'type':'string','enum':['hex','utf8','both']}},['address'])),
    ('calculate','Pure Python arithmetic/bytes expression. No imports, filesystem, network or program execution. Useful for numeric tables and packed constants.',schema({'expression':S},['expression'])),
    ('decode_swift_string','Decode 64-bit little-endian Swift small String storage. Supply address or two unsigned words. Reject unsupported pointer layouts instead of inventing text.',schema({'words':{'type':'array','items':{'anyOf':[S,{'type':'integer'}]},'minItems':2,'maxItems':2},'address':S})),
    ('read_evidence','Retrieve a content-checked evidence record by its returned id, with character paging. Never reads arbitrary paths.',schema({'id':S,'offset':{'type':'integer','minimum':0},'limit':{'type':'integer','minimum':1,'maximum':40000}},['id'])),
]


def protect_stdout():
    sys.stdout.flush()
    duplicate = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = os.fdopen(duplicate, 'w', encoding='utf-8', buffering=1)


def serve(backend):
    catalog = [{'name':name,'description':description,'inputSchema':spec} for name,description,spec in TOOLS]
    allowed = {t['name'] for t in catalog}
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            continue
        if 'id' not in request:
            continue
        try:
            method = request['method']
            if method == 'initialize':
                result = {'protocolVersion':request.get('params',{}).get('protocolVersion','2024-11-05'),
                    'capabilities':{'tools':{}},'serverInfo':{'name':'every-app-is-open-source','version':'0.1.0'}}
            elif method == 'ping': result = {}
            elif method == 'tools/list': result = {'tools':catalog}
            elif method == 'tools/call':
                name = request['params']['name']
                if name not in allowed: raise ValueError('Unknown tool')
                try:
                    output = getattr(backend,name)(**request['params'].get('arguments',{}))
                    result = {'content':[{'type':'text','text':json.dumps(output,ensure_ascii=False,separators=(',',':'))}]}
                except Exception as exc:
                    result = {'isError':True,'content':[{'type':'text','text':json.dumps({'error':str(exc),'classification':'fact','scope':'tool failure; no analysis claim'})}]}
            else: raise ValueError('Unsupported method')
            response = {'jsonrpc':'2.0','id':request['id'],'result':result}
        except Exception as exc:
            response = {'jsonrpc':'2.0','id':request['id'],'error':{'code':-32603,'message':str(exc)}}
        print(json.dumps(response,ensure_ascii=False),flush=True)


def main():
    parser = argparse.ArgumentParser(description='Every App Is Open Source: small native analysis tools')
    sub = parser.add_subparsers(dest='command',required=True)
    setup = sub.add_parser('setup',help='Download verified Java/Ghidra and build the Apple Silicon decompiler')
    setup.add_argument('--rebuild',action='store_true',help='Rebuild the ARM64 decompiler')
    setup.add_argument('--archive-cache',type=Path,
                       help='Use an existing directory of checksum-verified runtime archives')
    server = sub.add_parser('mcp'); server.add_argument('binary')
    call = sub.add_parser('call');call.add_argument('binary');call.add_argument('tool',choices=[t[0] for t in TOOLS]);call.add_argument('--args',default='{}')
    args = parser.parse_args()
    if args.command == 'setup':
        from .runtime import install
        try:
            install(args.rebuild, args.archive_cache.expanduser().resolve() if args.archive_cache else None)
        except (RuntimeError,OSError,subprocess.CalledProcessError) as exc:
            parser.exit(1, f'EAOS setup failed: {exc}\n')
        return
    protect_stdout()
    backend = Backend(args.binary)
    try:
        if args.command == 'mcp': serve(backend)
        else: print(json.dumps(getattr(backend,args.tool)(**json.loads(args.args)),ensure_ascii=False,indent=2))
    finally:
        backend.close()


if __name__ == '__main__':
    main()
