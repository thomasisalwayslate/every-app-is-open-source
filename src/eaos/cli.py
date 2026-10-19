"""CLI and stdio MCP, using only the standard library for transport."""
from __future__ import annotations

import argparse
import json
import os
import signal
from pathlib import Path
import subprocess
import sys

from .backend import Backend
from .session import McpSession


from .contracts import TOOLS, validate_arguments
from . import __version__


def protect_stdout():
    sys.stdout.flush()
    duplicate = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = os.fdopen(duplicate, 'w', encoding='utf-8', buffering=1)


def serve(backend):
    catalog = [{'name':name,'description':description,'inputSchema':spec} for name,description,spec in TOOLS]
    allowed = {t['name'] for t in catalog}
    maximum = 1024 * 1024
    while line := sys.stdin.readline(maximum + 1):
        if len(line) > maximum:
            while line and not line.endswith('\n'):
                line = sys.stdin.readline(maximum + 1)
            print(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {
                'code': -32600, 'message': 'Request exceeds 1 MiB character limit'}}), flush=True)
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        if not isinstance(request, dict) or 'id' not in request:
            continue
        try:
            method = request['method']
            if method == 'initialize':
                result = {'protocolVersion':request.get('params',{}).get('protocolVersion','2024-11-05'),
                    'capabilities':{'tools':{}},'serverInfo':{'name':'every-app-is-open-source','version':__version__}}
            elif method == 'ping': result = {}
            elif method == 'tools/list': result = {'tools':catalog}
            elif method == 'tools/call':
                name = request['params']['name']
                if name not in allowed: raise ValueError('Unknown tool')
                try:
                    arguments = validate_arguments(name, request['params'].get('arguments', {}))
                    output = (backend.call(name, arguments) if isinstance(backend, McpSession)
                              else getattr(backend,name)(**arguments))
                    result = {'content':[{'type':'text','text':json.dumps(output,ensure_ascii=False,separators=(',',':'))}]}
                except Exception as exc:
                    failure = {'error':str(exc),'classification':'fact','scope':'tool failure; no analysis claim'}
                    if getattr(exc, 'status', None) is not None:
                        failure['analysis'] = exc.status
                    result = {'isError':True,'content':[{'type':'text','text':json.dumps(failure)}]}
            else: raise ValueError('Unsupported method')
            response = {'jsonrpc':'2.0','id':request['id'],'result':result}
        except Exception as exc:
            response = {'jsonrpc':'2.0','id':request['id'],'error':{'code':-32603,'message':str(exc)}}
        print(json.dumps(response,ensure_ascii=False),flush=True)


def main():
    parser = argparse.ArgumentParser(description='Every App Is Open Source: small native analysis tools')
    sub = parser.add_subparsers(dest='command',required=True)
    setup = sub.add_parser('setup',help='Download verified Java/Ghidra and build Apple Silicon native helpers')
    setup.add_argument('--rebuild',action='store_true',help='Rebuild the ARM64 decompiler and GNU demanglers')
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
    arguments = None
    if args.command == 'call':
        try:
            arguments = validate_arguments(args.tool, json.loads(args.args))
        except (ValueError, TypeError) as exc:
            parser.exit(1, f'EAOS call failed: {exc}\n')
    protect_stdout()
    backend = Backend(args.binary)
    session = McpSession(backend) if args.command == 'mcp' else None
    previous_term = None
    if session is not None:
        previous_term = signal.signal(signal.SIGTERM,
                                      lambda *_: sys.exit(128 + signal.SIGTERM))
    try:
        if session is not None: serve(session)
        else: print(json.dumps(getattr(backend,args.tool)(**arguments),ensure_ascii=False,indent=2))
    finally:
        if session is not None: session.close()
        else: backend.close()
        if previous_term is not None: signal.signal(signal.SIGTERM, previous_term)


if __name__ == '__main__':
    main()
