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


from .contracts import TOOLS, validate_arguments, validate_search_profile
from . import __version__


def protect_stdout():
    sys.stdout.flush()
    duplicate = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = os.fdopen(duplicate, 'w', encoding='utf-8', buffering=1)


def serve(backend):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    catalog = [{'name':name,'description':description,'inputSchema':spec} for name,description,spec in TOOLS]
    allowed = {t['name'] for t in catalog}
    writer, guard = threading.Lock(), threading.Lock()
    pending = {}
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='eaos-rpc')

    def send(value):
        with writer:
            print(json.dumps(value,ensure_ascii=False),flush=True)

    def tool_call(request, cancelled):
        identifier = request['id']
        try:
            if cancelled.is_set():
                raise RuntimeError('Request cancelled before execution')
            name = request['params']['name']
            if name not in allowed:
                raise ValueError('Unknown tool')
            arguments = validate_arguments(name,request['params'].get('arguments',{}))
            output = (backend.call(name,arguments,request_id=identifier) if isinstance(backend,McpSession)
                      else getattr(backend,name)(**arguments))
            result = {'content':[{'type':'text','text':json.dumps(output,ensure_ascii=False,separators=(',',':'))}]}
        except Exception as exc:
            failure = {'error':str(exc),'classification':'fact','scope':'tool failure; no analysis claim'}
            if getattr(exc,'status',None) is not None:
                failure['analysis'] = exc.status
            result = {'isError':True,'content':[{'type':'text','text':json.dumps(failure)}]}
        try:
            send({'jsonrpc':'2.0','id':identifier,'result':result})
        finally:
            if isinstance(backend,McpSession):
                backend.forget_request(identifier)
            with guard:
                pending.pop(identifier,None)

    maximum = 1024*1024
    try:
        while line := sys.stdin.readline(maximum+1):
            if len(line)>maximum:
                while line and not line.endswith('\n'):
                    line = sys.stdin.readline(maximum+1)
                send({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Request exceeds 1 MiB character limit'}})
                continue
            try:
                request = json.loads(line)
            except ValueError:
                continue
            if not isinstance(request,dict):
                continue
            if request.get('method')=='notifications/cancelled':
                params = request.get('params',{})
                if not isinstance(params,dict):
                    continue
                identifier = params.get('requestId')
                if type(identifier) in (str,int):
                    with guard:
                        event = pending.get(identifier)
                        if event:
                            event.set()
                    if event and isinstance(backend,McpSession):
                        backend.cancel_request(identifier)
                continue
            if 'id' not in request:
                continue
            identifier = request['id']
            if type(identifier) not in (str,int):
                send({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid request id'}})
                continue
            try:
                method = request['method']
                if method=='initialize':
                    result = {'protocolVersion':request.get('params',{}).get('protocolVersion','2024-11-05'),
                              'capabilities':{'tools':{}},'serverInfo':{'name':'every-app-is-open-source','version':__version__}}
                elif method=='ping':
                    result = {}
                elif method=='tools/list':
                    result = {'tools':catalog}
                elif method=='tools/call':
                    event = threading.Event()
                    with guard:
                        if len(pending)>=8 or identifier in pending:
                            raise ValueError('Too many pending requests or duplicate request id')
                        pending[identifier] = event
                    if isinstance(backend,McpSession):
                        pool.submit(tool_call,request,event)
                    else:
                        tool_call(request,event)
                    continue
                else:
                    raise ValueError('Unsupported method')
                send({'jsonrpc':'2.0','id':identifier,'result':result})
            except Exception as exc:
                send({'jsonrpc':'2.0','id':identifier,'error':{'code':-32603,'message':str(exc)}})
    finally:
        # EOF is client shutdown: stop native work before waiting on RPC threads.
        with guard:
            for event in pending.values():
                event.set()
        if isinstance(backend,McpSession):
            backend.close()
        pool.shutdown(wait=True,cancel_futures=True)


def main():
    parser = argparse.ArgumentParser(description='Every App Is Open Source: small native analysis tools')
    sub = parser.add_subparsers(dest='command',required=True)
    setup = sub.add_parser('setup',help='Download verified Java/Ghidra and build Apple Silicon native helpers')
    setup.add_argument('--rebuild',action='store_true',help='Rebuild the ARM64 decompiler and GNU demanglers')
    setup.add_argument('--archive-cache',type=Path,
                       help='Use an existing directory of checksum-verified runtime archives')
    server = sub.add_parser('mcp'); server.add_argument('binary')
    call = sub.add_parser('call');call.add_argument('binary');call.add_argument('tool',choices=[t[0] for t in TOOLS]);call.add_argument('--args',default='{}')
    for command in (server,call):
        command.add_argument('--architecture',choices=['auto','arm64','arm64e','x86_64'],default='auto')
        command.add_argument('--analysis-mode',choices=['full','quick'],default='full')
        command.add_argument('--request-timeout',type=float,default=120,help='Native request deadline, seconds (0.05..7200)')
        command.add_argument('--analysis-timeout',type=float,default=3600,help='Initial analysis deadline, seconds (0.05..7200)')
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
            if args.tool=='search':validate_search_profile(arguments,args.analysis_mode)
        except (ValueError, TypeError) as exc:
            parser.exit(1, f'EAOS call failed: {exc}\n')
    protect_stdout()
    try:
        backend = Backend(args.binary,architecture=args.architecture,analysis_mode=args.analysis_mode)
    except (ValueError, FileNotFoundError) as exc:
        parser.exit(1, f'EAOS cannot open this program: {exc}\n')
    session = McpSession(backend,request_timeout=args.request_timeout,analysis_timeout=args.analysis_timeout)
    previous_term = None
    if session is not None:
        previous_term = signal.signal(signal.SIGTERM,
                                      lambda *_: sys.exit(128 + signal.SIGTERM))
    try:
        if args.command == 'mcp':
            serve(session)
        else:
            pure = args.tool in {'calculate','read_evidence'} or args.tool=='decode_swift_string' and 'words' in arguments
            if not pure and not (args.tool=='open_program' and arguments.get('cancel')):
                session.wait_ready(arguments.get('analysis_mode') if args.tool=='open_program' else None)
            print(json.dumps(session.call(args.tool,arguments),ensure_ascii=False,indent=2))
    finally:
        if session is not None: session.close()
        else: backend.close()
        if previous_term is not None: signal.signal(signal.SIGTERM, previous_term)


if __name__ == '__main__':
    main()
