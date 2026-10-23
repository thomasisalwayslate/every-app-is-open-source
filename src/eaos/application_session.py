"""Selected-root operations plus one explicitly selected native component owner."""
from __future__ import annotations

import threading
import re
import json
from pathlib import Path

from .application import Application
from .backend import Backend
from .contracts import APPLICATION_TOOLS, TOOLS, validate_arguments
from .evidence import Evidence
from .session import McpSession


class ApplicationSession(McpSession):
    """Use the normal native session unchanged; never analyze the original bundle."""
    tools = TOOLS + APPLICATION_TOOLS

    def __init__(self, root, workspace, *, architecture='auto', analysis_mode='full',
                 request_timeout=120, analysis_timeout=3600):
        self.application = Application(Path(root),Path(workspace))
        self.native = None
        self.selected = None
        self.architecture, self.analysis_mode = architecture, analysis_mode
        self.request_timeout, self.analysis_timeout = request_timeout, analysis_timeout
        self.closed = False
        self.guard = threading.RLock()
        self.local_operation = None
        self.native_dispatches = 0
        self.cancelled_ids = set()
        self.application_evidence = None

    def _record(self, operation, data, snapshot):
        evidence = Evidence(self.application._folder('evidence',snapshot),snapshot)
        self.application_evidence = evidence
        link = evidence.save(operation,'computed',data,
            ['Selected-root inventory/lexical interpretations only; no application execution.',
             'Selected-component coverage is not coverage of the entire application.'],
            {'application_snapshot':snapshot,'scope':'bounded_selected_root'})
        preview = json.loads(json.dumps(data))
        # Full immutable records stay on disk; inventory gaps and lexical strings
        # must not defeat the small-answer default or silently claim completeness.
        for container, key in ((preview,'relationships'),(preview.get('coverage',{}),'gaps'),
                               (preview.get('coverage',{}),'unparsed')):
            if key in container and len(container[key])>8:
                container[key+'_total']=len(container[key])
                container[key]=container[key][:8]
                container[key+'_truncated']=True
        for key in ('items','observations'):
            for row in preview.get(key,[]):
                if len(json.dumps(row))>1800:
                    retained = {name:row[name] for name in
                                ('component_id','path','kind','size','sha256','line','source_offset',
                                 'method','receiver','literal_argument','argument_status','relationship',
                                 'classification','capturable') if name in row}
                    for name,value in list(retained.items()):
                        if isinstance(value,str) and len(value)>512:
                            retained[name]=value[:512]
                            retained[name+'_truncated']=True
                    retained['full_metadata_in_evidence']=True
                    row.clear();row.update(retained)
        if len(json.dumps(preview,ensure_ascii=False))>16000:
            # An unusual page can still be large. Preserve its exact page and
            # continuations in evidence instead of returning an incomplete view.
            preview={key:value for key,value in preview.items() if key in
                     ('application_snapshot','component_id','source_sha256','view','matches','next_offset')}
            preview.update(preview_omitted=True,
                           next='read_evidence with the returned id retrieves this page and its full coverage.')
        return {'classification':'computed','data':preview,'evidence':link,
                'limitations':['Paths and bytes are recorded; roles/relationships are static interpretations.']}

    def _local(self, name, arguments, request_id):
        event = threading.Event()
        with self.guard:
            if self.closed:
                raise RuntimeError('Application session is closed')
            if request_id in self.cancelled_ids:
                raise InterruptedError('Request cancelled before execution')
            if self.local_operation is not None:
                raise RuntimeError('Another selected-root operation is active; wait or cancel it first')
            if self.native_dispatches or (self.native and (self.native.active or self.native.state in ('running','cancelling'))):
                raise RuntimeError('Native work is active; wait or cancel it before changing component scope')
            self.local_operation = {'request_id':request_id,'name':name,'event':event}
            self.application.cancelled = event.is_set
        try:
            if name == 'inventory_application':
                data = self.application.inventory(**arguments)
                if event.is_set():
                    raise InterruptedError('Inventory cancelled; committed snapshots preserved')
                return self._record(name,data,data['application_snapshot'])
            if name == 'inspect_javascript':
                data = self.application.inspect_javascript(**arguments)
                if event.is_set():
                    raise InterruptedError('JavaScript inspection cancelled; captured bytes preserved')
                return self._record(name,data,data['application_snapshot'])
            captured = self.application.capture(arguments['component_id'],
                                                architecture=arguments.get('architecture',self.architecture))
            if captured['selection'] is None:
                raise ValueError('Selected component is not a supported native Mach-O; use inspect_javascript for JavaScript')
            context = {key:captured[key] for key in ('application_snapshot','component_id','sha256')}
            with self.guard:
                if event.is_set() or self.closed:
                    raise InterruptedError('Component selection cancelled; capture preserved')
                old_native = self.native
                self.native = None
                self.selected = None
            # Do not hold the transport-control guard across shutdown or I/O.
            if old_native:
                old_native.close()
            analysis_root = Path(captured['path']).parent / 'eaos-analysis'
            if analysis_root.is_symlink():
                raise ValueError('Component analysis cache must not be a symlink')
            backend = Backend(captured['path'],architecture=arguments.get('architecture',self.architecture),
                              analysis_mode=arguments.get('analysis_mode',self.analysis_mode),
                              component_context=context,capture_cancelled=event.is_set)
            with self.guard:
                if event.is_set() or self.closed:
                    backend.close()
                    raise InterruptedError('Component selection cancelled; captured bytes preserved')
                self.native = McpSession(backend,request_timeout=self.request_timeout,
                                         analysis_timeout=self.analysis_timeout)
                self.selected = context
            # Selection/capture is explicit; startup remains status-responsive and cancellable.
            return self._record(name,{'selected_component':context,
                    'architecture':captured['selection'], 'analysis_mode':backend.analysis_mode,
                    'next':'Use open_program to start/check native analysis, then search/inspect/trace_calls.'},
                    captured['application_snapshot'])
        finally:
            with self.guard:
                self.local_operation = None
                self.application.cancelled = lambda: False

    def call(self, name, arguments, request_id=None):
        validate_arguments(name,arguments)
        with self.guard:
            if self.closed:
                raise RuntimeError('Application session is closed')
            if request_id in self.cancelled_ids:
                raise InterruptedError('Request cancelled before execution')
        if name in {entry[0] for entry in APPLICATION_TOOLS}:
            return self._local(name,arguments,request_id)
        if name == 'open_program' and arguments.get('cancel'):
            self.cancel_request(None)
            return {'classification':'fact','data':{'analysis':self.status()}}
        if name == 'read_evidence':
            if not re.fullmatch(r'[0-9a-f]{32}',arguments['id']):
                raise ValueError('Use an evidence id returned by this selected scope')
            # Never search other components' evidence stores by id.
            if self.application_evidence and (self.application_evidence.directory/(arguments['id']+'.json')).is_file():
                return self.application_evidence.read(**{'identifier' if key=='id' else key:value
                                                         for key,value in arguments.items()})
        with self.guard:
            if self.local_operation:
                if name=='open_program':
                    return {'classification':'fact','data':{'analysis':self.status()}}
                raise RuntimeError('Selected-root operation active; native work refused')
            native = self.native
            if native is None:
                if name=='open_program':
                    return {'classification':'fact','data':{'analysis':self.status()},
                            'limitations':['Inventory the root, then select_component explicitly. No native component is selected.']}
                raise ValueError('Use inventory_application and select_component before native operations')
            # Reserve scope before releasing the guard. Selection cannot replace
            # this native owner during the gap before its worker reserves work.
            self.native_dispatches += 1
        try:
            return native.call(name,arguments,request_id=request_id)
        finally:
            with self.guard:
                self.native_dispatches -= 1

    def wait_ready(self, mode=None):
        with self.guard:
            native = self.native
        if native:
            native.wait_ready(mode)

    def status(self):
        with self.guard:
            return {'state':'closed' if self.closed else 'working' if self.local_operation else 'ready',
                    'scope':'selected_root_and_explicit_component',
                    'operation':self.local_operation['name'] if self.local_operation else None,
                    'selected_component':self.selected,
                    'native':self.native.status() if self.native else None}

    def cancel_request(self, request_id):
        with self.guard:
            if request_id is not None:
                self.cancelled_ids.add(request_id)
            if self.local_operation and (request_id is None or self.local_operation['request_id']==request_id):
                self.local_operation['event'].set()
            native = self.native
        if native:
            if request_id is None:
                native.cancel()
            else:
                native.cancel_request(request_id)

    def forget_request(self, request_id):
        with self.guard:
            self.cancelled_ids.discard(request_id)
            native = self.native
        if native:
            native.forget_request(request_id)

    def close(self):
        with self.guard:
            self.closed = True
            if self.local_operation:
                self.local_operation['event'].set()
            native = self.native
        if native:
            native.close()
