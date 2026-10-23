"""Bounded instruction/reference relationships; never treats token mappings as calls."""
from __future__ import annotations

import time
from bisect import bisect_left


def provider(backend, deadline, cancelled=lambda: False):
    def check():
        if cancelled() or (backend.monitor and backend.monitor.isCancelled()):
            raise InterruptedError('Call tracing cancelled')
        if time.monotonic() >= deadline:
            raise TimeoutError('Call tracing time budget reached')

    def relations(address, direction, limit):
        check()
        manager = backend.program.getFunctionManager()
        fn = manager.getFunctionContaining(backend.address(address))
        if fn is None:
            node = {'address': address}
            # A direct destination can have a known candidate symbol without a
            # recovered body. Preserve that identity; never promote it to a
            # prepared function or expand discovery as a side effect of tracing.
            starts = (getattr(backend, 'quick_metadata', None) or {}).get('function_starts', [])
            try:
                number = int(address, 16)
            except ValueError:
                number = -1
            position = bisect_left(starts, number)
            if backend.analysis_mode == 'quick' and position < len(starts) and starts[position] == number:
                from .function_discovery import candidate_metadata
                node, _ = candidate_metadata(backend, number, deadline, lambda: check() or False)
            return {'node': node, 'edges': [], 'complete':False,
                    'unresolved':[{'address':address,'reason':'No analyzed function; prepare/inspect this candidate explicitly first.'}]}
        start = str(fn.getEntryPoint())
        info = backend.fn_info(fn)
        node = {key:value for key,value in info.items()
                if key in ('address','name','qualified_name','aliases','source')}
        edges, unresolved = [], []
        if fn.isExternal():
            return {'node':node, 'edges':[], 'complete':False,
                    'unresolved':[{'address':start,'reason':'External implementation is outside this component.'}]}
        complete = True
        if backend.analysis_mode == 'quick':
            complete = False
            unresolved.append({'address':start,'reason':'Quick-mode references are partial; missing edges do not establish absence.'})
            if backend.function_readiness.get(start,{}).get('state') != 'flow_prepared':
                unresolved.append({'address':start,'reason':'Function flow not prepared; inspect this function explicitly before deeper traversal.'})
        if direction == 'callees':
            scanned = 0
            for index, instruction in enumerate(backend.program.getListing().getInstructions(fn.getBody(),True)):
                check()
                scanned += 1
                if index >= 16384:
                    complete = False
                    unresolved.append({'address':str(instruction.getAddress()),'reason':'instruction_scan_limit'})
                    break
                flow = instruction.getFlowType()
                if not flow.isCall() and not (flow.isJump() and not flow.isConditional()):
                    continue
                site = str(instruction.getAddress())
                if flow.isComputed():
                    complete = False
                    unresolved.append({'address':site,'reason':'Indirect call/jump; runtime dispatch not established.'})
                    # Ghidra may supply computed target hints, but they are not direct edges.
                    if len(unresolved) >= limit:
                        complete = False
                        break
                    continue
                destinations = list(instruction.getFlows())
                if not destinations:
                    complete = False
                    unresolved.append({'address':site,'reason':'Flow has no recovered target.'})
                for destination in destinations:
                    if not flow.isCall() and fn.getBody().contains(destination):
                        continue
                    target = manager.getFunctionAt(destination)
                    edges.append({'source':start,'target':str(destination), 'call_site':site,
                                  'kind':'direct_call' if flow.isCall() else 'direct_outgoing_jump',
                                  'basis':'instruction_flow', 'target_analyzed':target is not None})
                    if len(edges) >= limit:
                        complete = False
                        unresolved.append({'address':site,'reason':'per_node_edges_limit'})
                        break
                if len(edges) >= limit:
                    break
            if not scanned:
                complete = False
                unresolved.append({'address':start,'reason':'No recovered instructions in this function body.'})
        else:
            references = backend.program.getReferenceManager().getReferencesTo(fn.getEntryPoint())
            for index, reference in enumerate(references):
                check()
                if index >= 4096:
                    complete = False
                    unresolved.append({'address':start,'reason':'incoming_reference_scan_limit'})
                    break
                site = reference.getFromAddress()
                instruction = backend.program.getListing().getInstructionAt(site)
                if instruction is None:
                    continue
                flow = instruction.getFlowType()
                if flow.isComputed():
                    complete = False
                    unresolved.append({'address':str(site),'reason':'Computed incoming reference is not a proven direct call.'})
                    if len(unresolved) >= limit:
                        complete = False
                        break
                    continue
                if not flow.isCall() and not (flow.isJump() and not flow.isConditional()):
                    continue
                # Require the referenced destination to be an actual instruction flow.
                if not any(destination == fn.getEntryPoint() for destination in instruction.getFlows()):
                    continue
                caller = manager.getFunctionContaining(site)
                if caller is None:
                    complete = False
                    unresolved.append({'address':str(site),'reason':'Caller function ownership unknown.'})
                    continue
                if not flow.isCall() and caller.getEntryPoint() == fn.getEntryPoint():
                    continue
                edges.append({'source':str(caller.getEntryPoint()),'target':start,
                              'call_site':str(site),'kind':'direct_call' if flow.isCall() else 'direct_outgoing_jump',
                              'basis':'instruction_flow','target_analyzed':True})
                if len(edges) >= limit:
                    complete = False
                    unresolved.append({'address':start,'reason':'per_node_edges_limit'})
                    break
        return {'node':node,'edges':edges,'unresolved':unresolved,'complete':complete}
    return relations
