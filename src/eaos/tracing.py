"""Cooperative bounded traversal of observed static call relationships.

The provider owns native reads and must obey its supplied edge limit and check
cancellation/deadlines while enumerating. This module never decompiles, invokes
an application, or promotes a candidate selector into a runtime dispatch edge.
"""
from __future__ import annotations

from collections import deque
import math
import time


def _integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f'{name} must be an integer from {minimum} through {maximum}')
    return value


def trace(start, provider, *, direction='callees', max_depth=3, max_nodes=32,
          max_edges=128, max_seconds=2, per_node_edges=32, cancel=None,
          clock=time.monotonic):
    """Return nodes, call-site edges and a retained unresolved frontier.

    ``provider(address, direction, edge_limit)`` returns a node, a bounded list
    of ``edges`` (source/target/call_site), optional ``unresolved`` records, and
    ``complete`` describing only its relationship enumeration for that node.
    Unknown or indirect targets are frontier records and are never traversed.
    ``call_site`` means an instruction address, not a pseudocode token PC.

    Limits apply to traversal in this call, not the whole selected program.
    ``cancel()`` returns true when cancelled. It is also the provider's duty to
    check it during a native read: a synchronous callback cannot be preempted by
    this pure walker. Identity/provenance on provider records is preserved.
    """
    if not isinstance(start, str) or not start or len(start) > 256:
        raise ValueError('start must be a nonempty address string of at most 256 characters')
    if direction not in ('callees', 'callers'):
        raise ValueError('direction must be callees or callers')
    max_depth = _integer(max_depth, 'max_depth', 0, 8)
    max_nodes = _integer(max_nodes, 'max_nodes', 1, 128)
    max_edges = _integer(max_edges, 'max_edges', 1, 512)
    per_node_edges = _integer(per_node_edges, 'per_node_edges', 1, 128)
    if (isinstance(max_seconds, bool) or not isinstance(max_seconds, (float, int)) or
            not math.isfinite(max_seconds) or not 0 < max_seconds <= 30):
        raise ValueError('max_seconds must be finite, greater than zero and at most 30')
    started = clock()
    queue = deque([(start, 0)])
    queued = {start}
    visited, nodes, edges, frontier, edge_keys = set(), [], [], [], set()
    frontier_keys = set()
    frontier_omitted = 0
    stop = 'queue_exhausted'
    relation_complete = True

    def pending(address, reason, depth, **details):
        nonlocal frontier_omitted
        key = (address, reason, details.get('source'), details.get('target'), details.get('call_site'))
        if key in frontier_keys:
            return
        frontier_keys.add(key)
        # Independent from the graph budget, but still bounded output.
        if len(frontier) >= 512:
            frontier_omitted += 1
            return
        frontier.append({'address': address, 'depth': depth, 'reason': reason, **details})

    def interrupted():
        if cancel is not None and cancel():
            return 'cancelled'
        if clock() - started >= max_seconds:
            return 'time_limit'
        return None

    while queue:
        if reason := interrupted():
            stop = reason
            break
        address, depth = queue.popleft()
        if address in visited:
            continue
        if len(nodes) >= max_nodes:
            pending(address, 'node_limit', depth)
            stop = 'node_limit'
            break
        if depth > max_depth:
            pending(address, 'depth_limit', depth)
            continue
        visited.add(address)
        try:
            batch = provider(address, direction, min(per_node_edges, max_edges - len(edges)))
        except (InterruptedError, TimeoutError) as error:
            relation_complete = False
            stop = 'cancelled' if isinstance(error, InterruptedError) else 'time_limit'
            pending(address, stop, depth, error=str(error)[:1000])
            break
        except Exception as error:
            relation_complete = False
            pending(address, 'provider_failure', depth, error=str(error)[:1000])
            continue
        if reason := interrupted():
            relation_complete = False
            stop = reason
            pending(address, reason, depth)
            break
        if not isinstance(batch, dict) or not isinstance(batch.get('node'), dict):
            relation_complete = False
            pending(address, 'invalid_provider_result', depth)
            continue
        node = dict(batch['node'])
        if node.get('address') != address:
            relation_complete = False
            pending(address, 'provider_identity_mismatch', depth)
            continue
        # Mirror this provider's explicit enumeration assertion on the node.
        # None means it supplied no assertion; frontier records carry details.
        reported = batch.get('complete')
        nodes.append({**node, 'depth': depth, 'relationships': {
            'enumeration_reported_complete': reported if type(reported) is bool else None,
            'scope':'known instruction/reference edges only',
            'runtime_dispatch_established':False}})
        batch_edges = batch.get('edges', [])
        unresolved = batch.get('unresolved', [])
        if not isinstance(batch_edges, list) or not isinstance(unresolved, list):
            relation_complete = False
            pending(address, 'invalid_provider_relationships', depth)
            continue
        if batch.get('complete') is not True:
            relation_complete = False
            pending(address, 'relationship_enumeration_incomplete', depth)
        if len(batch_edges) > per_node_edges:
            relation_complete = False
            pending(address, 'per_node_edge_limit', depth,
                    omitted=len(batch_edges) - per_node_edges)
        for record in unresolved[:per_node_edges]:
            if not isinstance(record, dict):
                relation_complete = False
                pending(address, 'invalid_unresolved_record', depth)
                continue
            record = dict(record)
            location = record.pop('address', address)
            if not isinstance(location, str):
                location = address
            record.pop('depth', None)
            reason = record.pop('reason', 'unresolved_relationship')
            pending(location, str(reason), depth, **record)
        if len(unresolved) > per_node_edges:
            relation_complete = False
            pending(address, 'unresolved_record_limit', depth,
                    omitted=len(unresolved) - per_node_edges)
        for edge in batch_edges[:per_node_edges]:
            if reason := interrupted():
                stop = reason
                pending(address, reason, depth)
                break
            if not isinstance(edge, dict):
                relation_complete = False
                pending(address, 'invalid_edge', depth)
                continue
            source, target = edge.get('source'), edge.get('target')
            site = edge.get('call_site')
            if (not isinstance(source, str) or not source or
                    (target is not None and (not isinstance(target, str) or not target)) or
                    (site is not None and not isinstance(site, str)) or
                    (direction == 'callees' and source != address) or
                    (direction == 'callers' and target != address)):
                relation_complete = False
                pending(address, 'invalid_edge_identity', depth)
                continue
            key = (source, target, site, edge.get('kind', 'call'))
            if key in edge_keys:
                continue
            if len(edges) >= max_edges:
                pending(address, 'edge_limit', depth, source=source, target=target, call_site=site)
                stop = 'edge_limit'
                break
            edge_keys.add(key)
            edges.append(dict(edge))
            neighbor = target if direction == 'callees' else source
            if neighbor is None:
                relation_complete = False
                pending(address, 'unresolved_target', depth, source=source, target=target, call_site=site)
            elif neighbor not in visited and neighbor not in queued:
                if depth >= max_depth:
                    pending(neighbor, 'depth_limit', depth + 1, source=source, target=target, call_site=site)
                else:
                    queued.add(neighbor)
                    queue.append((neighbor, depth + 1))
        if stop != 'queue_exhausted':
            break
        if len(edges) >= max_edges and queue:
            stop = 'edge_limit'
            break
    for address, depth in queue:
        if address not in visited:
            pending(address, stop if stop != 'queue_exhausted' else 'unvisited', depth)
    # A complete bounded queue is not whole-program coverage or proof that an
    # unresolved Objective-C/Swift runtime dispatch cannot reach another method.
    return {
        'start': start, 'direction': direction, 'nodes': nodes, 'edges': edges,
        'frontier': frontier,
        'coverage': {'stopping_reason': stop, 'nodes': len(nodes), 'edges': len(edges),
                     'frontier_omitted': frontier_omitted,
                     'enumerated_relationships_complete': relation_complete,
                     'traversal_complete': not frontier and not frontier_omitted and stop == 'queue_exhausted',
                     'scope': 'bounded static relationships; runtime dispatch and program-wide reachability not established',
                     'elapsed_seconds': max(0, clock() - started),
                     'limits': {'depth': max_depth, 'nodes': max_nodes, 'edges': max_edges,
                                'seconds': max_seconds, 'per_node_edges': per_node_edges}},
        'classification': 'computed',
    }
