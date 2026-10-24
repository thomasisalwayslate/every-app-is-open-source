"""Bounded projections of checksum-verified JavaScript evidence, never execution."""
from __future__ import annotations

import hashlib
import json
import time

SCHEMA = 1
NODE_LIMIT = 96
LINK_LIMIT = 48
RECORD_LIMIT = 12
RECORD_BYTES = 256 * 1024
TOTAL_BYTES = 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def project(records, contexts, root_component, *, offset=0, limit=20, view=None,
            cancelled=lambda: False, max_nodes=NODE_LIMIT, max_links=LINK_LIMIT,
            max_seconds=2.0):
    """Source facts and conditional lookup candidates; never a cross-process edge.

    Records must arrive through Evidence.read. Contexts are current verified
    captures, not caller-supplied paths or presumed process identities.
    """
    if not 1 <= len(records) <= RECORD_LIMIT:
        raise ValueError('Use 1..12 distinct JavaScript evidence ids')
    deadline = time.monotonic() + max_seconds
    nodes, links, profiles, module_nodes, declarations = [], [], [], {}, []
    omitted = 0
    stopped = None
    snapshot = contexts[root_component]['application_snapshot']

    def check():
        if cancelled():
            raise InterruptedError('Relationship projection cancelled; original evidence preserved')
        return time.monotonic() < deadline

    def add(record, role, span, fields, classification='fact'):
        nonlocal omitted, stopped
        if not check():
            omitted += 1
            stopped = 'time_budget'
            return None
        context = contexts[record['data']['component_id']]
        if (not isinstance(span, dict) or type(span.get('start_byte')) is not int
                or type(span.get('end_byte')) is not int
                or not 0 <= span['start_byte'] < span['end_byte'] <= context['size']):
            raise ValueError('Evidence span conflicts with captured source; inspect the component again')
        if len(nodes) >= max_nodes:
            omitted += 1
            stopped = stopped or 'node_budget'
            return None
        span = {k: span[k] for k in ('start_byte', 'end_byte', 'line', 'column_byte', 'end_line', 'end_column_byte') if k in span}
        identity = {'evidence_id': record['id'], 'role': role, 'span': span, 'fields': fields}
        node = {'kind': 'source_node', 'node_id': digest(identity)[:24], 'role': role,
                'classification': classification, 'evidence_id': record['id'],
                'application_snapshot': snapshot, 'component_id': context['component_id'],
                'source_sha256': context['sha256'], 'span': span,
                'runtime_context_established': False, **fields}
        if record['data'].get('table_identity'):
            node['table_identity'] = record['data']['table_identity']
            node['selected_method_candidate'] = record['data']['module_scope']['candidate_id']
        nodes.append(node)
        return node

    def link(value):
        nonlocal omitted, stopped
        if not check() or len(links) >= max_links:
            omitted += 1
            stopped = stopped or ('relationship_budget' if len(links) >= max_links else 'time_budget')
            return
        links.append(value)

    for record in records:
        if not check():
            raise TimeoutError('Relationship projection time budget; select fewer evidence records')
        data = record.get('data', {})
        component = data.get('component_id')
        context = contexts.get(component)
        if (record.get('operation') != 'inspect_javascript' or not context
                or record.get('target_sha256') != snapshot
                or context['application_snapshot'] != snapshot
                or data.get('application_snapshot') != snapshot
                or data.get('source_sha256') != context['sha256']):
            raise ValueError('Stale/incompatible JavaScript evidence context; re-inspect within this application snapshot')
        if 'relationship_schema' in data:
            raise ValueError('Select original inspection evidence, not a composed relationship result')
        profile = {k: data[k] for k in ('parser', 'binding_schema', 'binding_identity', 'module_schema',
                   'module_view_identity', 'module_scope', 'table_identity', 'table_scope', 'coverage', 'scope_coverage',
                   'match_scope', 'limitations', 'unresolved', 'static_steps') if k in data}
        profiles.append({'evidence_id': record['id'], 'classification': record['classification'],
                         'component_id': component, 'source_sha256': context['sha256'],
                         'original_profile': profile, 'original_limitations': record.get('limitations', []),
                         'original_analysis': record.get('analysis'),
                         'complete_record_via': {'tool': 'read_evidence', 'id': record['id']}})
        scope = data.get('module_scope')
        if scope:
            if data.get('module_schema') != 7 or not data.get('table_identity') or not data.get('table_scope'):
                raise ValueError('Module evidence lacks current table identity; re-inspect module_at before composing')
            expected_table = digest({'source_sha256': context['sha256'],
                                     'namespace_context': {'application_snapshot': snapshot, 'component_id': component},
                                     'table_span': data['table_scope']})
            if data['table_identity'] != expected_table:
                raise ValueError('Conflicting table identity; re-inspect module_at')
            table_key = (component, context['sha256'], data['table_identity'], scope['candidate_id'])
            anchor = module_nodes.get(table_key)
            if anchor and (anchor['span']['start_byte'], anchor['span']['end_byte']) != (scope['start_byte'], scope['end_byte']):
                raise ValueError('Conflicting duplicate table candidates; inspect source windows without assuming overwrite semantics')
            if anchor is None:
                header_coverage = data.get('scope_coverage', {})
                anchor = add(record, 'table_method_candidate', scope,
                             {'table_identity': data['table_identity'], 'literal_header': scope['candidate_id'],
                              'table_key_unique_in_complete_headers': bool(
                                  header_coverage.get('header_enumeration_complete') is True
                                  and header_coverage.get('selected_key_count_in_examined_headers') == 1
                                  and header_coverage.get('unsupported_headers') == 0),
                              'binding_status': 'unresolved_syntax_only'})
                if anchor:
                    module_nodes[table_key] = anchor
        for row in data.get('items', []) + data.get('observations', []):
            fields = {k: row[k] for k in ('kind', 'source_name', 'initializer_source', 'literal_call_argument',
                      'unshadowed_formal_call_candidate', 'candidate_basis', 'formal_origin', 'target_source', 'value_source',
                      'callee_source', 'receiver_source', 'argument_sources', 'argument_count',
                      'arguments_truncated', 'heritage_source', 'function_kind', 'method', 'receiver',
                      'literal_argument', 'argument_status', 'argument_expression', 'module',
                      'relationship', 'binding_status') if k in row}
            # Keep the node discriminator separate from the original row kind.
            if 'kind' in fields:
                fields['source_kind'] = fields.pop('kind')
            node = add(record, 'syntax_occurrence', row, fields)
            coverage = data.get('scope_coverage', {})
            if (node and scope and row.get('unshadowed_formal_call_candidate')
                    and coverage.get('selected_syntax_scan_complete') is True
                    and coverage.get('header_enumeration_complete') is True
                    and coverage.get('selected_key_count_in_examined_headers') == 1
                    and coverage.get('unsupported_headers') == 0):
                declarations.append((record, node, row, scope))
        window = data.get('source_window')
        if window:
            add(record, 'captured_source_window', window,
                {'text_preview': window.get('text', '')[:256],
                 'text_preview_truncated': len(window.get('text', '')) > 256,
                 'binding_status': 'unresolved_source_only'})
        api = data.get('selected_api')
        if api:
            narrow = (data.get('binding_schema') == 7
                      and data.get('coverage', {}).get('scope_index_complete') is True
                      and not data.get('coverage', {}).get('tree_has_parse_errors')
                      and data.get('callee_origin') == ['module', 'electron', 'contextBridge', 'exposeInMainWorld'])
            exposure = add(record, 'preload_exposure', data['focus'],
                           {'namespace': data.get('namespace'), 'basis': 'original narrow binding slice' if narrow else 'unaccepted binding record',
                            'accepted_narrow_binding': narrow}, 'computed')
            member = add(record, 'selected_preload_api', api,
                         {'name': api['name'], 'accepted_narrow_binding': narrow}, 'computed')
            for call in api.get('ipc_calls', []):
                accepted = narrow and call.get('origin', [])[:3] == ['module', 'electron', 'ipcRenderer']
                call_node = add(record, 'preload_call', call,
                    {'origin': call.get('origin'), 'channel': call.get('channel'),
                     'channel_status': call.get('channel_status'),
                     'accepted_narrow_binding': accepted,
                     'basis': 'preserved original preload slice; no added scope or IPC edge'}, 'computed')
                if member and call_node and accepted:
                    link({'kind': 'relationship', 'classification': 'computed',
                          'from': member['node_id'], 'to': call_node['node_id'],
                          'status': 'preserved_narrow_binding', 'basis_evidence_id': record['id'],
                          'basis': 'Original selected preload API slice contains this checked IPC receiver origin.',
                          'unresolved': ['Runtime reachability/delivery and whole-program receiver integrity unproved.']})
                provenance = call.get('channel_provenance') or {}
                if provenance.get('definition'):
                    definition = add(record, 'channel_literal_definition', provenance['definition'],
                        {'literal_value': provenance.get('value'), 'basis': provenance.get('basis'),
                         'accepted_narrow_binding': accepted}, 'computed')
                    if call_node and definition and accepted:
                        link({'kind': 'relationship', 'classification': 'computed',
                              'from': definition['node_id'], 'to': call_node['node_id'],
                              'status': 'preserved_narrow_binding', 'basis_evidence_id': record['id'],
                              'basis': 'Original checked channel definition/use provenance, retained within the same preload slice.',
                              'unresolved': ['No main-process receiver, cross-component context or delivery is established.']})
            if exposure and member and narrow:
                link({'kind': 'relationship', 'classification': 'computed',
                              'from': exposure['node_id'], 'to': member['node_id'],
                              'status': 'preserved_narrow_binding', 'basis_evidence_id': record['id'],
                              'basis': 'Existing bounded preload exposure/member slice; see original profile.',
                              'unresolved': ['Runtime reachability and whole-program receiver integrity unproved.']})

    for record, node, row, scope in declarations:
        context = contexts[record['data']['component_id']]
        key = (context['component_id'], context['sha256'], record['data']['table_identity'], row['literal_call_argument'])
        target = module_nodes.get(key)
        if target is None or not target['table_key_unique_in_complete_headers']:
            continue
        link({'kind': 'relationship', 'classification': 'computed',
                      'from': node['node_id'], 'to': target['node_id'], 'status': 'candidate_only',
                      'basis': row['candidate_basis']+' Literal token matches a selected header in this same source table.',
                      'formal_origin': row['formal_origin'],
                      'basis_evidence_ids': [record['id'], target['evidence_id']],
                      'unresolved': ['Formal-to-loader binding is not established.',
                                     'Factory/table replacement and effects of omitted modules are unproved.',
                                     'An equal literal key does not establish the loaded object or runtime call.',
                                     'Execution/process context for this source is not established.']})
    # No equality-based IPC, inheritance, main/preload context or interop edges.
    items = nodes + links
    identity = {'schema': SCHEMA, 'snapshot': snapshot, 'root_component': root_component,
                'records': [r['id'] for r in records], 'items': items, 'profiles': profiles}
    expected = digest(identity)
    if (view is not None and view != expected) or (offset and view is None):
        raise ValueError('Stale/missing relationship view; restart with offset=0 and the same evidence ids')
    page, page_bytes = [], 0
    for item in items[offset:offset+limit]:
        size = len(json.dumps(item, ensure_ascii=False).encode('utf-8'))
        if page and page_bytes+size > 7000:
            break
        page.append(item)
        page_bytes += size
    return {'classification': 'computed', 'relationship_schema': SCHEMA,
            'application_snapshot': snapshot, 'component_id': root_component,
            'source_sha256': contexts[root_component]['sha256'], 'view': expected,
            'input_evidence_ids': [record['id'] for record in records],
            'items': page, 'matches': len(items),
            'next_offset': offset+len(page) if offset+len(page) < len(items) else None,
            'page_item_bytes': page_bytes, 'page_item_byte_limit': 7000,
            'input_profiles': profiles, 'coverage': {'input_evidence_records': len(records),
                'source_nodes': len(nodes), 'relationships': len(links), 'omitted': omitted,
                'stopping_reason': stopped or 'end_of_selected_evidence',
                'whole_program_receiver_integrity': False, 'semantic_analysis_complete': False,
                'IPC_edges_established': 0, 'new_indexing': False},
            'limitations': ['Caller-selected evidence only; unrelated components and process contexts are not analyzed.',
                           'Equal channel strings or keys across tables do not establish edges.',
                           'Each candidate retains its source basis and specific missing binding obligations.',
                           'Preserved narrow binding claims retain their original profile and limitations.']}
