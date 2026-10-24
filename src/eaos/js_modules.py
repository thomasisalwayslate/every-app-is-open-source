"""Bounded source facts from one caller-selected object-method module candidate.

A numeric/string table key is not proof of a webpack module or loader. This
operation deliberately exposes syntax and excluded scope, not runtime bindings.
"""
from __future__ import annotations

from array import array
import hashlib
import json
import re
import time

from .js_syntax import SOURCE_LIMIT, location, text, literal, parser_identity

MODULE_SCHEMA = 7
HEADER_LIMIT = 4096
BODY_LIMIT = 25000
FUNCTIONS = {'function_declaration','function_expression','arrow_function',
             'method_definition','generator_function_declaration','generator_function'}


def children(node):
    return [node.named_child(i) for i in range(node.named_child_count)] if node else []


def identifier(data, entry):
    name = entry.child_by_field_name('name') or entry.child_by_field_name('key')
    if name is None or name.type not in ('number','string'):
        return None
    value = literal(data,name) if name.type=='string' else text(data,name,128)
    return value if value is not None and len(value)<=128 else None


def node_key(node):
    return (node.start_byte, node.end_byte, node.type) if node else None


def binding_names(pattern, *, flat_object=False, simple_rest=False):
    """Names only: never infer destructured values, getters or default effects."""
    if pattern is None:
        return []
    if pattern.type in ('identifier', 'shorthand_property_identifier_pattern'):
        return [pattern]
    if simple_rest and pattern.type == 'rest_pattern' and pattern.named_child_count == 1:
        child = pattern.named_child(0)
        return [child] if child.type == 'identifier' else None
    if flat_object and pattern.type == 'object_pattern' and pattern.named_child_count <= 64:
        names = []
        for item in children(pattern):
            if item.type == 'comment':
                continue
            if item.type == 'shorthand_property_identifier_pattern':
                names.append(item)
            elif item.type == 'pair_pattern':
                prop = item.child_by_field_name('key')
                value = item.child_by_field_name('value')
                if (prop is None or prop.type not in ('property_identifier', 'string', 'number')
                        or value is None or value.type != 'identifier'):
                    return None
                names.append(value)
            else:
                return None
        return names
    return None


class FormalOwnership:
    """Lexical ownership only within the already bounded syntax traversal.

    No value propagation, module resolution or omitted-scope mutation claims.
    Unsupported patterns/eval/arguments remain independent refusal conditions.
    """
    SCOPE_NODES = FUNCTIONS | {'program', 'statement_block', 'catch_clause',
                               'for_statement', 'for_in_statement', 'switch_body',
                               'class', 'class_declaration', 'class_body'}

    def __init__(self, data, selected):
        self.data, self.selected = data, node_key(selected)
        self.scopes, self.at, self.writes, self.gaps = {}, {}, [], set()
        self.written = None

    def declare(self, scope, name, kind, node):
        if scope is not None and name is not None and name.type in ('identifier', 'shorthand_property_identifier_pattern'):
            spelling = text(self.data, name)
            if spelling:
                self.scopes[scope]['bindings'].setdefault(spelling, []).append((kind, node))

    def function_scope(self, scope):
        while scope is not None:
            if self.scopes[scope]['node'].type in FUNCTIONS | {'program'}:
                return scope
            scope = self.scopes[scope]['parent']
        return None

    def visit(self, node, scope):
        name = node.child_by_field_name('name')
        if node.type in ('function_declaration', 'class_declaration'):
            self.declare(scope, name, 'declaration', node)
            if node.type == 'function_declaration' and self.function_scope(scope) == self.selected:
                body = self.scopes[self.selected]['node'].child_by_field_name('body')
                if self.scopes[scope]['node'] != body:
                    self.gaps.add('block_function_hoisting_uncertainty')
        if node.type in self.SCOPE_NODES:
            parent = scope
            scope = node_key(node)
            self.scopes[scope] = {'parent': parent, 'node': node, 'bindings': {}}
            if node.type in FUNCTIONS:
                parameters = children(node.child_by_field_name('parameters'))
                single = node.child_by_field_name('parameter')
                if single is not None:
                    parameters.append(single)
                for parameter in parameters:
                    names = binding_names(parameter, simple_rest=True)
                    if names is None:
                        self.gaps.add('unsupported_parameter_pattern')
                    else:
                        kind = 'rest_parameter' if parameter.type == 'rest_pattern' else 'parameter'
                        for bound in names:
                            self.declare(scope, bound, kind, bound)
                if node.type != 'function_declaration':
                    self.declare(scope, name, 'self_name', node)
            elif node.type == 'catch_clause':
                parameter = node.child_by_field_name('parameter')
                self.declare(scope, parameter, 'catch', parameter)
            elif node.type == 'class':
                self.declare(scope, name, 'self_name', node)
        self.at[node_key(node)] = scope
        if node.type == 'variable_declarator':
            owner = scope
            if node.parent and node.parent.type == 'variable_declaration':
                owner = self.function_scope(owner)
            names = binding_names(name, flat_object=True)
            if names is None:
                self.gaps.add('unsupported_declaration_pattern')
            else:
                for declared in names:
                    self.declare(owner, declared, 'variable', node)
        if node.type in ('assignment_expression', 'augmented_assignment_expression', 'update_expression'):
            target = node.child_by_field_name('left') or node.child_by_field_name('argument')
            if target is not None and target.type == 'identifier':
                self.writes.append(target)
        if node.type == 'for_in_statement':
            target = node.child_by_field_name('left')
            if target is not None and target.type == 'identifier':
                kind = text(self.data, node.child_by_field_name('kind'))
                if kind in ('let', 'const', 'var'):
                    owner = self.function_scope(scope) if kind == 'var' else scope
                    self.declare(owner, target, 'loop_variable', target)
                else:
                    self.writes.append(target)
        return scope

    def binding(self, reference):
        if reference is None or reference.type != 'identifier':
            return None
        name = text(self.data, reference)
        scope = self.at.get(node_key(reference))
        while scope is not None:
            if name in self.scopes[scope]['bindings']:
                return scope, name
            scope = self.scopes[scope]['parent']
        return None

    def selected_formal(self, reference):
        if self.written is None:
            return None
        owner = self.binding(reference)
        if owner is None or owner[0] != self.selected:
            return None
        declarations = self.scopes[owner[0]]['bindings'][owner[1]]
        if len(declarations) != 1 or declarations[0][0] != 'parameter':
            return None
        if owner in self.written:
            return None
        return declarations[0][1]

    def prepare_writes(self, deadline):
        written = set()
        for reference in self.writes:
            if time.monotonic() >= deadline:
                return False
            owner = self.binding(reference)
            if owner is not None:
                written.add(owner)
        self.written = written
        return time.monotonic() < deadline


def inspect_module(data, focus_byte, *, module_id=None, kind='declarations',
                   find='', offset=0, limit=30, view=None,
                   max_nodes=BODY_LIMIT, max_seconds=2.0, header_limit=HEADER_LIMIT, namespace_context=None):
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    if len(data)>SOURCE_LIMIT or not 0<=focus_byte<len(data):
        raise ValueError('Module focus outside coherent source budget')
    data.decode('utf-8')
    tree=Parser(Language(tree_sitter_javascript.language())).parse(data)
    node=tree.root_node.named_descendant_for_byte_range(focus_byte,focus_byte+1)
    candidates=[]
    for _ in range(256):
        if node is None:break
        if node.type=='method_definition' and node.parent and node.parent.type=='object' and identifier(data,node) is not None:
            candidates.append(node)
        node=node.parent
    if not candidates:
        raise ValueError('No enclosing literal table-method candidate; use an observed call start_byte or a bounded source window')
    seed=candidates[-1]
    table=seed.parent
    newline_offsets=array('I',(m.start() for m in re.finditer(b'\n',data)))
    loc=lambda n:location(n,newline_offsets)
    deadline=time.monotonic()+max_seconds
    headers=[];examined=0;unsupported=0;matches=[]
    for i in range(min(table.named_child_count,header_limit)):
        if time.monotonic()>=deadline:break
        entry=table.named_child(i);examined+=1
        value=identifier(data,entry)
        if value is None or entry.type!='method_definition':
            unsupported+=1;continue
        headers.append({'id':value,**loc(entry)})
        if module_id is not None and value==module_id:matches.append(entry)
    headers_complete=examined==table.named_child_count
    if module_id is not None:
        if len(matches)>1:
            raise ValueError('Duplicate table keys make module selection ambiguous; inspect source windows without assuming overwrite semantics')
        if not matches:
            raise ValueError('Module id not present in examined headers; header coverage may be incomplete. Use syntax index continuation and an observed source-byte focus')
        selected=matches[0]
    else:selected=seed
    parameters_node=selected.child_by_field_name('parameters')
    parameter_count=parameters_node.named_child_count if parameters_node else 0
    parameters=[parameters_node.named_child(i) for i in range(min(8,parameter_count))]
    selected_id=identifier(data,selected)
    ancestor_scope=table.parent
    while ancestor_scope and ancestor_scope.type not in FUNCTIONS | {'program'}:
        ancestor_scope=ancestor_scope.parent
    # Keep the coherent source tree and original offsets. A skeleton walks only
    # the nearest enclosing function/program, excluding the entire factory table.
    # It is not a partial Slice: none of the complete binding guarantees of that
    # class apply to these observations.
    ancestors=kind=='ancestors'
    scan_root=ancestor_scope if ancestors else selected
    if scan_root is None:
        raise ValueError('No bounded ancestor syntax scope')
    rows=[];nodes=0;pending=[(scan_root,0,None)];reason='end_of_scope';omissions=[]
    dynamic_scope=False;candidate_gaps=set();ownership=FormalOwnership(data,selected);candidate_references=[]
    while pending:
        if nodes>=max_nodes:reason='node_budget';break
        if time.monotonic()>=deadline:reason='time_budget';break
        current,depth,parent_scope=pending.pop()
        if ancestors and current==table:
            omissions.append({'reason':'module_table_bodies_excluded',
                              'entries_available':table.named_child_count,**loc(table)})
            continue
        if depth>256:reason='depth_budget';break
        nodes+=1
        scope=ownership.visit(current,parent_scope)
        node_kind=None if current.has_error else current.type
        if node_kind in ('assignment_expression','augmented_assignment_expression','update_expression'):
            target=current.child_by_field_name('left') or current.child_by_field_name('argument')
            if target and target.type not in ('identifier','member_expression','subscript_expression'):
                candidate_gaps.add('unsupported_assignment_target')
        if node_kind=='for_in_statement':
            target=current.child_by_field_name('left')
            if target and target.type not in ('identifier','lexical_declaration','variable_declaration','member_expression','subscript_expression'):
                candidate_gaps.add('unsupported_loop_target')
        if node_kind=='identifier' and text(data,current)=='arguments':
            candidate_gaps.add('implicit_arguments_alias_uncertainty')
        if node_kind=='identifier' and text(data,current)=='eval':
            candidate_gaps.add('eval_reference_scope_uncertainty')
        if node_kind=='computed_property_name':
            candidate_gaps.add('computed_name_evaluation_scope_uncertainty')
        if node_kind=='with_statement' or (node_kind=='call_expression' and text(data,current.child_by_field_name('function'))=='eval'):
            dynamic_scope=True
        if node_kind=='catch_clause':
            parameter=current.child_by_field_name('parameter')
            if parameter and parameter.type!='identifier':candidate_gaps.add('unsupported_catch_pattern')
        if node_kind=='variable_declarator':
            name=current.child_by_field_name('name');value=current.child_by_field_name('value')
            if binding_names(name,flat_object=True) is None:candidate_gaps.add('unsupported_declaration_pattern')
            if name and name.type=='identifier':
                row={'kind':'declarations','source_name':text(data,name),'initializer_type':value.type if value else None,
                     'initializer_source':text(data,value,256),
                     'initializer_source_omitted':bool(value and value.end_byte-value.start_byte>256),**loc(current)}
                if value and value.type=='call_expression':
                    args=children(value.child_by_field_name('arguments'))
                    callee=value.child_by_field_name('function')
                    row['callee_source']=text(data,callee,128)
                    candidate_references.append((row,callee))
                    if len(args)==1:
                        arg=literal(data,args[0]) if args[0].type=='string' else text(data,args[0],128) if args[0].type=='number' else None
                        if arg is not None:row['literal_call_argument']=arg
                    parent=current.parent
                    while parent and parent.type not in FUNCTIONS:parent=parent.parent
                    row['initializer_in_selected_function']=parent==selected
                    row['relationship']='initializer syntax only; loader and alias bindings unresolved'
                rows.append(row)
        elif node_kind in FUNCTIONS and current!=scan_root:
            name=current.child_by_field_name('name')
            params=current.child_by_field_name('parameters')
            count=params.named_child_count if params else 0
            for p in children(params):
                if binding_names(p,simple_rest=True) is None:candidate_gaps.add('unsupported_parameter_pattern')
            rows.append({'kind':'functions','source_name':text(data,name),'function_kind':current.type,
                         'parameters':[text(data,params.named_child(i),128) for i in range(min(8,count))],
                         'parameters_truncated':count>8,**loc(current)})
        elif node_kind in ('class_declaration','class'):
            name=current.child_by_field_name('name')
            heritage=next((c for c in children(current) if c.type=='class_heritage'),None)
            rows.append({'kind':'functions','source_name':text(data,name),'function_kind':current.type,
                         'heritage_source':text(data,heritage,128),'relationship':'class syntax; inheritance and instance identity unresolved',**loc(current)})
        elif node_kind=='assignment_expression':
            left=current.child_by_field_name('left');right=current.child_by_field_name('right')
            if left and left.type=='member_expression':
                rows.append({'kind':'assignments','target_source':text(data,left,128),
                             'source_name':text(data,left.child_by_field_name('property'),128),
                             'value_type':right.type if right else None,'value_source':text(data,right,256),
                             'value_source_omitted':bool(right and right.end_byte-right.start_byte>256),
                             'relationship':'property assignment syntax, not an established module export',**loc(current)})
        elif node_kind=='call_expression':
            fn=current.child_by_field_name('function');args=current.child_by_field_name('arguments')
            receiver=fn.child_by_field_name('object') if fn and fn.type=='member_expression' else None
            prop=fn.child_by_field_name('property') if fn and fn.type=='member_expression' else None
            rows.append({'kind':'calls','source_name':text(data,prop) if prop else text(data,fn,128),
                         'callee_source':text(data,fn,128),'receiver_source':text(data,receiver,128),
                         'argument_sources':[text(data,args.named_child(i),128) for i in range(min(3,args.named_child_count))] if args else [],
                         'argument_count':args.named_child_count if args else 0,
                         'arguments_truncated':bool(args and args.named_child_count>3),
                         'argument_preview_omitted':[i for i in range(min(3,args.named_child_count)) if args.named_child(i).end_byte-args.named_child(i).start_byte>128] if args else [],
                         'callee_source_omitted':bool(fn and fn.end_byte-fn.start_byte>128),
                         'relationship':'call syntax only; dispatch and receiver binding unresolved',**loc(current)})
        for i in range(current.named_child_count-1,-1,-1):
            pending.append((current.named_child(i),depth+1,scope))
            if len(pending)>max_nodes:
                reason='pending_node_budget';break
        if reason=='pending_node_budget':break
    complete=not pending and reason=='end_of_scope'
    candidate_gaps.update(ownership.gaps)
    ownership_ready=bool(complete and not ancestors and ownership.prepare_writes(deadline))
    if complete and not ancestors and not ownership_ready:candidate_gaps.add('formal_ownership_time_budget')
    if parameter_count>8:candidate_gaps.add('selected_parameter_preview_incomplete')
    if any(binding_names(p,simple_rest=True) is None for p in parameters):candidate_gaps.add('unsupported_selected_parameter_pattern')
    for row,reference in candidate_references:
        if 'literal_call_argument' in row:
            if time.monotonic()>=deadline:
                candidate_gaps.add('formal_ownership_time_budget');ownership_ready=False
            formal=ownership.selected_formal(reference) if ownership_ready else None
            row['unshadowed_formal_call_candidate']=bool(not ancestors and complete and not selected.has_error
                and not dynamic_scope and not candidate_gaps and row.get('initializer_in_selected_function')
                and formal is not None)
            if row['unshadowed_formal_call_candidate']:
                row['formal_origin']={'classification':'computed','parameter':loc(formal),'function':loc(selected),'reference':loc(reference)}
            row['candidate_basis']=('literal initializer call lexically owned by the selected function formal, with no writes to that binding in the complete bounded body; loader identity, object mutations and excluded bodies remain unproved'
                if row['unshadowed_formal_call_candidate'] else 'Formal-call candidate refused: local identity/write assumptions not established')
    if not ownership_ready:
        for row,reference in candidate_references:
            if 'unshadowed_formal_call_candidate' in row:
                row['unshadowed_formal_call_candidate']=False
                row.pop('formal_origin',None)
                row['candidate_basis']='Formal-call candidate refused: local identity/write assumptions not established'
    filtered=[]
    for row in rows:
        if not ancestors and row['kind']!=kind:continue
        values=[row.get(k) for k in ('source_name','initializer_source','callee_source','receiver_source','target_source','value_source','heritage_source')]
        values += row.get('argument_sources',[])
        if not find or any(find.casefold() in value.casefold() for value in values if isinstance(value,str)):
            filtered.append(dict(row,classification='fact',binding_status='unresolved_syntax_only'))
    context={'source_sha256':hashlib.sha256(data).hexdigest(),'parser':parser_identity(),
             'module_schema':MODULE_SCHEMA,'namespace_context':namespace_context or {},'seed_focus_byte':focus_byte,
             'table_span':loc(table),'selected_module_span':loc(selected),'selected_id':selected_id,
             'inspection_scope':loc(scan_root),'scope_kind':'ancestor_skeleton' if ancestors else 'selected_body'}
    canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    # Include the actual bounded facts, so a time cutoff cannot silently change a
    # paginated view. A changed cutoff rejects rather than repeating/skipping rows.
    expected=hashlib.sha256(canonical({'context':context,'kind':kind,'find':find,'rows':filtered})).hexdigest()
    if (view is not None and view!=expected) or (offset and view is None):
        raise ValueError('Stale/missing selected-module view; request offset=0. Paging never selects additional module bodies')
    return {'classification':'computed','module_view_identity':hashlib.sha256(canonical(context)).hexdigest(),
            'module_schema':MODULE_SCHEMA,'module_scope':{'candidate_id':selected_id,**loc(selected),
                'role':'literal table-method candidate; webpack registration and runtime entry not established',
                'parameters':[text(data,p,128) for p in parameters[:8]],'parameters_truncated':parameter_count>8,
                'seed_focus_byte':focus_byte,'module_id_supplied':module_id},
            'table_scope':loc(table),
            'table_identity':hashlib.sha256(canonical({k:context[k] for k in ('source_sha256','namespace_context','table_span')})).hexdigest(),
            'view':expected,'items':filtered[offset:offset+limit],'matches':len(filtered),
            'match_scope':('ancestor skeleton syntax prefix' if ancestors else 'selected candidate syntax prefix')+' only; not semantic exports/functions/call coverage',
            'next_offset':offset+limit if offset+limit<len(filtered) else None,
            'scope_coverage':{'selected_named_nodes_examined':0 if ancestors else nodes,'selected_named_nodes_available':None,
                'selected_syntax_scan_complete':None if ancestors else complete,'stopping_reason':reason,
                'ancestor_named_nodes_examined':nodes if ancestors else 0,
                'ancestor_syntax_scan_complete':complete if ancestors else None,
                'inspection_scope':loc(scan_root),'scope_kind':'ancestor_skeleton' if ancestors else 'selected_body',
                'omitted_scopes':omissions,
                'header_entries_examined':examined,'header_entries_available':table.named_child_count,
                'header_enumeration_complete':headers_complete,'unsupported_headers':unsupported,
                'selected_key_count_in_examined_headers':sum(h['id']==selected_id for h in headers),
                'unselected_bodies_examined':0,'ancestor_bindings_indexed':False,
                'dynamic_scope_syntax':dynamic_scope,
                'formal_candidate_gaps':sorted(candidate_gaps),
                'formal_ownership_analysis_complete':ownership_ready and not candidate_gaps,
                'global_parse_errors':tree.root_node.has_error,'selected_parse_errors':selected.has_error,
                'whole_program_receiver_integrity':False,'semantic_analysis_complete':False},
            'module_header_preview':headers[:8],'module_header_preview_truncated':len(headers)>8 or not headers_complete,
            'limitations':['No JavaScript or application execution.',
                'Names, assignments and literal call arguments are source facts; they do not establish module, network or IPC roles.',
                ('Only the nearest enclosing function/program skeleton is scanned; the complete module table is omitted.' if ancestors else
                 'Only the explicitly selected candidate body is scanned. Other bodies and ancestor binding effects are excluded.'),
                'Partial body scans do not automatically continue; use source windows or the separate explicit syntax index to locate further facts.',
                'No mutation, constructor, inheritance, wrapper forwarding or runtime context proof is implied.']}
