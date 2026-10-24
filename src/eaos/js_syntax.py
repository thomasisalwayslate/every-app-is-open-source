"""Original, syntax-only observations from a coherent JavaScript syntax tree.

This module never evaluates JavaScript or resolves identifier/module bindings.
Traversal continuation is a named-child path, used only inside a captured index.
"""
from __future__ import annotations

import re
import bisect
from array import array
import time
from importlib.metadata import version

SCHEMA = 2
SOURCE_LIMIT = 8 * 1024 * 1024
NODE_LIMIT = 100000
RECORD_LIMIT = 20000
DEPTH_LIMIT = 512


def parser_identity():
    return {'engine': 'tree-sitter', 'engine_version': version('tree-sitter'),
            'grammar': 'tree-sitter-javascript',
            'grammar_version': version('tree-sitter-javascript'), 'index_schema': SCHEMA}


def location(node, newlines):
    # Derive positions from original bytes. Do not depend on native Point wrapper
    # lifetimes; only the parser's stable byte spans cross this interface.
    start, end = node.start_byte, node.end_byte
    line, end_line = bisect.bisect_left(newlines, start), bisect.bisect_left(newlines, end)
    return {'start_byte': start, 'end_byte': end,
            'line': line + 1, 'column_byte': start - (newlines[line-1]+1 if line else 0),
            'end_line': end_line + 1,
            'end_column_byte': end - (newlines[end_line-1]+1 if end_line else 0)}


def text(data, node, limit=256):
    if node is None:
        return None
    if node.end_byte - node.start_byte > limit:
        return None
    return data[node.start_byte:node.end_byte].decode('utf-8')


def literal(data, node):
    # Conservative: escape interpretation and interpolation are not guessed.
    value = text(data, node, 1026)
    if node is None or node.has_error or node.type != 'string' or value is None:
        return None
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0] and '\\' not in value:
        return value[1:-1]
    return None


def observation(data, node, newlines):
    if node.has_error:
        return None
    item = None
    if node.type == 'call_expression':
        callee = node.child_by_field_name('function')
        arguments = node.child_by_field_name('arguments')
        first = arguments.named_child(0) if arguments and arguments.named_child_count else None
        name = text(data, callee)
        if callee and callee.type in ('identifier', 'import') and name in ('require', 'import'):
            item = {'kind': 'module_specifier', 'module': literal(data, first),
                    'syntax': name, 'argument_status': 'literal' if literal(data, first) is not None else 'dynamic_or_unsupported'}
        elif callee and callee.type == 'member_expression':
            prop = callee.child_by_field_name('property')
            receiver = callee.child_by_field_name('object')
            method = text(data, prop)
            # Property spelling is a syntax fact, not proof of an Electron API.
            if method in ('on', 'once', 'handle', 'handleOnce', 'send', 'sendSync',
                          'invoke', 'postMessage', 'loadFile', 'loadURL', 'exposeInMainWorld'):
                item = {'kind': 'call_site', 'receiver': text(data, receiver), 'method': method,
                        'literal_argument': literal(data, first),
                        'argument_status': 'literal' if literal(data, first) is not None else 'dynamic_or_unsupported',
                        'callee_location': location(callee, newlines),
                        'argument_location': location(first, newlines) if first else None}
    elif node.type in ('import_statement', 'export_statement'):
        source = node.child_by_field_name('source')
        if source:
            item = {'kind': 'module_specifier', 'module': literal(data, source), 'syntax': node.type}
    elif node.type == 'pair':
        key = node.child_by_field_name('key')
        if text(data, key) == 'preload' or literal(data, key) == 'preload':
            value = node.child_by_field_name('value')
            item = {'kind': 'preload_property', 'literal_argument': literal(data, value),
                    'argument_status': 'literal' if literal(data, value) is not None else 'dynamic_or_unsupported'}
    elif node.type == 'comment':
        raw = text(data, node, 2048)
        match = re.fullmatch(r'//[#@]\s*sourceMappingURL=([^\s]+)\s*', raw or '')
        if match:
            item = {'kind': 'source_map_reference', 'reference': match[1],
                    'availability': 'not_resolved; declaration only'}
    if item is not None:
        return dict(item, classification='fact', **location(node, newlines),
                    relationship='syntax occurrence only; binding, reachability and runtime dispatch unverified')
    return None


def parse_batch(data, previous=None, *, max_nodes=NODE_LIMIT, max_records=RECORD_LIMIT,
                max_seconds=2.0):
    from tree_sitter import Language, Parser
    import tree_sitter_javascript

    if len(data) > SOURCE_LIMIT:
        raise ValueError('JavaScript source exceeds coherent-parse byte budget')
    data.decode('utf-8')  # Byte offsets refer to the original, unmodified UTF-8 bytes.
    language = Language(tree_sitter_javascript.language())
    tree = Parser(language).parse(data)
    newlines = array('I', (match.start() for match in re.finditer(b'\n', data)))
    previous = previous or {'next_path': [], 'nodes_indexed': 0, 'observations': [],
                            'errors': [], 'error_count': 0}
    path = previous['next_path']
    if path is None:
        raise ValueError('Syntax traversal is already complete')
    node, parents = tree.root_node, []
    for index in path:
        if type(index) is not int or not 0 <= index < node.named_child_count:
            raise ValueError('Invalid syntax index continuation; start a new index')
        parents.append(node)
        node = node.named_child(index)
    path = list(path)
    items, errors = list(previous['observations']), list(previous['errors'])
    error_count = previous['error_count']
    visited = 0
    deadline = time.monotonic() + max_seconds
    reason, possible = 'node_budget', True
    while node is not None:
        if visited >= max_nodes:
            reason = 'node_budget'
            break
        if time.monotonic() >= deadline:
            reason = 'time_budget'
            break
        if len(items) >= max_records:
            reason, possible = 'record_budget', False
            break
        if len(path) > DEPTH_LIMIT:
            reason, possible = 'depth_budget', False
            break
        visited += 1
        if node.type == 'ERROR' or node.is_missing:
            error_count += 1
            if len(errors) < 30:
                errors.append(dict(location(node, newlines), reason='missing_syntax' if node.is_missing else 'parse_error'))
        row = observation(data, node, newlines)
        if row:
            items.append(row)
        if node.named_child_count:
            parents.append(node)
            path.append(0)
            node = node.named_child(0)
        else:
            while path:
                index, parent = path.pop(), parents.pop()
                if index + 1 < parent.named_child_count:
                    parents.append(parent)
                    path.append(index + 1)
                    node = parent.named_child(index + 1)
                    break
            else:
                node, path, reason, possible = None, None, 'end_of_syntax_tree', False
    return {'next_path': path, 'nodes_indexed': previous['nodes_indexed'] + visited,
            'batch_nodes': visited, 'observations': items, 'errors': errors,
            'error_count': error_count, 'tree_has_errors': tree.root_node.has_error,
            'grammar_abi': language.abi_version, 'stopping_reason': reason,
            'indexing_possible': possible, 'traversal_complete': path is None}
