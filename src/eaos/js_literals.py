"""Read a deliberately closed literal declaration grammar; never run JavaScript."""
from __future__ import annotations

import re

from .js_syntax import literal, text

UNSAFE = {'__proto__', 'prototype', 'constructor'}


def children(node):
    return [node.named_child(i) for i in range(node.named_child_count)] if node else []


def unwrap(node):
    for _ in range(8):
        if node and node.type == 'parenthesized_expression' and node.named_child_count == 1:
            node = node.named_child(0)
        else:
            return node
    return None


def same(left, right):
    return left is not None and right is not None and (left.start_byte, left.end_byte, left.type) == (right.start_byte, right.end_byte, right.type)


def property_parts(model, node):
    parts = []
    while node and node.type in ('member_expression', 'subscript_expression'):
        field = node.child_by_field_name('property' if node.type == 'member_expression' else 'index')
        prop = text(model.data, field) if node.type == 'member_expression' else literal(model.data, field)
        if prop is None or prop in UNSAFE or len(parts) >= 8:
            return None, None
        parts.append(prop)
        node = node.child_by_field_name('object')
    return node, list(reversed(parts))


def binding_of(model, node):
    return model.binding(text(model.data, node), node) if node and node.type == 'identifier' else None


def no_alias(model, binding):
    for node in model.nodes:
        if node.type == 'variable_declarator':
            value = node.child_by_field_name('value')
            if value and value.type == 'identifier' and binding_of(model, value) == binding:
                return False
    return True


def reference_is_object_escape(model, binding, path, permitted=()):
    """Only supported scalar-property reads may use a tracked object binding.

    Bare references, including shorthand fields inside aggregates, escape. This
    is deliberately conservative instead of following arbitrary object graphs.
    """
    def inside(node, parent):
        return parent.start_byte <= node.start_byte and node.end_byte <= parent.end_byte
    for node in model.nodes:
        if node.type not in ('identifier', 'shorthand_property_identifier'):
            continue
        if model.binding(text(model.data, node), node) != binding:
            continue
        if any(inside(node, span) for span in permitted):
            continue
        declaration_name = False
        for _, declaration in binding[2]:
            name = declaration.child_by_field_name('name') if declaration.type == 'variable_declarator' else declaration
            if name and inside(node, name):
                declaration_name = True
                break
        if declaration_name:
            continue
        chain = node
        while chain.parent and chain.parent.type in ('member_expression', 'subscript_expression') and same(chain.parent.child_by_field_name('object'), chain):
            chain = chain.parent
        root, fields = property_parts(model, chain)
        if fields is None or not fields:
            return True
        if chain.parent and chain.parent.type == 'call_expression' and same(chain.parent.child_by_field_name('function'),chain) and len(fields)-1 < len(path):
            return True  # A method receives the tracked object, not just a scalar value.
        prefix_length = min(len(fields), len(path))
        if fields[:prefix_length] == path[:prefix_length] and len(fields) < len(path):
            return True
    return False


def unconditional_factory_statement(model, call, factory):
    """Accept only a direct top-level expression or comma sequence, in order."""
    node = call
    while node.parent and node.parent.type == 'sequence_expression':
        node = node.parent
    statement = node.parent
    body = factory.child_by_field_name('body')
    if not statement or statement.type != 'expression_statement' or not same(statement.parent, body):
        return False
    for preceding in children(body):
        if same(preceding, statement):
            return True
        if preceding.type not in ('variable_declaration', 'lexical_declaration', 'expression_statement', 'comment'):
            return False
    return False


def enum_object_escapes(model, exports, temp_binding, export_name, initializer):
    for call in model.nodes:
        if call.type != 'call_expression' or same(call, initializer):
            continue
        args = children(call.child_by_field_name('arguments'))
        for argument in args:
            root, path = property_parts(model, argument)
            owner = binding_of(model, root)
            if owner == temp_binding and not path:
                return True
            if owner != exports or path is None or (path and path[0] != export_name):
                continue
            # Permit only the standard independent __esModule data marker. No
            # setters, getters, dynamic descriptors or writes to the enum slot.
            fn = call.child_by_field_name('function')
            marker = len(args) == 3 and text(model.data, fn) == 'Object.defineProperty' and model.binding('Object', fn) is None and literal(model.data, args[1]) == '__esModule'
            descriptor = children(args[2]) if marker and args[2].type == 'object' else []
            marker = marker and len(descriptor) == 1 and descriptor[0].type == 'pair' and text(model.data, descriptor[0].child_by_field_name('key')) == 'value' and text(model.data, descriptor[0].child_by_field_name('value')) in ('true', '!0')
            if not marker:
                return True
    return False


def closed_object(model, node, depth=0):
    if depth > 8 or not node or node.type != 'object':
        return False
    names = set()
    for item in children(node):
        if item.type != 'pair':
            return False
        field = item.child_by_field_name('key')
        name = literal(model.data, field) if field and field.type == 'string' else text(model.data, field)
        if not field or field.type == 'computed_property_name' or name in UNSAFE or name in names:
            return False
        names.add(name)
        value = item.child_by_field_name('value')
        if value is None:
            return False
        if value.type == 'object':
            if not closed_object(model,value,depth+1):
                return False
        elif value.type not in ('number','true','false','null') and literal(model.data,value) is None:
            return False
    return True


def object_field(model, node, name):
    if not closed_object(model,node) or name in UNSAFE:
        return None
    found = []
    names = set()
    for item in children(node):
        if item.type != 'pair':
            return None
        key = item.child_by_field_name('key')
        prop = literal(model.data, key) if key and key.type == 'string' else text(model.data, key)
        if not key or key.type == 'computed_property_name' or prop in UNSAFE or prop in names:
            return None
        names.add(prop)
        if prop == name:
            found.append(item.child_by_field_name('value'))
    return found[0] if len(found) == 1 else None


def closed_enum(model, factory, export_name, property_name):
    """Recognize an unset local || (exports.Name = local = {}) literal enum."""
    if export_name in UNSAFE or property_name in UNSAFE:
        return None
    if any(node.type in ('member_expression','subscript_expression') and text(model.data,node.child_by_field_name('object')) == 'Object' and (text(model.data,node.child_by_field_name('property')) if node.type=='member_expression' else literal(model.data,node.child_by_field_name('index'))) == 'prototype' for node in model.nodes):
        return None
    params = children(factory.child_by_field_name('parameters'))
    if len(params) < 2 or any(p.type != 'identifier' for p in params):
        return None
    if len({text(model.data, p) for p in params}) != len(params):
        return None
    module_parameter = binding_of(model,params[0])
    if module_parameter is None or not model.binding_references_allowed(module_parameter,[]):
        return None  # module.exports aliases the exports parameter in this recipe.
    exports = binding_of(model, params[1])
    if exports is None or not no_alias(model, exports):
        return None
    matches = []
    for call in model.nodes:
        if call.type != 'call_expression' or not same(model.nearest_function(call), factory) or not unconditional_factory_statement(model,call,factory):
            continue
        fn = unwrap(call.child_by_field_name('function'))
        args = children(call.child_by_field_name('arguments'))
        if not fn or fn.type != 'function_expression' or len(args) != 1:
            continue
        if not model.data[fn.start_byte:fn.start_byte+9].startswith(b'function(') and not model.data[fn.start_byte:fn.start_byte+10].startswith(b'function ('):
            continue  # Named/async/generator/decorated forms are unsupported.
        parameters = children(fn.child_by_field_name('parameters'))
        if len(parameters) != 1 or parameters[0].type != 'identifier':
            continue
        arg = unwrap(args[0])
        if not arg or arg.type != 'binary_expression' or text(model.data, arg.child_by_field_name('operator')) != '||':
            continue
        temp = arg.child_by_field_name('left')
        temp_binding = binding_of(model, temp)
        if not temp_binding or len(temp_binding[2]) != 1:
            continue
        temp_value = temp_binding[2][0][0]
        if temp_value[0] != 'variable' or temp_value[1] is not None or not no_alias(model, temp_binding) or temp_binding[2][0][1].end_byte > call.start_byte:
            continue
        assign_export = unwrap(arg.child_by_field_name('right'))
        if not assign_export or assign_export.type != 'assignment_expression':
            continue
        exported = assign_export.child_by_field_name('left')
        root, path = property_parts(model, exported)
        if binding_of(model, root) != exports or path != [export_name]:
            continue
        assign_temp = unwrap(assign_export.child_by_field_name('right'))
        if not assign_temp or assign_temp.type != 'assignment_expression' or binding_of(model, assign_temp.child_by_field_name('left')) != temp_binding:
            continue
        initial = unwrap(assign_temp.child_by_field_name('right'))
        if not initial or initial.type != 'object' or initial.named_child_count:
            continue
        statements = children(fn.child_by_field_name('body'))
        if len(statements) != 1 or statements[0].type != 'expression_statement':
            continue
        pending = [statements[0].named_child(0)]
        definitions = {}
        safe = True
        enum_param = binding_of(model, parameters[0])
        while pending:
            expr = unwrap(pending.pop())
            if not expr or len(definitions) + len(pending) > 256:
                safe = False;break
            if expr.type == 'sequence_expression':
                pending.extend(reversed(children(expr)))
                continue
            if expr.type != 'assignment_expression' or text(model.data, expr.child_by_field_name('operator')) not in (None, '='):
                safe = False;break
            left, right = expr.child_by_field_name('left'), expr.child_by_field_name('right')
            left_root, left_path = property_parts(model, left)
            value = literal(model.data, right)
            if binding_of(model, left_root) != enum_param or len(left_path or []) != 1 or value is None:
                safe = False;break
            name = left_path[0]
            if name in definitions or name in UNSAFE:
                safe = False;break
            definitions[name] = (value, right, expr)
        if not safe or property_name not in definitions:
            continue
        # Refuse writes outside the recognized initializer. Only an earlier
        # `exports.Name = void 0` placeholder is part of this supported grammar.
        for write in model.writes:
            write_root, write_path = property_parts(model, write)
            owner = binding_of(model, write_root)
            if owner == temp_binding and not same(write, assign_temp.child_by_field_name('left')):
                safe = False;break
            if owner != exports:
                continue
            if not write_path:
                safe = False;break
            if write_path[0] != export_name:
                continue
            if same(write, exported):
                continue
            parent = write.parent
            rhs = parent.child_by_field_name('right') if parent and parent.type == 'assignment_expression' else None
            if not (write.start_byte < call.start_byte and rhs and rhs.type == 'unary_expression' and text(model.data, rhs.child_by_field_name('operator')) == 'void' and text(model.data, rhs.child_by_field_name('argument')) == '0'):
                safe = False;break
        if safe and enum_object_escapes(model, exports, temp_binding, export_name, call):
            safe = False
        if safe:
            permitted_exports = [assign_export.child_by_field_name('left')]
            for write in model.writes:
                parent = write.parent
                rhs = parent.child_by_field_name('right') if parent and parent.type == 'assignment_expression' else None
                if write.start_byte < call.start_byte and rhs and rhs.type == 'unary_expression' and text(model.data,rhs.child_by_field_name('operator')) == 'void' and text(model.data,rhs.child_by_field_name('argument')) == '0':
                    permitted_exports.append(write)
            for other in model.nodes:
                if other.type == 'call_expression' and text(model.data,other.child_by_field_name('function')) == 'Object.defineProperty':
                    marker_args = children(other.child_by_field_name('arguments'))
                    if len(marker_args) == 3 and literal(model.data,marker_args[1]) == '__esModule':
                        permitted_exports.append(marker_args[0])
            if reference_is_object_escape(model,exports,[export_name,property_name],permitted_exports) or reference_is_object_escape(model,temp_binding,[property_name],[args[0]]):
                safe = False
        if safe:
            value, definition, assignment = definitions[property_name]
            matches.append({'value':value, 'basis':'computed_closed_enum_literal',
                            'definition':model.loc(definition), 'assignment':model.loc(assignment),
                            'initializer':model.loc(call), 'export_assignment':model.loc(assign_export),
                            'factory':model.loc(factory)})
    return matches[0] if len(matches) == 1 else None


def resolve_string(model, node, seen=()):
    node = unwrap(node)
    if node is None or len(seen) > 8:
        return None
    value = literal(model.data, node)
    if value is not None:
        return {'value':value, 'basis':'literal', 'definition':model.loc(node), 'use':model.loc(node)}
    root, parts = property_parts(model, node)
    binding = binding_of(model, root)
    if not binding or len(binding[2]) != 1 or model.mutated(binding):
        return None
    identity = (binding[0], binding[1])
    if identity in seen:
        return None
    initializer, declaration = binding[2][0]
    if initializer[0] != 'const' or declaration.end_byte > node.start_byte:
        return None
    if parts and reference_is_object_escape(model, binding, parts):
        return None
    expr = initializer[1]
    if not parts:
        result = resolve_string(model, expr, seen+(identity,))
    elif expr is not None and expr.type == 'object':
        for part in parts:
            expr = object_field(model, expr, part)
            if expr is None:
                return None
        result = resolve_string(model, expr, seen+(identity,))
    elif expr is not None and expr.type == 'call_expression' and len(parts) == 2:
        module = model.webpack_factory(expr.child_by_field_name('function'), children(expr.child_by_field_name('arguments')))
        if module is None:
            return None
        factory, dispatch, table = module
        module_arg = children(expr.child_by_field_name('arguments'))[0]
        module_id = text(model.data,module_arg) if module_arg.type == 'number' else literal(model.data,module_arg)
        loader_binding = binding_of(model,expr.child_by_field_name('function'))
        permitted_loader = children(dispatch.child_by_field_name('arguments'))[2:3]
        for reference in model.nodes:
            if reference.type != 'identifier' or binding_of(model,reference) != loader_binding:
                continue
            parent = reference.parent
            if parent and parent.type == 'call_expression' and same(parent.child_by_field_name('function'),reference):
                arguments = children(parent.child_by_field_name('arguments'))
                if len(arguments) != 1:
                    return None
                argument = arguments[0]
                supported = literal(model.data,argument) is not None or (argument.type == 'number' and re.fullmatch(r'0|[1-9][0-9]{0,9}',text(model.data,argument) or ''))
                if not supported:
                    return None
                permitted_loader.append(reference)
        if not model.binding_references_allowed(loader_binding,permitted_loader):
            return None
        possible_aliases = 0
        for other in model.nodes:
            if other.type != 'call_expression' or same(other,expr):
                continue
            arguments = children(other.child_by_field_name('arguments'))
            if len(arguments) != 1:
                continue
            argument = arguments[0]
            identifier = text(model.data,argument) if argument.type == 'number' else literal(model.data,argument)
            other_loader = binding_of(model,other.child_by_field_name('function'))
            if other_loader == loader_binding and argument.type == 'number' and not re.fullmatch(r'0|[1-9][0-9]{0,9}', identifier or ''):
                return None  # Alternate numeric spellings may alias a cache key.
            if identifier != module_id:
                continue
            possible_aliases += 1
            if possible_aliases > 128:
                return None
            other_module = model.webpack_factory(other.child_by_field_name('function'),arguments)
            if other_module is None or not same(other_module[0],factory) or not same(other_module[1],dispatch) or not same(other_module[2],table):
                continue
            declaration = other.parent
            if not declaration or declaration.type != 'variable_declarator' or not same(declaration.child_by_field_name('value'),other):
                return None
            alias = binding_of(model,declaration.child_by_field_name('name'))
            if not alias or len(alias[2]) != 1 or alias[2][0][0][0] != 'const' or model.mutated(alias) or reference_is_object_escape(model,alias,parts):
                return None
        result = closed_enum(model, factory, parts[0], parts[1])
        if result:
            result['module_dispatch'] = model.loc(dispatch)
            result['module_table'] = model.loc(table)
            loader = model.nearest_function(dispatch)
            cache_read = children(loader.child_by_field_name('body'))[0].named_child(0).child_by_field_name('value')
            cache = binding_of(model,cache_read.child_by_field_name('object'))
            result['module_loader'] = model.loc(loader)
            result['module_cache_definition'] = model.loc(cache[2][0][1])
            result['module_identifier'] = module_id
    else:
        return None
    if result:
        result = dict(result, basis=result['basis'] if result['basis']=='computed_closed_enum_literal' else 'computed_const_or_object_literal', use=model.loc(node), binding_definition=model.loc(declaration))
    return result
