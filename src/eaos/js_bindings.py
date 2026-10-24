"""A bounded, original static binding slice for one exposed preload API.

No evaluation or general symbolic execution. Lexical bindings, a supported
webpack dispatcher shape and simple external factories are checked explicitly.
Unrecognized loaders, mutation, shadowing and dynamic channels stay unresolved.
"""
from __future__ import annotations
from array import array
import re
import time
from .js_syntax import SOURCE_LIMIT, literal, location, text
BINDING_SCHEMA = 7
FUNCTIONS = {'function_declaration', 'function_expression', 'arrow_function', 'generator_function', 'generator_function_declaration', 'method_definition'}
SCOPES = FUNCTIONS | {'program', 'statement_block', 'catch_clause', 'for_statement', 'for_in_statement', 'switch_body', 'class_body'}
MAX_NODES = 30000
MODELED_RECEIVER_CALLS = {('module', 'electron', 'contextBridge', 'exposeInMainWorld')} | {
    ('module', 'electron', 'ipcRenderer', method) for method in
    ('send', 'sendSync', 'invoke', 'postMessage', 'on', 'once', 'off', 'removeListener', 'removeAllListeners')}

def key(node):
    return (node.start_byte, node.end_byte, node.type) if node else None

def children(node):
    if node is None:
        return []
    return [node.named_child(n) for n in range(node.named_child_count)]

class Slice:

    def __init__(self, data, *, max_nodes=MAX_NODES, seconds=2.0):
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        self.data = data
        if len(data) > SOURCE_LIMIT:
            raise ValueError('Binding source exceeds coherent source budget')
        data.decode('utf-8')
        self.tree = Parser(Language(tree_sitter_javascript.language())).parse(data)
        self.newlines = array('I', (m.start() for m in re.finditer(b'\n', data)))
        self.nodes, self.scope_at, self.scopes, self.writes = ([], {}, {}, [])
        self.reasons = set()
        self.trace = []
        self.ignore_mutations = False
        self.complete = True
        self.dynamic_scope = False
        todo = [(self.tree.root_node, None, 0)]
        deadline = time.monotonic() + seconds
        while todo:
            if len(self.nodes) >= max_nodes or time.monotonic() >= deadline:
                self.complete = False
                self.reasons.add('binding_node_or_time_budget; no bindings accepted from incomplete scope')
                break
            node, scope, depth = todo.pop()
            if depth > 256:
                self.complete = False
                self.reasons.add('binding_depth_budget')
                break
            if node.type == 'function_declaration':
                name = node.child_by_field_name('name')
                if name:
                    self.declare(scope, text(data, name), ('function', node), name)
            if node.type in SCOPES:
                parent = scope
                scope = key(node)
                self.scopes[scope] = {'parent': parent, 'node': node, 'bindings': {}}
                if node.type in FUNCTIONS:
                    params = node.child_by_field_name('parameters')
                    if params:
                        for p in children(params):
                            self.pattern(scope, p, ('parameter', node), p)
                    param = node.child_by_field_name('parameter')
                    if param:
                        self.pattern(scope, param, ('parameter', node), param)
                    if node.type != 'function_declaration':
                        name = node.child_by_field_name('name')
                        if name:
                            self.declare(scope, text(data, name), ('unsupported', node), name)
                if node.type == 'catch_clause':
                    param = node.child_by_field_name('parameter')
                    if param:
                        self.pattern(scope, param, ('unsupported', param), param)
            self.scope_at[key(node)] = scope
            self.nodes.append(node)
            if node.type == 'import_statement':
                module = literal(data, node.child_by_field_name('source'))
                clause = next((c for c in children(node) if c.type == 'import_clause'), None)
                for entry in children(clause):
                    if entry.type == 'identifier':
                        self.declare(scope, text(data, entry), ('unsupported', entry), entry)
                    elif entry.type == 'namespace_import':
                        local = entry.named_child(entry.named_child_count - 1)
                        self.declare(scope, text(data, local), ('import', module), local)
                    elif entry.type == 'named_imports':
                        for spec in children(entry):
                            remote = spec.child_by_field_name('name')
                            local = spec.child_by_field_name('alias') or remote
                            prop = text(data, remote)
                            value = ('import', module, prop) if module and prop != 'default' else ('unsupported', spec)
                            self.declare(scope, text(data, local), value, local)
            if node.type == 'variable_declarator':
                name, value = (node.child_by_field_name('name'), node.child_by_field_name('value'))
                declaration = node.parent
                constant = text(data, declaration.child_by_field_name('kind')) == 'const' if declaration else False
                # Grammar lexical kind may also appear as an anonymous token.
                constant = constant or bool(declaration and data[declaration.start_byte:node.start_byte].lstrip().startswith(b'const '))
                target_scope = scope
                if declaration and declaration.type == 'variable_declaration':
                    while target_scope and self.scopes[target_scope]['node'].type not in FUNCTIONS | {'program'}:
                        target_scope = self.scopes[target_scope]['parent']
                self.pattern(target_scope, name, ('const' if constant else 'variable', value), node)
            if node.type in ('assignment_expression', 'augmented_assignment_expression', 'update_expression'):
                left = node.child_by_field_name('left') or node.child_by_field_name('argument')
                if left:
                    self.writes.append(left)
            if node.type == 'unary_expression' and text(data, node.child_by_field_name('operator')) == 'delete':
                argument = node.child_by_field_name('argument')
                if argument:
                    self.writes.append(argument)
            if node.type == 'with_statement' or (node.type == 'call_expression' and text(data, node.child_by_field_name('function')) == 'eval'):
                self.dynamic_scope = True
            # Bound the pending child stack as well as the visited node count.
            for n in range(node.named_child_count - 1, -1, -1):
                todo.append((node.named_child(n), scope, depth + 1))
                if len(todo) > max_nodes:
                    self.complete = False
                    self.reasons.add('binding_pending_node_budget')
                    break
            if not self.complete:
                break

    def declare(self, scope, name, value, node):
        if scope and name:
            self.scopes[scope]['bindings'].setdefault(name, []).append((value, node))

    def pattern(self, scope, node, value, declaration):
        if node is None:
            return
        if node.type in ('identifier', 'shorthand_property_identifier_pattern'):
            self.declare(scope, text(self.data, node), value, declaration)
        elif node.type == 'object_pattern':
            for child in children(node):
                if child.type == 'shorthand_property_identifier_pattern':
                    name = text(self.data, child)
                    self.declare(scope, name, ('property', value, name), declaration)
                elif child.type == 'pair_pattern':
                    prop = child.child_by_field_name('key')
                    target = child.child_by_field_name('value')
                    name = text(self.data, prop)
                    if target and target.type == 'identifier' and name:
                        self.declare(scope, text(self.data, target), ('property', value, name), declaration)
                    else:
                        self.pattern(scope, target, ('unsupported', target), declaration)
                else:
                    self.pattern(scope, child, ('unsupported', child), declaration)
        else:
            # Unsupported patterns still register lexical shadows.
            for child in children(node):
                self.pattern(scope, child, ('unsupported', child), declaration)

    def binding(self, name, at):
        scope = self.scope_at.get(key(at))
        # Stable source spans also identify newly returned child wrappers.
        parent = at
        while scope is None and parent:
            parent = parent.parent
            scope = self.scope_at.get(key(parent))
        while scope:
            found = self.scopes[scope]['bindings'].get(name)
            if found:
                return (scope, name, found)
            scope = self.scopes[scope]['parent']
        return None

    def note(self, reason):
        self.reasons.add(reason)
        return None

    def loc(self, node):
        return location(node, self.newlines)

    def root_identifier(self, node):
        while node and node.type in ('member_expression', 'subscript_expression'):
            node = node.child_by_field_name('object')
        return node if node and node.type == 'identifier' else None

    def mutated(self, binding):
        for node in self.writes:
            root = self.root_identifier(node)
            if root and self.binding(text(self.data, root), root) == binding:
                return True
        return False

    def resolve_value(self, value, at, seen):
        kind = value[0]
        if kind == 'property':
            origin = self.resolve_value(value[1], at, seen)
            return origin + (value[2],) if origin else None
        if kind == 'const':
            return self.resolve(value[1], seen)
        if kind == 'import' and value[1]:
            return ('module',) + value[1:]
        return self.note('mutable_or_unsupported_binding')

    def resolve(self, node, seen=()):
        if node is None or len(seen) > 16:
            return self.note('binding_resolution_budget')
        if node.has_error:
            return self.note('parse_error_in_binding_expression')
        if node.type == 'parenthesized_expression' and node.named_child_count == 1:
            return self.resolve(node.named_child(0), seen)
        if node.type == 'identifier':
            name = text(self.data, node)
            binding = self.binding(name, node)
            if binding is None:
                return self.note('unbound_identifier:' + str(name))
            scope, name, decls = binding
            identity = (scope, name)
            if identity in seen:
                return self.note('cyclic_binding')
            if len(decls) != 1 or (not self.ignore_mutations and self.mutated(binding)):
                return self.note('ambiguous_or_mutated_binding:' + name)
            value, definition = decls[0]
            if definition.end_byte > node.start_byte and value[0] not in ('function', 'parameter', 'import'):
                return self.note('binding_before_initialization:' + name)
            result = self.resolve_value(value, node, seen + (identity,))
            if result and len(self.trace) < 16:
                self.trace.append({'binding': name, 'definition': self.loc(definition), 'origin': list(result)})
            return result
        if node.type == 'member_expression':
            base = self.resolve(node.child_by_field_name('object'), seen)
            prop = text(self.data, node.child_by_field_name('property'))
            return base + (prop,) if base and prop else None
        if node.type == 'subscript_expression':
            base = self.resolve(node.child_by_field_name('object'), seen)
            prop = literal(self.data, node.child_by_field_name('index'))
            return base + (prop,) if base and prop is not None else self.note('dynamic_property')
        if node.type == 'call_expression':
            fn = node.child_by_field_name('function')
            args = children(node.child_by_field_name('arguments'))
            if text(self.data, fn) == 'require' and self.binding('require', fn) is None and (len(args) == 1) and self.free_require_safe():
                module = literal(self.data, args[0])
                return ('module', module) if module else self.note('dynamic_require')
            module = self.webpack_external(fn, args, seen)
            if module:
                return ('module', module)
            return self.note('unsupported_call_origin')
        return self.note('unsupported_binding_expression:' + node.type)

    def nearest_function(self, node):
        parent = node.parent
        while parent and parent.type not in FUNCTIONS:
            parent = parent.parent
        return parent

    def free_require_safe(self):
        return not any((text(self.data, self.root_identifier(w)) == 'require' and self.binding('require', self.root_identifier(w)) is None for w in self.writes))

    def contains_module_origin(self, expression, origin):
        """Bounded conservative escape check, including local aggregate aliases."""
        pending = [expression]
        seen = set()
        while pending:
            node = pending.pop()
            if node is None or key(node) in seen:
                continue
            seen.add(key(node))
            if len(seen) > 1000:
                return True  # Cannot rule out an escape within this bounded slice.
            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                target = self.resolve(callee)
                if target in MODELED_RECEIVER_CALLS:
                    # Referring to the module as a modeled call receiver does
                    # not pass that receiver to the callback's external owner.
                    pending.extend(children(node.child_by_field_name('arguments')))
                    continue
            if node.type in ('identifier', 'member_expression', 'subscript_expression', 'call_expression'):
                found = self.resolve(node)
                if found and found[:2] == origin[:2]:
                    return True
            if node.type == 'identifier':
                binding = self.binding(text(self.data, node), node)
                if binding and len(binding[2]) == 1:
                    value = binding[2][0][0]
                    if value[0] in ('const', 'variable') and value[1] is not None:
                        pending.append(value[1])
            pending.extend(children(node))
        return False

    def tainted_module(self, origin):
        if not origin or origin[:1] != ('module',):
            return False
        saved_trace, saved_reasons = (list(self.trace), set(self.reasons))
        self.ignore_mutations = True
        try:
            for write in self.writes:
                if write.type not in ('member_expression', 'subscript_expression'):
                    continue
                root = self.root_identifier(write)
                if root:
                    found = self.resolve(root)
                    if found and found[:2] == origin[:2]:
                        return True
            for call in self.nodes:
                if call.type != 'call_expression':
                    continue
                fn = call.child_by_field_name('function')
                target = self.resolve(fn)
                modeled = target in MODELED_RECEIVER_CALLS if target else False
                dispatches = [step['webpack_dispatch'] for step in self.trace if 'webpack_dispatch' in step]
                if any(item['start_byte'] == call.start_byte and item['end_byte'] == call.end_byte for item in dispatches):
                    modeled = True  # The checked loader recipe explicitly models this invocation.
                if target and target[:2] == origin[:2] and not modeled:
                    return True
                if not modeled:
                    receiver = fn.child_by_field_name('object') if fn and fn.type in ('member_expression', 'subscript_expression') else None
                    if receiver and self.contains_module_origin(receiver, origin):
                        return True
                    for argument in children(call.child_by_field_name('arguments')):
                        if self.contains_module_origin(argument, origin):
                            return True
            return False
        finally:
            self.ignore_mutations = False
            self.trace = saved_trace
            self.reasons = saved_reasons

    def binding_references_allowed(self, binding, permitted):
        """Refuse hidden aggregates/aliases of checked loader state."""
        for node in self.nodes:
            if node.type not in ('identifier', 'shorthand_property_identifier') or self.binding(text(self.data,node),node) != binding:
                continue
            declarations = [entry[1] for entry in binding[2]]
            names = [decl.child_by_field_name('name') if decl.type in ('variable_declarator','function_declaration') else decl for decl in declarations]
            spans = permitted + [name for name in names if name is not None]
            if not any(span.start_byte <= node.start_byte and node.end_byte <= span.end_byte for span in spans):
                return False
        return True

    def dispatcher_return_shape(self, dispatcher, dispatch, module, module_init, parameter):
        """Recognize one narrow cached-module recipe, not arbitrary call similarity."""
        body = dispatcher.child_by_field_name('body')
        statements = children(body)
        if len(statements) != 4:
            return False
        cached, guard, fresh, ret = statements
        if cached.type != 'variable_declaration' or fresh.type != 'variable_declaration' or guard.type != 'if_statement' or (ret.type != 'return_statement'):
            return False
        if cached.named_child_count != 1 or fresh.named_child_count != 1:
            return False
        declaration = cached.named_child(0)
        cached_name = declaration.child_by_field_name('name')
        cached_init = declaration.child_by_field_name('value')
        if not cached_name or cached_name.type != 'identifier' or (not cached_init) or (cached_init.type != 'subscript_expression'):
            return False
        index = cached_init.child_by_field_name('index')
        if text(self.data, index) != text(self.data, parameter):
            return False
        cache = cached_init.child_by_field_name('object')
        cache_binding = self.binding(text(self.data, cache), cache)
        if not cache_binding or len(cache_binding[2]) != 1:
            return False
        cache_value = cache_binding[2][0][0][1]
        if cache_value is None or cache_value.type != 'object' or cache_value.named_child_count:
            return False
        if any((n.type == 'variable_declarator' and n.child_by_field_name('value') is not None and (n.child_by_field_name('value').type == 'identifier') and (self.binding(text(self.data, n.child_by_field_name('value')), n.child_by_field_name('value')) == cache_binding) for n in self.nodes)):
            return False
        init_left = module_init.child_by_field_name('left')
        if init_left is None or init_left.type != 'subscript_expression':
            return False
        if self.binding(text(self.data, init_left.child_by_field_name('object')), init_left.child_by_field_name('object')) != cache_binding:
            return False
        if self.binding(text(self.data, init_left.child_by_field_name('index')), init_left.child_by_field_name('index')) != self.binding(text(self.data, parameter), parameter):
            return False
        for write in self.writes:
            root = self.root_identifier(write)
            if root and self.binding(text(self.data, root), root) == cache_binding and (key(write) != key(init_left)):
                return False
        if not self.binding_references_allowed(cache_binding,[cached_init.child_by_field_name('object'),init_left.child_by_field_name('object')]):
            return False
        fresh_declaration = fresh.named_child(0)
        if key(fresh_declaration.child_by_field_name('value')) != key(module_init):
            return False
        if text(self.data, fresh_declaration.child_by_field_name('name')) != text(self.data, module):
            return False
        returned = ret.named_child(0)
        if returned.type != 'sequence_expression' or returned.named_child_count != 2:
            return False
        if key(returned.named_child(0)) != key(dispatch):
            return False
        final = returned.named_child(1)
        if final.type != 'member_expression' or text(self.data, final.child_by_field_name('object')) != text(self.data, module) or text(self.data, final.child_by_field_name('property')) != 'exports':
            return False
        condition = guard.child_by_field_name('condition')
        if condition.type == 'parenthesized_expression' and condition.named_child_count == 1:
            condition = condition.named_child(0)
        if condition.type != 'binary_expression' or text(self.data, condition.child_by_field_name('operator')) != '!==':
            return False
        lhs, rhs = (condition.child_by_field_name('left'), condition.child_by_field_name('right'))
        if lhs.type != 'unary_expression' or text(self.data, lhs.child_by_field_name('operator')) != 'void' or text(self.data, lhs.child_by_field_name('argument')) != '0':
            return False
        if text(self.data, rhs) != text(self.data, cached_name):
            return False
        consequence = guard.child_by_field_name('consequence')
        if guard.child_by_field_name('alternative') or consequence.type != 'return_statement' or consequence.named_child_count != 1:
            return False
        value = consequence.named_child(0)
        return value.type == 'member_expression' and text(self.data, value.child_by_field_name('object')) == text(self.data, cached_name) and (text(self.data, value.child_by_field_name('property')) == 'exports')

    def closed_factory_table(self, table):
        """This slice does not model arbitrary cross-factory loader propagation."""
        names = set()
        for entry in children(table):
            name_node = entry.child_by_field_name('name') or entry.child_by_field_name('key')
            name = literal(self.data,name_node) if name_node and name_node.type=='string' else text(self.data,name_node)
            if name_node is None or name_node.type == 'computed_property_name' or name in ('__proto__','prototype','constructor') or name in names:
                return False
            names.add(name)
            factory = entry if entry.type == 'method_definition' else entry.child_by_field_name('value') if entry.type == 'pair' else None
            if factory is None or factory.type not in ('method_definition','function_expression','arrow_function'):
                return False
            if entry.type == 'method_definition' and self.data[entry.start_byte:name_node.start_byte].strip():
                return False
            if factory.type == 'function_expression' and not self.data[factory.start_byte:factory.start_byte+8].startswith(b'function'):
                return False
            if any(factory.start_byte < node.start_byte < factory.end_byte and (node.type == 'this' or (node.type == 'identifier' and text(self.data,node) == 'arguments' and self.binding('arguments',node) is None)) for node in self.nodes):
                return False  # Implicit table/loader aliases are outside the closed slice.
            params = children(factory.child_by_field_name('parameters'))
            if len(params) >= 3:
                if params[2].type != 'identifier':
                    return False
                loader = self.binding(text(self.data,params[2]),params[2])
                # Passing the loader is part of the call recipe, but recovering
                # arbitrary uses of its alias inside another factory is not.
                if loader and not self.binding_references_allowed(loader,[]):
                    return False
        return True

    def webpack_factory(self, function, args):
        if function is None or function.type != 'identifier' or len(args) != 1:
            return None
        binding = self.binding(text(self.data, function), function)
        if not binding or len(binding[2]) != 1:
            return None
        value, definition = binding[2][0]
        if value[0] != 'function' or self.mutated(binding):
            return None
        dispatcher = value[1]
        params = children(dispatcher.child_by_field_name('parameters'))
        if len(params) != 1 or params[0].type != 'identifier':
            return None
        module_id = text(self.data, args[0]) if args[0].type == 'number' else literal(self.data, args[0])
        if not module_id or not re.fullmatch('[A-Za-z0-9_-]{1,128}', module_id):
            return None
        candidates = []
        for call in self.nodes:
            if call.type != 'call_expression' or not dispatcher.start_byte < call.start_byte < dispatcher.end_byte:
                continue
            callee = call.child_by_field_name('function')
            if callee.type != 'subscript_expression':
                continue
            index = callee.child_by_field_name('index')
            if not index or self.binding(text(self.data, index), index) != self.binding(text(self.data, params[0]), params[0]):
                continue
            actual = children(call.child_by_field_name('arguments'))
            if len(actual) != 3 or actual[0].type != 'identifier' or actual[1].type != 'member_expression':
                continue
            if text(self.data, actual[1].child_by_field_name('object')) != text(self.data, actual[0]) or text(self.data, actual[1].child_by_field_name('property')) != 'exports':
                continue
            if text(self.data, actual[2]) != text(self.data, function) or self.binding(text(self.data, actual[2]), actual[2]) != binding:
                continue
            table = callee.child_by_field_name('object')
            table_binding = self.binding(text(self.data, table), table)
            if not table_binding or len(table_binding[2]) != 1 or self.mutated(table_binding):
                continue
            table_value, table_decl = table_binding[2][0]
            obj = table_value[1]
            if obj is None or obj.type != 'object' or not self.closed_factory_table(obj):
                continue
            # The factory must receive the fresh cached module object.
            module_binding = self.binding(text(self.data, actual[0]), actual[0])
            if not module_binding or len(module_binding[2]) != 1:
                continue
            init = module_binding[2][0][0][1]
            if init is None or init.type != 'assignment_expression':
                continue
            module_obj = init.child_by_field_name('right')
            if module_obj is None or module_obj.type != 'object':
                continue
            props = children(module_obj)
            if len(props) != 1 or text(self.data, props[0].child_by_field_name('key')) != 'exports':
                continue
            export_obj = props[0].child_by_field_name('value')
            if export_obj is None or export_obj.type != 'object' or export_obj.named_child_count:
                continue
            if not self.binding_references_allowed(table_binding,[table]):
                continue
            if not self.dispatcher_return_shape(dispatcher, call, actual[0], init, params[0]):
                continue
            if any((n.type == 'variable_declarator' and n.child_by_field_name('value') is not None and (n.child_by_field_name('value').type == 'identifier') and (self.binding(text(self.data, n.child_by_field_name('value')), n.child_by_field_name('value')) == table_binding) for n in self.nodes)):
                continue
            for factory in children(obj):
                name = factory.child_by_field_name('name') or factory.child_by_field_name('key')
                if text(self.data, name) == module_id and factory.type == 'method_definition':
                    prefix = self.data[factory.start_byte:name.start_byte].strip()
                    if prefix:
                        continue  # Generators, async functions and accessors do not match this recipe.
                    candidates.append((factory, call, table_decl))
        if len(candidates) != 1:
            return None
        return candidates[0]

    def webpack_external(self, function, args, seen):
        found = self.webpack_factory(function, args)
        if found is None:
            return None
        factory, dispatch, table_decl = found
        parameters = children(factory.child_by_field_name('parameters'))
        body = factory.child_by_field_name('body')
        statements = children(body)
        if not parameters or parameters[0].type != 'identifier' or len(statements) != 1 or (statements[0].type != 'expression_statement'):
            return None
        expr = statements[0].named_child(0)
        if expr.type != 'assignment_expression':
            return None
        left, right = (expr.child_by_field_name('left'), expr.child_by_field_name('right'))
        if left.type != 'member_expression' or text(self.data, left.child_by_field_name('property')) != 'exports':
            return None
        if self.binding(text(self.data, left.child_by_field_name('object')), left.child_by_field_name('object')) != self.binding(text(self.data, parameters[0]), parameters[0]):
            return None
        if right.type != 'call_expression':
            return None
        fn = right.child_by_field_name('function')
        external = children(right.child_by_field_name('arguments'))
        if text(self.data, fn) != 'require' or self.binding('require', fn) is not None or len(external) != 1 or (not self.free_require_safe()):
            return None
        module = literal(self.data, external[0])
        if module:
            self.trace.append({'webpack_dispatch': self.loc(dispatch), 'factory': self.loc(factory), 'table_definition': self.loc(table_decl), 'module': module, 'basis': 'supported static table-dispatch/fresh-module/external-export shape; loader execution not proven'})
        return module

def inspect_binding(data, focus_byte, api=None):
    model = Slice(data)
    result = {'classification': 'computed', 'binding_schema': BINDING_SCHEMA, 'coverage': {'scope': 'one supported static preload API binding slice', 'named_nodes_examined': len(model.nodes), 'scope_index_complete': model.complete, 'tree_has_parse_errors': model.tree.root_node.has_error, 'semantic_analysis_complete': False, 'whole_program_receiver_integrity': False}, 'static_steps': [], 'unresolved': [], 'limitations': ['No JavaScript executed. Standard CommonJS require semantics are an assumption.', 'Static origin propagation is not runtime receiver, reachability or IPC-delivery proof.', 'Only immutable lexical aliases and a narrow webpack external-export shape are supported.', 'No cross-component IPC edge is established by this operation.']}
    if not model.complete or model.dynamic_scope or model.tree.root_node.has_error:
        result['unresolved'] = sorted(model.reasons | ({'dynamic_eval_or_with_scope'} if model.dynamic_scope else set()) | ({'parse_errors_in_binding_scope'} if model.tree.root_node.has_error else set()))
        return result
    calls = [n for n in model.nodes if n.type == 'call_expression' and n.start_byte == focus_byte]
    if len(calls) != 1:
        result['unresolved'] = ['Use the start_byte of one exposeInMainWorld call returned by syntax inspection.']
        return result
    call = calls[0]
    callee = call.child_by_field_name('function')
    args = children(call.child_by_field_name('arguments'))
    model.ignore_mutations = True
    lexical_origin = model.resolve(callee)
    model.ignore_mutations = False
    result['lexical_callee_origin'] = list(lexical_origin) if lexical_origin else None
    origin = model.resolve(callee)
    result['focus'] = model.loc(call)
    result['callee_origin'] = list(origin) if origin else None
    if model.tainted_module(origin):
        origin = None
        result['callee_origin'] = None
        model.reasons.add('module_receiver_mutated_or_escaped')
    if origin != ('module', 'electron', 'contextBridge', 'exposeInMainWorld') or len(args) != 2 or args[1].type != 'object':
        model.reasons.add('exposeInMainWorld_not_bound_to_supported_electron_import_or_literal_object')
    else:
        result['namespace'] = literal(data, args[0])
        if any(n.type == 'spread_element' or any(n.child_by_field_name(field) and n.child_by_field_name(field).type == 'computed_property_name' for field in ('name', 'key')) for n in children(args[1])):
            model.reasons.add('spread_or_computed_exposed_object_may_override_API')
            result['unresolved'] = sorted(model.reasons)
            return result
        entries = []
        for entry in children(args[1]):
            name = entry.child_by_field_name('name') or entry.child_by_field_name('key')
            spelling = text(data, entry) if entry.type == 'shorthand_property_identifier' else text(data, name)
            if name and name.type == 'string':
                spelling = literal(data, name)
            entries.append((spelling, entry))
        result['api_outline'] = [{'name': name, 'start_byte': entry.start_byte, 'end_byte': entry.end_byte} for name, entry in entries[:64]]
        result['api_total'] = len(entries)
        result['api_outline_truncated'] = len(entries) > 64
        if api is not None:
            matching = [entry for name, entry in entries if name == api]
            if len(matching) != 1:
                model.reasons.add('API_missing_duplicate_or_dynamic')
            else:
                entry = matching[0]
                fn = entry if entry.type == 'method_definition' else entry.child_by_field_name('value')
                result['selected_api'] = {'name': api, **model.loc(entry), 'ipc_calls': []}
                method_name = entry.child_by_field_name('name')
                prefix = data[entry.start_byte:method_name.start_byte].strip() if method_name else b''
                ordinary_method = prefix not in (b'get', b'set') and b'*' not in prefix
                if fn and fn.type in FUNCTIONS and (not fn.type.startswith('generator_')) and ordinary_method:
                    for candidate in model.nodes:
                        if candidate.type != 'call_expression' or not fn.start_byte < candidate.start_byte < fn.end_byte:
                            continue
                        if key(model.nearest_function(candidate)) != key(fn):
                            model.reasons.add('nested_callback_call_not_asserted_as_direct_API_path')
                            continue
                        target = model.resolve(candidate.child_by_field_name('function'))
                        if model.tainted_module(target):
                            model.reasons.add('module_receiver_mutated_or_escaped')
                            continue
                        if target and len(target) == 4 and (target[:3] == ('module', 'electron', 'ipcRenderer')) and (target[3] in ('send', 'sendSync', 'invoke', 'postMessage', 'on', 'once')):
                            actual = children(candidate.child_by_field_name('arguments'))
                            from .js_literals import resolve_string
                            resolved_channel = resolve_string(model, actual[0]) if actual else None
                            channel = resolved_channel['value'] if resolved_channel else None
                            if channel is None:
                                model.reasons.add('dynamic_or_unsupported_channel_expression')
                            result['selected_api']['ipc_calls'].append({'classification': 'computed', 'origin': list(target), 'channel': channel, 'channel_status': resolved_channel['basis'] if resolved_channel else 'unresolved_expression', 'channel_provenance': resolved_channel, 'channel_expression': text(data, actual[0]) if actual else None, **model.loc(candidate)})
                    if not result['selected_api']['ipc_calls']:
                        model.reasons.add('no_supported_direct_electron_ipc_call_resolved')
                else:
                    model.reasons.add('API_is_not_a_supported_function')
    if api is not None:
        result.pop('api_outline', None)
    unique_steps = {repr(step): step for step in model.trace}
    result['static_steps'] = list(unique_steps.values())[:16]
    result['unresolved'] = sorted(model.reasons)
    return result
