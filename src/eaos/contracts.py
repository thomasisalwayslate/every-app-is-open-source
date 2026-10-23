"""Shared tool schemas and strict validation, without third-party validators."""
import functools
import inspect
import re

def schema(properties=None, required=None):
    return {'type':'object','properties':properties or {},'required':required or [],'additionalProperties':False}


S = {'type':'string', 'maxLength':10000}
B = {'type':'boolean','default':False}
TOOLS = [('open_program',
  'Open selected target. In MCP, returns analysis status while loading; call again when asked, '
  'not in a polling loop. Ready: memory map and cached analysis; full=true adds metadata. '
  'Full analysis is default. analysis_mode=quick opts into partial metadata/targeted work; '
  'analysis_mode=full explicitly opens the separate full profile. cancel=true stops owned work. '
  'Status stays available during operations. full=true changes detail only.',
  {'type': 'object',
   'properties': {'full': {'type': 'boolean', 'default': False},
                  'analysis_mode': {'type':'string','enum':['full','quick']},
                  'cancel': {'type':'boolean'}},
   'required': [],
   'additionalProperties': False}),
 ('search',
  'Find strings with xrefs or functions, including supported Go names and literal-byte matches. '
  'Matches available class/namespace names and short aliases. Quick-mode references/names are partial; '
  'missing matches do not prove absence. Quick functions: page next_offset with returned view; '
  'index_cursor=next_index_cursor explicitly indexes one more bounded batch at offset=0, invalidating old views. '
  'Byte matches need a pattern and are slices, not whole strings.',
  {'type': 'object',
   'properties': {'kind': {'type': 'string', 'enum': ['strings', 'functions']},
                  'pattern': {'type': 'string', 'maxLength': 10000},
                  'offset': {'type': 'integer', 'minimum': 0},
                  'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200},
                  'index_cursor': {'type':'string','minLength':1,'maxLength':256},
                  'view': {'type':'string','minLength':1,'maxLength':256},
                  'full': {'type': 'boolean', 'default': False}},
   'required': [],
   'additionalProperties': False}),
 ('inspect',
  'Outline first; then one function: find matching text/integer lines or focus by instruction, '
  'string address/text prefix or callee. For paired code/instructions use focus with mode=all; '
  'assembly works without decompilation. Page code only as a last resort '
  '(full=true, next offset/column). limit=1..80, context=0..20 (find default 2, focus 6). '
  'find offset pages matches. Full evidence retained.',
  {'type': 'object',
   'properties': {'addresses': {'type': 'array',
                                'items': {'type': 'string', 'maxLength': 10000},
                                'minItems': 1,
                                'maxItems': 8},
                  'mode': {'type': 'string',
                           'enum': ['decompile', 'outline', 'assembly', 'references', 'calls', 'all']},
                  'full': {'type': 'boolean', 'default': False},
                  'offset': {'type': 'integer', 'minimum': 0},
                  'column': {'type': 'integer', 'minimum': 0},
                  'limit': {'type': 'integer', 'minimum': 1, 'maximum': 80},
                  'context': {'type': 'integer', 'minimum': 0, 'maximum': 20},
                  'find': schema({'kind': {'type': 'string', 'enum': ['text', 'constant']},
                                  'value': {'type': 'string', 'minLength': 1, 'maxLength': 256}},
                                 ['kind', 'value']),
                  'focus': schema({'kind': {'type': 'string', 'enum': ['address', 'string', 'call']},
                                   'value': {'type': 'string', 'minLength': 1, 'maxLength': 256},
                                   'occurrence': {'type': 'integer', 'minimum': 0, 'maximum': 1000000}},
                                  ['kind', 'value'])},
   'required': ['addresses'],
   'additionalProperties': False}),
 ('read_memory',
  'Static image bytes, not live memory. Verified Mach-O zero-fill is computed initial state; unknown memory stays unavailable. '
  'Default hex; format=utf8/both for text. layout=go_strings plus count decodes bounded Go pointer/length entries '
  '(32 per page, 256 bytes/string); page with offset/next_offset. Full provenance in evidence.',
  {'type': 'object',
   'properties': {'address': {'type': 'string', 'maxLength': 10000},
                  'length': {'type': 'integer', 'minimum': 1, 'maximum': 65536},
                  'format': {'type': 'string', 'enum': ['hex', 'utf8', 'both']},
                  'layout': {'type': 'string', 'enum': ['go_strings']},
                  'count': {'type': 'integer', 'minimum': 1, 'maximum': 1000000},
                  'offset': {'type': 'integer', 'minimum': 0, 'maximum': 1000000}},
   'required': ['address'],
   'additionalProperties': False}),
 ('calculate',
  'Pure Python arithmetic/bytes expression. No imports, filesystem, network or program execution. '
  'Useful for numeric tables and packed constants.',
  {'type': 'object',
   'properties': {'expression': {'type': 'string', 'maxLength': 10000}},
   'required': ['expression'],
   'additionalProperties': False}),
 ('decode_swift_string',
  'Decode 64-bit little-endian Swift small String storage. Supply address or two unsigned words. '
  'Reject unsupported pointer layouts instead of inventing text.',
  {'type': 'object',
   'properties': {'words': {'type': 'array',
                            'items': {'anyOf': [{'type': 'string', 'maxLength': 10000},
                                                {'type': 'integer'}]},
                            'minItems': 2,
                            'maxItems': 2},
                  'address': {'type': 'string', 'maxLength': 10000}},
   'required': [],
   'additionalProperties': False}),
 ('read_evidence',
  'Retrieve a content-checked evidence record by its returned id, with character paging. Never '
  'reads arbitrary paths. For code, prefer inspect outline, then find/focus; page last.',
  {'type': 'object',
   'properties': {'id': {'type': 'string', 'maxLength': 10000},
                  'offset': {'type': 'integer', 'minimum': 0},
                  'limit': {'type': 'integer', 'minimum': 1, 'maximum': 40000}},
   'required': ['id'],
   'additionalProperties': False})]

SCHEMAS = {name: spec for name, _, spec in TOOLS}

def _validate(value, spec, path):
    if 'anyOf' in spec:
        for option in spec['anyOf']:
            try:
                _validate(value, option, path)
                return
            except ValueError:
                pass
        raise ValueError(f'{path}: does not match an allowed type')
    kind = spec.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}
    if kind and type(value) is not types[kind]:
        raise ValueError(f'{path}: expected {kind}')
    if 'enum' in spec and value not in spec['enum']:
        raise ValueError(f'{path}: expected one of {spec["enum"]}')
    if kind == 'object':
        properties = spec.get('properties', {})
        if any(key not in value for key in spec.get('required', [])):
            raise ValueError(f'{path}: missing required argument')
        if spec.get('additionalProperties') is False and value.keys() - properties.keys():
            raise ValueError(f'{path}: unknown argument')
        for key, child in value.items():
            _validate(child, properties[key], f'{path}.{key}')
    elif kind == 'array':
        if len(value) < spec.get('minItems', 0) or len(value) > spec.get('maxItems', float('inf')):
            raise ValueError(f'{path}: invalid number of items')
        for index, child in enumerate(value):
            _validate(child, spec['items'], f'{path}[{index}]')
    elif kind == 'integer':
        if value < spec.get('minimum', -float('inf')) or value > spec.get('maximum', float('inf')):
            raise ValueError(f'{path}: outside allowed range')
    elif kind == 'string':
        if len(value) > spec.get('maxLength', 10000):
            raise ValueError(f'{path}: string too long')
        if len(value) < spec.get('minLength', 0):
            raise ValueError(f'{path}: string too short')

def validate_arguments(name, arguments):
    if name not in SCHEMAS:
        raise ValueError('Unknown tool')
    _validate(arguments, SCHEMAS[name], name)
    if name == 'search' and ('index_cursor' in arguments or 'view' in arguments):
        if arguments.get('kind','strings') != 'functions':
            raise ValueError('search: discovery cursors require kind=functions')
        if 'index_cursor' in arguments and ('view' in arguments or arguments.get('offset',0)):
            raise ValueError('search: index continuation requires offset=0 and no result view')
    if name == 'read_memory':
        if 'layout' in arguments:
            if 'count' not in arguments or 'length' in arguments:
                raise ValueError('read_memory: go_strings requires count, without length')
            if arguments.get('offset', 0) > arguments['count']:
                raise ValueError('read_memory: offset exceeds descriptor count')
        elif 'count' in arguments or arguments.get('offset', 0):
            raise ValueError('read_memory: count/offset require layout=go_strings')
    if name == 'inspect':
        mode = arguments.get('mode', 'decompile')
        if 'find' in arguments:
            if 'focus' in arguments or arguments.get('column', 0):
                raise ValueError('inspect: find cannot combine with focus or column')
            if len(arguments['addresses']) != 1 or mode not in {'decompile', 'assembly'}:
                raise ValueError('inspect: find needs one address and decompile/assembly mode')
            query = arguments['find']
            if query['kind'] == 'constant' and not re.fullmatch(r'[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)', query['value']):
                raise ValueError('inspect: constant must be a decimal or hexadecimal integer')
        if 'focus' in arguments:
            if len(arguments['addresses']) != 1 or mode not in {'decompile', 'assembly', 'all'}:
                raise ValueError('inspect: focus needs one address and decompile/assembly/all mode')
            if arguments.get('offset', 0) or arguments.get('column', 0):
                raise ValueError('inspect: use a focus occurrence or a code cursor, not both')
        elif 'context' in arguments and 'find' not in arguments:
            raise ValueError('inspect: context requires focus or find')
        if arguments.get('column', 0) and (len(arguments['addresses']) != 1 or
                                           mode not in {'decompile', 'all'}):
            raise ValueError('inspect: column needs one decompile/all address')
    if name == 'decode_swift_string':
        if ('words' in arguments) == ('address' in arguments):
            raise ValueError('decode_swift_string: supply words or address, not both')
        for word in arguments.get('words', []):
            try:
                number = int(word, 0) if isinstance(word, str) else word
            except ValueError:
                raise ValueError('decode_swift_string: invalid integer word') from None
            if not 0 <= number < (1 << 64):
                raise ValueError('decode_swift_string: words must be unsigned 64-bit values')
    return arguments


def validate_search_profile(arguments, analysis_mode):
    """Reject incompatible discovery requests before starting a native owner."""
    if ('index_cursor' in arguments or 'view' in arguments) and analysis_mode!='quick':
        raise ValueError('Discovery cursors require kind=functions and the quick profile')
    if (arguments.get('kind','strings')=='functions' and analysis_mode=='quick' and
            arguments.get('offset',0) and 'view' not in arguments):
        raise ValueError('Quick function pagination requires the returned view with offset. Restart at offset=0 after index expansion.')

def validated_tool(name):
    def decorate(function):
        signature = inspect.signature(function)
        @functools.wraps(function)
        def checked(self, *args, **kwargs):
            try:
                bound = signature.bind(self, *args, **kwargs)
            except TypeError as error:
                raise ValueError(str(error)) from None
            validate_arguments(name, {key: value for key, value in bound.arguments.items() if key != 'self'})
            return function(self, *args, **kwargs)
        return checked
    return decorate
