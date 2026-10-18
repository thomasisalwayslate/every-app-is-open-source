"""Shared tool schemas and strict validation, without third-party validators."""
import functools
import inspect

def schema(properties=None, required=None):
    return {'type':'object','properties':properties or {},'required':required or [],'additionalProperties':False}


S = {'type':'string', 'maxLength':10000}
B = {'type':'boolean','default':False}
TOOLS = [('open_program',
  'Selected target, memory map and analysis cache. full=true includes all metadata.',
  {'type': 'object',
   'properties': {'full': {'type': 'boolean', 'default': False}},
   'required': [],
   'additionalProperties': False}),
 ('search',
  'Substring search of strings (with xrefs) or functions. Page with next_offset; full=true for '
  'signatures.',
  {'type': 'object',
   'properties': {'kind': {'type': 'string', 'enum': ['strings', 'functions']},
                  'pattern': {'type': 'string', 'maxLength': 10000},
                  'offset': {'type': 'integer', 'minimum': 0},
                  'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200},
                  'full': {'type': 'boolean', 'default': False}},
   'required': [],
   'additionalProperties': False}),
 ('inspect',
  'Batch addresses. Default computed pseudocode. mode=calls, references, assembly or all; '
  'full=true expands. Omitted detail: read_evidence.',
  {'type': 'object',
   'properties': {'addresses': {'type': 'array',
                                'items': {'type': 'string', 'maxLength': 10000},
                                'minItems': 1,
                                'maxItems': 8},
                  'mode': {'type': 'string',
                           'enum': ['decompile', 'assembly', 'references', 'calls', 'all']},
                  'full': {'type': 'boolean', 'default': False}},
   'required': ['addresses'],
   'additionalProperties': False}),
 ('read_memory',
  'Fact: literal bytes at a virtual address. Default hex; format=utf8 or both for text display.',
  {'type': 'object',
   'properties': {'address': {'type': 'string', 'maxLength': 10000},
                  'length': {'type': 'integer', 'minimum': 1, 'maximum': 65536},
                  'format': {'type': 'string', 'enum': ['hex', 'utf8', 'both']}},
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
  'reads arbitrary paths.',
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
    elif kind == 'string' and len(value) > spec.get('maxLength', 10000):
        raise ValueError(f'{path}: string too long')

def validate_arguments(name, arguments):
    if name not in SCHEMAS:
        raise ValueError('Unknown tool')
    _validate(arguments, SCHEMAS[name], name)
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
