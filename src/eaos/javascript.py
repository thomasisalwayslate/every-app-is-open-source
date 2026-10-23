"""Conservative, execution-free JavaScript call-site observations.

This is a lexer for a deliberately narrow Electron slice, not a JavaScript
parser, module resolver, control-flow analysis, or runtime IPC verifier.
"""
from __future__ import annotations

import hashlib
import bisect
import time


class JavaScriptError(ValueError):
    pass


def inspect_source(data, *, max_bytes=1024 * 1024, max_tokens=100000,
                   max_observations=2000, max_seconds=10.0, cancelled=None):
    if len(data) > max_bytes:
        raise JavaScriptError('JavaScript source exceeds byte budget')
    try:
        source = data.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise JavaScriptError('Only UTF-8 JavaScript source is supported') from exc
    deadline = time.monotonic() + max_seconds
    def check():
        if cancelled and cancelled():
            raise InterruptedError('JavaScript inspection cancelled')
        if time.monotonic() >= deadline:
            raise TimeoutError('JavaScript inspection time budget')
    tokens, gaps = [], []
    i = 0
    while i < len(source):
        check()
        if len(tokens) >= max_tokens:
            gaps.append({'offset': i, 'reason': 'token_budget'})
            break
        c = source[i]
        if c.isspace():
            i += 1
            continue
        if source.startswith('//', i):
            end = source.find('\n', i)
            i = len(source) if end < 0 else end + 1
            continue
        if source.startswith('/*', i):
            end = source.find('*/', i + 2)
            if end < 0:
                gaps.append({'offset': i, 'reason': 'unterminated_comment'})
                break
            i = end + 2
            continue
        at = i
        if c in "'\"`":
            quote, value, dynamic, escaped = c, [], c == '`', False
            terminated = False
            i += 1
            while i < len(source):
                if i % 4096 == 0:
                    check()
                c = source[i]
                if c == quote:
                    terminated = True
                    i += 1
                    break
                if c == '\\':
                    # Do not guess JS escape interpretation; retain source range.
                    escaped = True
                    i += 2
                    continue
                if c in '\r\n' and quote != '`':
                    break
                value.append(c)
                i += 1
            if not terminated:
                gaps.append({'offset': at, 'reason': 'unterminated_string'})
            if dynamic or escaped:
                gaps.append({'offset': at, 'reason': 'template_or_escaped_literal_unparsed'})
            tokens.append(('unsupported' if dynamic or escaped or not terminated else 'string', ''.join(value), at, i))
            continue
        if c == '/':
            # Regex/division is intentionally unsupported. Consume to a statement
            # boundary so apparent ipc calls inside regex text cannot become facts.
            end = source.find('\n', i)
            end = len(source) if end < 0 else end
            gaps.append({'offset': i, 'reason': 'regex_or_division_unparsed'})
            tokens.append(('unsupported', '', i, end))
            i = end
            continue
        if c.isalpha() or c in '_$':
            i += 1
            while i < len(source) and (source[i].isalnum() or source[i] in '_$'):
                i += 1
            tokens.append(('identifier', source[at:i], at, i))
        else:
            i += 1
            tokens.append(('punctuation', c, at, i))
    observations = []
    newlines = [i for i, char in enumerate(source) if char == '\n']
    def emit(kind, token, **fields):
        if len(observations) >= max_observations:
            return False
        observations.append({'kind': kind, 'classification': 'fact',
                             'line': bisect.bisect_left(newlines, token[2]) + 1,
                             'source_character_offset': token[2], **fields})
        return True
    for n, token in enumerate(tokens):
        check()
        if len(observations) >= max_observations:
            gaps.append({'offset': token[2], 'reason': 'observation_budget'})
            break
        values = [t[1] for t in tokens[n:n + 5]]
        # Static module specifiers only; no filesystem or package execution.
        standalone = token[0] == 'identifier' and (n == 0 or tokens[n-1][1] != '.')
        if standalone and values[:2] == ['require', '(']:
            if len(values) >= 4 and tokens[n+2][0] == 'string' and values[3] == ')':
                emit('module_specifier', token, module=tokens[n+2][1], syntax='require',
                     relationship='syntactic require spelling; binding unverified')
            else:
                gaps.append({'offset': token[2], 'reason': 'dynamic_require_unparsed'})
        elif standalone and token[1] in ('import', 'export'):
            if len(values) > 1 and tokens[n+1][0] == 'string' and token[1] == 'import':
                emit('module_specifier', token, module=tokens[n+1][1], syntax='import')
            elif values[1:2] == ['(']:
                if len(values) >= 4 and tokens[n+2][0] == 'string' and values[3] == ')':
                    emit('module_specifier', token, module=tokens[n+2][1], syntax='literal_dynamic_import')
                else:
                    gaps.append({'offset': token[2], 'reason': 'dynamic_import_unparsed'})
            else:
                allowed_start = (token[1] == 'import' and len(values) > 1 and (tokens[n+1][0] == 'identifier' or values[1] in ('{', '*'))) or (token[1] == 'export' and len(values) > 1 and values[1] in ('{', '*'))
                for later_index in range(n + 1, min(n + 64, len(tokens) - 1)) if allowed_start else ():
                    later = tokens[later_index]
                    if later[1] in (';', '=', '(', ':') or later[0] in ('string', 'unsupported'):
                        break
                    if later[0] == 'identifier' and later[1] == 'from' and tokens[later_index+1][0] == 'string':
                        emit('module_specifier', token, module=tokens[later_index+1][1], syntax=token[1])
                        break
        if len(values) >= 4 and standalone and values[1] == '.' and values[3] == '(':
            receiver, method = values[0], values[2]
            relevant = ((receiver in ('ipcMain', 'ipcRenderer') and method in ('on', 'once', 'handle', 'handleOnce', 'send', 'sendSync', 'invoke', 'postMessage'))
                        or method in ('loadFile', 'loadURL', 'exposeInMainWorld'))
            if relevant:
                arg = tokens[n+4] if n+4 < len(tokens) else None
                literal = arg is not None and arg[0] == 'string' and n+5 < len(tokens) and tokens[n+5][1] in (',', ')')
                emit('call_site', token, receiver=receiver, method=method,
                     literal_argument=arg[1] if literal else None,
                     argument_status='literal' if literal else 'dynamic_or_unparsed',
                     relationship='syntactic_only; binding and runtime dispatch unverified')
        if values[:2] == ['preload', ':']:
            arg = tokens[n+2] if n+2 < len(tokens) else None
            literal = arg is not None and arg[0] == 'string' and n+3 < len(tokens) and tokens[n+3][1] in (',', '}')
            emit('preload_property', token, literal_argument=arg[1] if literal else None,
                 argument_status='literal' if literal else 'dynamic_or_unparsed',
                 relationship='property occurrence; BrowserWindow ownership unverified')
    return {'classification': 'computed', 'source_sha256': hashlib.sha256(data).hexdigest(),
            'source_bytes': len(data), 'observations': observations,
            'coverage': {'complete': False, 'scope': 'bounded lexical direct-call observations',
                         'tokens_examined': len(tokens), 'unparsed': gaps},
            'limitations': ['Not a full JavaScript parser or module resolver.',
                            'Identifier bindings, shadowing, dynamic paths, runtime IPC and control flow are not established.',
                            'Absence of an observation does not establish absence of behavior.']}
