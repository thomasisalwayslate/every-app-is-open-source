"""Bounded views of a saved function. No interpretation or native dependencies."""
from __future__ import annotations

import json
import re
from itertools import zip_longest

SMALL_FUNCTION_CHARS = 5000
PAGE_CHARS = 6000
REPLY_CHARS = 16000


def compact(item):
    """Keep searchable identities in evidence, not repeated large signatures."""
    row = {k: v for k, v in item.items() if k in
           {'address', 'name', 'ghidra_name', 'size', 'source', 'signature'}}
    for key in ('name', 'ghidra_name', 'signature'):
        if key in row and len(row[key]) > 160:
            row[key + '_truncated'] = True
            row[key] = row[key][:160]
    return row


def page(lines, offset=0, column=0, limit=40, end=None):
    """A line/column cursor preserves even a single extremely long line."""
    if offset > len(lines) or (offset == len(lines) and column):
        raise ValueError('Code offset is outside this function')
    if offset < len(lines) and column > len(lines[offset]['text']):
        raise ValueError('Code column is outside this line')
    stop = min(len(lines), offset + limit, end if end is not None else len(lines))
    text, locations, cursor, col = '', [], offset, column
    while cursor < stop:
        line = lines[cursor]
        remaining = line['text'][col:] + '\n'
        available = PAGE_CHARS - len(text)
        if not available:
            break
        part = remaining[:available]
        text += part
        addresses = line.get('addresses', [])
        if addresses:
            locations.append({'line': cursor + 1, 'address': addresses[0],
                              'address_count': len(addresses)})
        if len(part) < len(remaining):
            col += len(part)
            # The pending newline is represented by column == len(text).
            break
        cursor += 1
        col = 0
    next_page = {'offset': cursor, 'column': col} if cursor < len(lines) else None
    return {'pseudocode': text, 'line_start': offset + 1, 'start_column': column,
            'line_end': cursor + (1 if col else 0), 'line_locations': locations,
            'total_lines': len(lines), 'next': next_page,
            'truncated': next_page is not None or offset != 0 or column != 0}


def _category(items, offset, limit):
    return {'total': len(items), 'offset': offset, 'items': items[offset:offset + limit],
            'next_offset': offset + limit if offset + limit < len(items) else None}


def outline(row, offset=0, limit=6):
    callees = {}
    for site in row['call_sites']:
        target = site.get('target')
        key = target['address'] if target else '(unresolved)'
        entry = callees.setdefault(key, {**(compact(target) if target else
                                           {'name': '(unresolved indirect call)'}),
                                        'sites': [], 'site_count': 0})
        entry.pop('signature', None)
        entry.pop('size', None)
        entry['site_count'] += 1
        if len(entry['sites']) < 3:
            entry['sites'].append(site['address'])
    strings = [{**{k: s[k] for k in ('address', 'reference', 'text', 'source')},
                'classification': s.get('classification', 'computed')}
               for s in row['string_references']]
    for item in strings:
        item['text'] = item['text'][:96]
        item['extent'] = 'preview; not Go string boundaries'
    returns, errors = [], []
    for line in row['lines']:
        if re.search(r'\breturn\b', line['text']):
            returns.append({'kind': 'return', 'line': line['line'],
                          'address': next(iter(line['addresses']), None),
                          'text': line['text'].strip()[:120]})
    for site in row['call_sites']:
        name = (site.get('target') or {}).get('name', '')
        if re.search(r'error|abort|fatal|panic', name, re.I):
            errors.append({'kind': 'error_candidate', 'address': site['address'],
                          'text': name[:120], 'basis': 'callee name; heuristic'})
    sites = [s for pair in zip_longest(returns, errors) for s in pair if s is not None]
    callees = sorted(callees.values(), key=lambda c: c['name'].startswith(('runtime.', 'internal/')))
    return {'code_characters': len(row['pseudocode']), 'code_lines': len(row['lines']),
            'callees': _category(callees, offset, min(limit, 6)),
            'strings': _category(strings, offset, min(limit, 6)),
            'sites': _category(sites, offset, min(limit, 6)),
            'coverage': row['coverage']}


def _focus_matches(row, focus, lines=None):
    kind, value = focus['kind'], focus['value']
    def normalize(value):
        value = value.lower().removeprefix('0x')
        return f'{int(value, 16):x}' if re.fullmatch(r'[0-9a-f]+', value) else value
    sources = []
    if kind == 'address':
        sources = [{'address': value}]
    elif kind == 'string':
        sources = [{'address': s['reference'], 'string_address': s['address'],
                    'classification': s.get('classification', 'computed'),
                    'basis': s['source'] + '; referenced address or text prefix, extent unverified'}
                   for s in row['string_references']
                   if normalize(value) == normalize(s['address']) or
                   s['text'].casefold().startswith(value.casefold())]
    else:
        for site in row['call_sites']:
            target = site.get('target') or {}
            if (normalize(value) == normalize(target.get('address', '')) or
                    value.casefold() in (target.get('name', '') + ' ' +
                                         target.get('ghidra_name', '')).casefold()):
                sources.append({'address': site['address'],
                                'target': target.get('address')})
    matches, unmapped = [], []
    seen = set()
    mapped = {}
    for line in row['lines'] if lines is None else lines:
        for address in line['addresses']:
            mapped.setdefault(normalize(address), []).append(
                (line['line'], line.get('columns', {}).get(address, 0)))
    for source in sources:
        locations = mapped.get(normalize(source['address']), [])
        for number, column in locations:
            key = (number, normalize(source['address']))
            if key not in seen:
                matches.append({'line': number, 'column': column, **source})
                seen.add(key)
        if not locations:
            unmapped.append(source['address'])
            matches.append({'line': None, 'column': 0, **source})
    matches.sort(key=lambda m: (m['line'] if m['line'] is not None else float('inf'), m['address']))
    return matches, unmapped


def focus_metadata(row, focus, lines=None):
    matches, unmapped = _focus_matches(row, focus, lines)
    occurrence = focus.get('occurrence', 0)
    return {'kind': focus['kind'], 'value': focus['value'],
            'matches': len(matches), 'occurrence': occurrence,
            'next_occurrence': occurrence + 1 if occurrence + 1 < len(matches) else None,
            'unmapped_count': len(unmapped), 'unmapped_sites': unmapped[:6],
            'match': matches[occurrence] if occurrence < len(matches) else None,
            'coverage': row.get('coverage', {})}


def instruction_lines(instructions):
    return [{'line': index + 1, 'text': item['text'],
             'addresses': [item['address']], 'columns': {item['address']: 0}}
            for index, item in enumerate(instructions)]


_INTEGER = re.compile(r'(?<![\w.])[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*(?![\w.])')
_FLOAT = re.compile(r'(?<![\w.])(?:0[xX](?:[\da-fA-F]+(?:\.[\da-fA-F]*)?|\.[\da-fA-F]+)'
                    r'[pP][+-]?\d+|(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)'
                    r'[fFlL]?(?![\w.])')
_QUOTED = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def _integer(value):
    value = value.rstrip('uUlL')
    return int(value, 16 if value.lstrip('+-').lower().startswith('0x') else 10)


def find_view(row, query, *, assembly=False, offset=0, limit=40, context=2):
    """Literal line search, with bounded context; not an expression/data-flow evaluator."""
    lines = instruction_lines(row['instructions']) if assembly else row['lines']
    texts = [line['text'] for line in lines]
    if query['kind'] == 'constant':
        # Mask quotes/comments without changing positions. Text search can find them.
        masked = _QUOTED.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]),
                             '\n'.join(texts))
        masked = _FLOAT.sub(lambda m: ' ' * len(m[0]), masked)
        searchable = masked.split('\n')
        number = _integer(query['value'])
    else:
        searchable = texts
        literal = re.compile(re.escape(query['value']), re.I)
    matches = []
    for index, text in enumerate(searchable):
        if query['kind'] == 'constant':
            match = next((m for m in _INTEGER.finditer(text) if _integer(m[0]) == number), None)
        else:
            match = literal.search(text)
        if match is not None:
            matches.append((index, match.start()))
    if offset > len(matches):
        raise ValueError('Search offset is outside the matching lines')

    def snippet(index, column=0):
        line = lines[index]
        start = max(0, column - 64)
        end = min(len(line['text']), start + 384)
        return {'line': index + 1, 'text': line['text'][start:end], 'start_column': start,
                'text_truncated': start != 0 or end < len(line['text']),
                'addresses': line['addresses'][:4], 'address_count': len(line['addresses'])}

    shown = []
    for index, column in matches[offset:offset + min(limit, 8)]:
        item = {'line': index + 1, 'match_column': column,
                'lines': [snippet(i, column if i == index else 0)
                          for i in range(max(0, index - context), min(len(lines), index + context + 1))]}
        # Preserve the actual match even when a requested context window is huge.
        while len(json.dumps(item, ensure_ascii=False)) > PAGE_CHARS - 256:
            if index + 1 - item['lines'][0]['line'] >= item['lines'][-1]['line'] - index - 1:
                item['lines'].pop(0)
            else:
                item['lines'].pop()
        if len(json.dumps(shown + [item], ensure_ascii=False)) > PAGE_CHARS:
            break
        shown.append(item)
    next_offset = offset + len(shown)
    result = compact(row)
    result['find'] = {**query, 'mode': 'assembly' if assembly else 'decompile',
                      'searched_lines': len(lines),
                      'total_matching_lines': len(matches), 'offset': offset,
                      'next_offset': next_offset if next_offset < len(matches) else None,
                      'matches': shown,
                      'limitations': 'Literal rendered-line search, not evaluated values or control flow. '
                                     'One hit per line; context/text can be shortened. '
                                     'Missing decompiler PCs are not replaced with guessed addresses. '
                                     'Constants match lexical decimal/hex integers, excluding quoted text/comments.'}
    return result


def code_view(row, *, full=False, offset=0, column=0, limit=40, focus=None, context=6):
    result = compact(row)
    if focus:
        result['focus'] = focus_metadata(row, focus)
        match = result['focus']['match']
        if match and match['line'] is not None:
            left = min(context, (limit - 1) // 2)
            right = min(context, limit - left - 1)
            begin = max(0, match['line'] - 1 - left)
            end = min(len(row['lines']), match['line'] + right)
            # Context must never push the matched token out of the bounded page.
            before = sum(len(l['text']) + 1 for l in row['lines'][begin:match['line'] - 1])
            column = 0
            if before + match['column'] >= PAGE_CHARS - 128:
                begin = match['line'] - 1
                column = max(0, match['column'] - PAGE_CHARS // 3)
            result.update(page(row['lines'], begin, column, min(limit, end - begin), end))
            result['focus']['window_end_line'] = end
        else:
            result['pseudocode'] = ''
            result['limitations'] = ['No mapped match. This does not prove absence; '
                                      'use an outline address or assembly. No nearest-line guess was substituted.']
    elif full or offset or column or len(row['pseudocode']) <= SMALL_FUNCTION_CHARS:
        result.update(page(row['lines'], offset, column, limit))
        if not offset and not column and len(row['pseudocode']) > SMALL_FUNCTION_CHARS:
            result['outline'] = outline(row, limit=3)
    else:
        result['outline'] = outline(row, limit=limit)
        result['hint'] = 'Next use find text/constant or focus address/string/call. Page code only as a last resort (full=true, next cursor).'
    return result


def fit_outline(row, maximum):
    """Trim lists only, retaining real totals and resumable category offsets."""
    if 'outline' not in row:
        return row
    while len(json.dumps(row, ensure_ascii=False, separators=(',', ':'))) > maximum:
        categories = [v for v in row['outline'].values()
                      if isinstance(v, dict) and v.get('items')]
        if not categories:
            break
        category = max(categories, key=lambda v: len(json.dumps(v['items'])))
        category['items'].pop()
        # Each category uses the same requested offset; preserve its own next cursor.
        category['next_offset'] = category['offset'] + len(category['items'])
    return row
