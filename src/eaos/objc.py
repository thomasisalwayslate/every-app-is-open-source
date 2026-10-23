"""Project explicit Objective-C method symbols already recovered by Ghidra.

No second metadata parser: the existing ObjcTypeMetadataAnalyzer owns recovery.
A qualified C++/Swift name alone is not an Objective-C method declaration.
"""
from __future__ import annotations

import re

# Native clang spellings use a space; Ghidra can render that separator as '_'.
# For the latter require the independent qualified class name to disambiguate
# legitimate underscores in a class or selector. Never split on an arbitrary '_'.
_METHOD = re.compile(r'^([+-])\[([^\[\]\s]+) ([^\[\]\s]+)\]$')
_SELECTOR = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$]*(?::[A-Za-z0-9_$]*)*$')


def method_identities(row):
    """Return bounded explicit class/selector/implementation identities.

    Input is an existing fn_info/search row. Duplicate aliases collapse only
    within this implementation; matching selectors on distinct classes/addresses
    remain distinct. Names and implementation addresses are computed metadata,
    not proof of a message send, selected receiver, or runtime dispatch.
    """
    address = row.get('address')
    if not isinstance(address, str) or not address:
        return []
    qualified = row.get('qualified_name', '')
    qualified = qualified if isinstance(qualified, str) else ''
    namespace, _, short_name = qualified.rpartition('::')
    names = [row.get('name', '')]
    aliases = row.get('aliases', [])
    if isinstance(aliases, list):
        names += aliases[:128]
    found = {}
    for spelling in names:
        if not isinstance(spelling, str) or len(spelling) > 4096:
            continue
        match = _METHOD.fullmatch(spelling)
        if match:
            kind, class_name, selector = match.groups()
        elif (namespace and short_name and len(namespace) < 2048 and
              spelling in (f'-[{namespace}_{short_name}]', f'+[{namespace}_{short_name}]')):
            kind, class_name, selector = spelling[0], namespace, short_name
        else:
            continue
        if not _SELECTOR.fullmatch(selector) or (':' in selector and not selector.endswith(':')):
            continue
        key = (kind, class_name, selector)
        found[key] = {'class': class_name, 'selector': selector,
                      'method_kind': 'instance' if kind == '-' else 'class',
                      'implementation': address,
                      'source': 'ghidra_objective_c_symbol',
                      'symbol': spelling, 'classification': 'computed',
                      'runtime_dispatch': 'not established'}
    return [found[key] for key in sorted(found)]
