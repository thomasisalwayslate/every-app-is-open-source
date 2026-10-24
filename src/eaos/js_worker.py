"""Owned subprocess entry point. Parse captured bytes; never execute their code."""
from __future__ import annotations

import hashlib
import json
import os
import resource
import sys
from pathlib import Path


def main():
    # OS-enforced CPU/output/core limits. RSS is sampled/enforced by the owner;
    # RLIMIT_AS is deliberately not advertised as a reliable macOS RSS bound.
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    from .js_syntax import SOURCE_LIMIT, parse_batch
    config = json.loads(sys.stdin.buffer.read(8193))
    path = Path(config['capture'])
    with path.open('rb') as stream:
        raw = stream.read(SOURCE_LIMIT + 1)
    if len(raw) > SOURCE_LIMIT or hashlib.sha256(raw).hexdigest() != config['sha256']:
        raise ValueError('Captured JavaScript identity/size mismatch')
    previous = None
    if config.get('state'):
        state_path = Path(config['state'])
        if state_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Syntax state exceeds budget')
        payload = state_path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != config['state_sha256']:
            raise ValueError('Committed syntax state changed')
        previous = json.loads(payload)['progress']
    progress = parse_batch(raw, previous, max_nodes=config['max_nodes'],
                           max_seconds=config['batch_seconds'])
    result = {'progress': progress, 'worker_pid': os.getpid(),
              'peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss *
                                (1 if sys.platform == 'darwin' else 1024)}
    sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
