"""Bounded, owned syntax worker and content-checked committed index snapshots."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

from .js_syntax import NODE_LIMIT, SOURCE_LIMIT, parser_identity

STATE_LIMIT = 8 * 1024 * 1024
GENERATION_LIMIT = 64
RSS_LIMIT = 512 * 1024 * 1024


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def checked_read(path, limit=STATE_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Syntax cache exceeds byte budget; preserve it and use a new workspace')
    return raw


def atomic_write(path, raw):
    if path.is_symlink():
        raise ValueError('Syntax cache cannot be a symlink')
    fd, tmp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class SyntaxOwner:
    def __init__(self):
        self.guard = threading.RLock()
        self.process = None
        self.closed = False

    @staticmethod
    def _stop(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=2)

    def close(self):
        with self.guard:
            self.closed = True
            process = self.process
        if process:
            self._stop(process)

    def run(self, config, *, folder, cancelled, wall_seconds=15.0):
        started, peak = time.monotonic(), 0
        with tempfile.TemporaryFile(dir=folder) as output, tempfile.TemporaryFile(dir=folder) as errors:
            with self.guard:
                if self.closed:
                    raise RuntimeError('Syntax owner is closed')
                if self.process:
                    raise RuntimeError('Another syntax worker is active')
                process = subprocess.Popen([sys.executable, '-X', 'faulthandler', '-m', 'eaos.js_worker'],
                    stdin=subprocess.PIPE, stdout=output, stderr=errors,
                    start_new_session=True, close_fds=True)
                self.process = process
            try:
                process.stdin.write(encoded(config))
                process.stdin.close()
                while process.poll() is None:
                    if cancelled and cancelled():
                        raise InterruptedError('JavaScript inspection cancelled; committed index preserved')
                    if time.monotonic() - started >= wall_seconds:
                        raise TimeoutError('JavaScript worker wall-time budget; committed index preserved')
                    # A sampled RSS guard, not a false hard address-space promise.
                    probe = subprocess.run(['ps', '-o', 'rss=', '-p', str(process.pid)],
                                           capture_output=True, timeout=.5, check=False)
                    if process.poll() is None:
                        raw_rss = probe.stdout.strip()
                        if not raw_rss.isdigit():
                            raise RuntimeError('Cannot monitor syntax worker RSS; worker stopped')
                        rss = int(raw_rss) * 1024
                        peak = max(peak, rss)
                        if rss > RSS_LIMIT:
                            raise MemoryError('JavaScript worker exceeded sampled RSS budget')
                    time.sleep(.02)
                if cancelled and cancelled():
                    raise InterruptedError('JavaScript inspection cancelled; committed index preserved')
                if process.returncode:
                    errors.seek(0)
                    detail = errors.read(2048).decode('utf-8', errors='replace')
                    raise RuntimeError(f'JavaScript syntax worker failed ({process.returncode}): {detail}')
                output.seek(0)
                raw = output.read(STATE_LIMIT + 1)
                if len(raw) > STATE_LIMIT:
                    raise ValueError('JavaScript syntax output exceeds byte budget')
                result = json.loads(raw)
                if result['peak_rss_bytes'] > RSS_LIMIT:
                    raise MemoryError('JavaScript worker peak RSS exceeded budget; index not committed')
                result['resource_limits'] = {
                    'cpu_seconds': 10, 'wall_seconds': wall_seconds,
                    'output_bytes': STATE_LIMIT, 'source_bytes': SOURCE_LIMIT,
                    'rss_guard': 'sampled ps RSS; overshoot between samples is possible',
                    'rss_limit_bytes': RSS_LIMIT,
                    'observed_peak_rss_bytes': max(peak, result['peak_rss_bytes'])}
                return result
            finally:
                self._stop(process)
                with self.guard:
                    if self.process is process:
                        self.process = None


def inspect_index(owner, capture, folder, *, offset=0, limit=30, view=None,
                  index_cursor=None, find='', cancelled=None, max_nodes=NODE_LIMIT,
                  batch_seconds=2.0, wall_seconds=15.0):
    context = {key: capture[key] for key in ('application_snapshot', 'component_id', 'sha256')}
    context['parser'] = parser_identity()
    identity = digest(context)
    folder = Path(folder)
    current = folder / 'current.json'
    lock_fd = os.open(folder / 'owner.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another syntax index operation owns this component') from exc
        state, state_path, state_sha = None, None, None
        if current.exists() or current.is_symlink():
            pointer = json.loads(checked_read(current, 1024))
            state_sha = pointer['sha256']
            if not isinstance(state_sha, str) or re.fullmatch('[a-f0-9]{64}', state_sha) is None:
                raise ValueError('Malformed syntax snapshot; use a new workspace, preserving evidence')
            state_path = folder / ('state-' + state_sha + '.json')
            raw = checked_read(state_path)
            if hashlib.sha256(raw).hexdigest() != state_sha:
                raise ValueError('Syntax snapshot hash mismatch; preserve cache and reopen in a new workspace')
            state = json.loads(raw)
            if state['identity'] != identity or state['context'] != context:
                raise ValueError('Incompatible syntax index identity; use a new workspace')
        generation = state['generation'] if state else 0
        cursor = f'js1:{identity}:{generation}:{state_sha or "initial"}'
        if index_cursor is not None:
            if offset or view is not None:
                raise ValueError('index_cursor expands the index; use view+offset only for result pagination')
            if state is None or index_cursor != cursor:
                raise ValueError('Stale/incompatible index_cursor; request offset=0 without a cursor for current coverage')
            if not state['progress']['indexing_possible']:
                raise ValueError('Syntax indexing cannot continue; inspect coverage stopping_reason')
        elif state is None and (offset or view is not None):
            raise ValueError('Stale/missing JavaScript view; request offset=0 without view')
        if state is None or index_cursor is not None:
            if cancelled and cancelled():
                raise InterruptedError('JavaScript indexing cancelled before worker startup')
            snapshots = list(folder.glob('state-*.json'))
            if len(snapshots) >= GENERATION_LIMIT or sum(p.stat().st_size for p in snapshots) >= GENERATION_LIMIT * STATE_LIMIT:
                raise ValueError('Syntax snapshot storage budget reached; preserve evidence and use a new workspace')
            if generation >= GENERATION_LIMIT:
                raise ValueError('Syntax snapshot storage budget reached; preserve evidence and use a new workspace')
            result = owner.run({'capture': capture['path'], 'sha256': capture['sha256'],
                                'state': str(state_path) if state_path else None,
                                'state_sha256': state_sha, 'max_nodes': max_nodes,
                                'batch_seconds': batch_seconds}, folder=folder,
                               cancelled=cancelled, wall_seconds=wall_seconds)
            next_state = {'identity': identity, 'context': context, 'generation': generation + 1,
                          'progress': result['progress'], 'resource_limits': result['resource_limits']}
            raw = encoded(next_state)
            if len(raw) > STATE_LIMIT:
                raise ValueError('Syntax snapshot exceeds storage budget; committed progress preserved')
            if cancelled and cancelled():
                raise InterruptedError('JavaScript indexing cancelled; committed progress preserved')
            state_sha = hashlib.sha256(raw).hexdigest()
            state_path = folder / ('state-' + state_sha + '.json')
            if state_path.exists():
                if checked_read(state_path) != raw:
                    raise ValueError('Syntax snapshot identity conflict')
            else:
                atomic_write(state_path, raw)
                state_path.chmod(0o444)
            # Snapshot is committed first. Cancellation before this atomic pointer
            # leaves valid previous progress; an unused immutable snapshot is safe.
            if cancelled and cancelled():
                raise InterruptedError('JavaScript indexing cancelled; committed progress preserved')
            atomic_write(current, encoded({'sha256': state_sha}))
            state = next_state
        progress = state['progress']
        expected = digest({'index': state_sha, 'find': find})
        if (view is not None and view != expected) or (offset and view is None):
            raise ValueError('Stale/missing JavaScript view; index expanded or query changed. Request offset=0 without view')
        rows = [row for row in progress['observations'] if find.casefold() in
                json.dumps(row, ensure_ascii=False).casefold()]
        cursor = f'js1:{identity}:{state["generation"]}:{state_sha}'
        possible = progress['indexing_possible'] and state['generation'] < GENERATION_LIMIT
        coverage = {'complete': False, 'scope': 'supported syntax occurrences among visited named nodes',
                    'coherent_source_bytes': Path(capture['path']).stat().st_size,
                    'nodes_indexed': progress['nodes_indexed'], 'nodes_available': None,
                    'nodes_available_reason': 'not counted; that would require a full traversal',
                    'syntax_tree_traversal_complete': progress['traversal_complete'],
                    'tree_has_parse_errors': progress['tree_has_errors'],
                    'observed_named_error_count': progress['error_count'], 'unparsed': progress['errors'],
                    'error_ranges_truncated': progress['error_count'] > len(progress['errors']),
                    'stopping_reason': progress['stopping_reason'] if state['generation'] < GENERATION_LIMIT else 'snapshot_storage_budget',
                    'last_batch_nodes': progress['batch_nodes'], 'further_indexing_possible': possible,
                    'index_cursor': cursor if possible else None,
                    'next_index_request': 'inspect_javascript with component_id and index_cursor; discard old result views' if possible else None,
                    'semantic_analysis_complete': False}
        return {'classification': 'computed', 'application_snapshot': capture['application_snapshot'],
                'component_id': capture['component_id'], 'source_sha256': capture['sha256'],
                'source_bytes': coverage['coherent_source_bytes'], 'parser': context['parser'],
                'grammar_abi': progress['grammar_abi'], 'index_revision': state_sha,
                'view': expected, 'observations': rows[offset:offset+limit], 'matches': len(rows),
                'match_scope': 'committed supported syntax observations only; not all program behavior',
                'next_offset': offset+limit if offset+limit < len(rows) else None,
                'coverage': coverage, 'resource_limits': state['resource_limits'],
                'limitations': ['No target code is executed. The whole captured source is parsed coherently.',
                    'Bindings, modules, control flow and runtime IPC relationships are not established.',
                    'Errors, unsupported constructs and unvisited syntax may hide observations; absence is not proof.',
                    'Index expansion invalidates result views; earlier evidence remains unchanged.']}
    finally:
        os.close(lock_fd)
