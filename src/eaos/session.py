"""Keep MCP responsive while a single owned process initializes Ghidra.

The child owns all Java objects. It receives the already captured Backend, so
spawning it never reopens the caller's selected path or changes input identity.
"""
from __future__ import annotations

import multiprocessing
import json
import os
import signal
import threading
import time

from .contracts import validate_arguments
from .backend import ProgramBusyError


def _worker(backend, connection, owner_pid):
    def emit(message):
        # Native values (for example JPype integer wrappers) must become plain
        # JSON values here. Unpickling them in the non-JVM parent is unsafe.
        connection.send_bytes(json.dumps(message, ensure_ascii=False).encode())
    if os.name == 'posix':
        os.setsid()
        # SIGKILL cannot run the parent's finally block. Do not leave Java or
        # its helpers running as detached jobs when the owning server dies.
        def watch_owner():
            while os.getppid() == owner_pid:
                time.sleep(0.5)
            os.killpg(os.getpid(), signal.SIGTERM)
        threading.Thread(target=watch_owner, daemon=True).start()
    try:
        backend.on_stage = lambda stage: emit({
            'kind': 'stage', 'stage': stage, 'at': time.monotonic()})
        backend._load()
        emit({'kind': 'ready'})
        while True:
            request = connection.recv()
            if request is None:
                break
            name, arguments = request
            try:
                value = getattr(backend, name)(**arguments)
                emit({'kind': 'result', 'value': value})
            except Exception as error:
                emit({'kind': 'error', 'error': str(error)})
    except (EOFError, BrokenPipeError):
        pass
    except BaseException as error:
        try:
            emit({'kind': 'failed', 'error': str(error),
                  'retryable': isinstance(error, ProgramBusyError)})
        except (EOFError, OSError):
            pass
    finally:
        backend.close()
        connection.close()


class AnalysisUnavailable(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(status.get('error') or
                         'Analysis is still running; check open_program when needed.')


class McpSession:
    """One worker per server; no detached jobs, arbitrary paths or new tools."""

    def __init__(self, backend, initial_wait=5.0):
        self.backend = backend
        self.initial_wait = initial_wait
        self.process = self.connection = None
        self.started = self.stage_started = None
        self.finished = None
        self.stage = 'not_started'
        self.state = 'not_started'
        self.error = None
        self.retryable = False
        self.closed = False

    def _start(self):
        self.error, self.finished, self.retryable = None, None, False
        self.started = self.stage_started = time.monotonic()
        self.state, self.stage = 'running', 'starting'
        context = multiprocessing.get_context('spawn')
        self.connection, child = context.Pipe()
        self.process = context.Process(target=_worker, args=(self.backend, child, os.getpid()),
                                       name='eaos-analysis')
        try:
            self.process.start()
        except Exception as error:
            self.state, self.error = 'failed', str(error)
            self.finished = time.monotonic()
            self.connection.close()
            self.connection = None
            self.process = None
        finally:
            child.close()

    def _receive(self):
        try:
            message = json.loads(self.connection.recv_bytes())
        except (EOFError, OSError):
            self.state = 'failed'
            self.finished = time.monotonic()
            self.error = 'Analysis worker exited before returning a result.'
            return None
        kind = message['kind']
        if kind == 'stage':
            self.stage, self.stage_started = message['stage'], message['at']
        elif kind == 'ready':
            self.state, self.stage = 'ready', 'ready'
            self.finished = self.stage_started = time.monotonic()
        elif kind == 'failed':
            self.state, self.error = 'failed', message['error']
            self.retryable = message.get('retryable', False)
            self.finished = time.monotonic()
        return message

    def _refresh(self):
        if self.connection is not None and self.state != 'failed':
            while self.connection.poll():
                if self._receive() is None or self.state == 'failed':
                    break
        if (self.process is not None and not self.process.is_alive()
                and self.state != 'failed'):
            self.state = 'failed'
            self.finished = time.monotonic()
            self.error = f'Analysis worker exited (code {self.process.exitcode}).'

    def status(self):
        self._refresh()
        now = self.finished or time.monotonic()
        return {
            'state': self.state,
            'stage': self.stage,
            'elapsed_seconds': round(now - self.started, 1) if self.started else 0,
            'stage_elapsed_seconds': round(now - self.stage_started, 1) if self.stage_started else 0,
            'worker_alive': self.process is not None and self.process.is_alive(),
            'sha256': self.backend.digest,
            **({'error': self.error} if self.error else {}),
        }

    def _ensure_started(self):
        if self.state == 'not_started':
            self._start()
            deadline = time.monotonic() + self.initial_wait
            while self.state == 'running' and self.connection is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self.connection.poll(remaining):
                    break
                self._receive()
        self._refresh()

    def call(self, name, arguments):
        validate_arguments(name, arguments)
        if self.closed:
            raise RuntimeError('MCP session is closed')
        # These operations never need Ghidra, even during initial analysis.
        if (name in {'calculate', 'read_evidence'} or
                name == 'decode_swift_string' and 'words' in arguments):
            return getattr(self.backend, name)(**arguments)
        # Retry only an explicit open request after transient lock contention.
        # Status checks and other failures must not create a restart loop.
        if name == 'open_program':
            self._refresh()
            if self.state == 'failed' and self.retryable:
                self._stop_worker()
                self.state = self.stage = 'not_started'
        self._ensure_started()
        if self.state != 'ready':
            status = self.status()
            if name != 'open_program' or self.state == 'failed':
                raise AnalysisUnavailable(status)
            return {'classification': 'fact', 'scope': 'analysis status; no program result',
                    'data': {'analysis': status}, 'limitations': [
                        'Elapsed time and a live worker do not establish forward progress or time remaining.',
                        'Check open_program when asked; do not poll continuously. Analysis stops when this server closes.',
                    ]}
        try:
            self.connection.send((name, arguments))
        except (BrokenPipeError, OSError) as error:
            self.state, self.error = 'failed', str(error)
            raise AnalysisUnavailable(self.status()) from None
        while True:
            message = self._receive()
            if message is None or self.state == 'failed':
                raise AnalysisUnavailable(self.status())
            if message['kind'] == 'error':
                raise RuntimeError(message['error'])
            if message['kind'] == 'result':
                return message['value']

    def _stop_worker(self):
        if self.process is not None:
            if self.process.is_alive():
                try:
                    self.connection.send(None)
                except (BrokenPipeError, OSError):
                    pass
                self.process.join(timeout=1)
            if self.process.is_alive():
                # End the owned group (including transient native helpers),
                # never another session or the caller's installed application.
                try:
                    if os.name == 'posix' and os.getpgid(self.process.pid) == self.process.pid:
                        os.killpg(self.process.pid, signal.SIGTERM)
                    else:
                        self.process.terminate()
                except ProcessLookupError:
                    pass
                self.process.join(timeout=3)
            if self.process.is_alive():
                self.process.kill()
                self.process.join()
            self.process.close()
            self.process = None
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._stop_worker()
        self.backend.close()
