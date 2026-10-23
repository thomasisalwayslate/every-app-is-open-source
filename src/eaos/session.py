"""One native owner, independent status receiver, bounded requests and cancellation."""
from __future__ import annotations

import json
import multiprocessing
import os
import signal
import threading
import time

from .backend import ProgramBusyError
from .contracts import validate_arguments, validate_search_profile


def _worker(backend, connection, owner_pid):
    def emit(message):
        connection.send_bytes(json.dumps(message, ensure_ascii=False).encode())
    if os.name == 'posix':
        os.setsid()
        def watch_owner():
            while os.getppid() == owner_pid:
                time.sleep(0.5)
            os.killpg(os.getpid(), signal.SIGTERM)
        threading.Thread(target=watch_owner, daemon=True).start()
    try:
        backend.on_stage = lambda stage: emit({'kind':'stage','stage':stage,'at':time.monotonic(),
                                               'coverage':backend.coverage()})
        backend._load()
        emit({'kind':'ready','coverage':backend.coverage()})
        while True:
            request = connection.recv()
            if request is None:
                break
            sequence, name, arguments = request
            try:
                value = getattr(backend, name)(**arguments)
                emit({'kind':'result','id':sequence,'value':value,'coverage':backend.coverage()})
            except Exception as error:
                emit({'kind':'error','id':sequence,'error':str(error),'coverage':backend.coverage()})
    except (EOFError, BrokenPipeError):
        pass
    except BaseException as error:
        try:
            emit({'kind':'failed','error':str(error),'retryable':isinstance(error,ProgramBusyError)})
        except (EOFError, OSError):
            pass
    finally:
        backend.close()
        connection.close()


class AnalysisUnavailable(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(status.get('error') or 'Native work is pending; open_program reports status.')


class McpSession:
    def __init__(self, backend, initial_wait=5.0, request_timeout=120.0, analysis_timeout=3600.0):
        if not 0.05 <= request_timeout <= 7200 or not 0.05 <= analysis_timeout <= 7200:
            raise ValueError('Native timeouts must be between 0.05 and 7200 seconds')
        self.backend, self.initial_wait = backend, initial_wait
        self.request_timeout, self.analysis_timeout = request_timeout, analysis_timeout
        self.process = self.connection = None
        self.stopping_process = self.shutdown_thread = None
        self.started = self.stage_started = self.finished = None
        self.state = self.stage = 'not_started'
        self.error = None
        self.retryable = self.closed = False
        self.coverage = backend.coverage()
        self.active = None
        self.initializer = None
        self.cancelled_requests = set()
        self.sequence = self.generation = 0
        self.responses = {}
        self.condition = threading.Condition(threading.RLock())
        self.control = threading.RLock()

    def _listen(self, connection, generation):
        try:
            while True:
                message = json.loads(connection.recv_bytes())
                with self.condition:
                    if generation != self.generation:
                        return
                    if self.state in ('cancelling','cancelled'):
                        continue
                    kind = message['kind']
                    if kind == 'stage':
                        self.stage, self.stage_started = message['stage'], message['at']
                    elif kind == 'ready':
                        self.state = self.stage = 'ready'
                        self.initializer = None
                        self.finished = self.stage_started = time.monotonic()
                    elif kind == 'failed':
                        self.state, self.error = 'failed', message['error']
                        self.retryable = message.get('retryable',False)
                        self.finished = time.monotonic()
                    elif kind in ('result','error'):
                        self.responses[message['id']] = message
                        self.active = None
                        self.stage, self.stage_started = 'ready', time.monotonic()
                    if 'coverage' in message:
                        self.coverage = message['coverage']
                    self.condition.notify_all()
        except (EOFError, OSError, ValueError):
            with self.condition:
                if generation == self.generation and self.state != 'failed':
                    self.state, self.error = 'failed', 'Analysis worker exited before returning a result.'
                    self.finished = time.monotonic()
                    self.condition.notify_all()

    def _watch_deadlines(self, generation):
        while True:
            with self.condition:
                if generation != self.generation or self.closed or self.state in ('failed','cancelling','cancelled'):
                    return
                now = time.monotonic()
                reason = None
                if self.state == 'running' and now-self.started >= self.analysis_timeout:
                    reason = 'Initial analysis deadline exceeded; work stopped, evidence preserved.'
                if self.active and now-self.active['started'] >= self.request_timeout:
                    reason = 'Native request deadline exceeded; work stopped, evidence preserved.'
                sequence = self.active['id'] if self.active else None
            if reason:
                self.cancel(reason=reason, generation=generation, sequence=sequence)
                return
            time.sleep(0.05)

    def _start(self):
        with self.condition:
            self.error, self.finished, self.retryable = None, None, False
            self.started = self.stage_started = time.monotonic()
            self.state, self.stage = 'running','starting'
            context = multiprocessing.get_context('spawn')
            self.connection, child = context.Pipe()
            self.process = context.Process(target=_worker,args=(self.backend,child,os.getpid()),name='eaos-analysis')
            generation = self.generation
            try:
                self.process.start()
            except Exception as error:
                self.state,self.error = 'failed',str(error)
                self.connection.close()
                self.process = self.connection = None
            finally:
                child.close()
            if self.connection is not None:
                threading.Thread(target=self._listen,args=(self.connection,generation),daemon=True).start()
                threading.Thread(target=self._watch_deadlines,args=(generation,),daemon=True).start()

    def status(self):
        with self.condition:
            now = time.monotonic()
            worker = self.process or self.stopping_process
            result = {'state':self.state,'stage':self.stage,
                'elapsed_seconds':round((self.finished or now)-self.started,1) if self.started else 0,
                'stage_elapsed_seconds':round(now-self.stage_started,1) if self.stage_started else 0,
                'worker_alive':worker is not None and worker.is_alive(),
                'sha256':self.backend.digest,'profile':self.backend.analysis_mode,'coverage':self.coverage}
            if self.active:
                result['operation'] = {'tool':self.active['name'],
                    'elapsed_seconds':round(now-self.active['started'],1),'deadline_seconds':self.request_timeout}
            if self.error:
                result['error'] = self.error
            return result

    def _status_result(self):
        return {'classification':'fact','scope':'owned-process status; no program completeness claim',
                'data':{'analysis':self.status()},
                'limitations':['Elapsed time does not establish forward progress or time remaining.',
                               'Quick analysis and missing matches/references do not establish absence.']}

    def _ensure_started(self, mode=None, request_id=None):
        started_now = False
        with self.control:
            if self.closed:
                raise RuntimeError('MCP session is closed')
            with self.condition:
                if self.state in ('cancelling','cancelled'):
                    raise AnalysisUnavailable(self.status())
            if mode is not None and mode != self.backend.analysis_mode:
                with self.condition:
                    if self.active:
                        raise AnalysisUnavailable(self.status())
                self._stop_worker()
                with self.condition:
                    if self.state in ('cancelling','cancelled'):
                        raise AnalysisUnavailable(self.status())
                    self.backend._set_profile(mode)
                    self.coverage = self.backend.coverage()
                    self.state = 'not_started'
            with self.condition:
                if self.state in ('cancelling','cancelled'):
                    raise AnalysisUnavailable(self.status())
                if self.state == 'not_started':
                    if request_id in self.cancelled_requests:
                        raise RuntimeError('Request cancelled before native startup')
                    # Initialization ownership and running state become visible
                    # atomically to cancellation notifications.
                    self.initializer = request_id
                    self._start()
                    started_now = True
        with self.condition:
            deadline = time.monotonic()+self.initial_wait
            while started_now and self.state == 'running' and time.monotonic() < deadline:
                self.condition.wait(deadline-time.monotonic())

    def wait_ready(self, mode=None):
        self._ensure_started(mode)
        with self.condition:
            while self.state == 'running':
                self.condition.wait(0.1)
            if self.state != 'ready':
                raise AnalysisUnavailable(self.status())

    def call(self, name, arguments, request_id=None):
        validate_arguments(name,arguments)
        if name=='search':validate_search_profile(arguments,self.backend.analysis_mode)
        if self.closed:
            raise RuntimeError('MCP session is closed')
        with self.condition:
            if request_id is not None and request_id in self.cancelled_requests:
                raise RuntimeError('Request cancelled before execution')
        if name in {'calculate','read_evidence'} or name=='decode_swift_string' and 'words' in arguments:
            return getattr(self.backend,name)(**arguments)
        if name == 'open_program' and arguments.get('cancel'):
            self.cancel()
            return self._status_result()
        with self.condition:
            if self.state == 'cancelling':
                if name == 'open_program':
                    return self._status_result()
                raise AnalysisUnavailable(self.status())
        if name == 'open_program' and self.state=='failed' and self.retryable:
            with self.control:
                self._stop_worker()
                self.state = 'not_started'
        mode = arguments.get('analysis_mode') if name=='open_program' else None
        self._ensure_started(mode,request_id)
        with self.condition:
            if request_id is not None and request_id in self.cancelled_requests:
                raise RuntimeError('Request cancelled before native operation')
            if self.state != 'ready' or self.active:
                if name=='open_program' and self.state not in ('failed','cancelled'):
                    return self._status_result()
                raise AnalysisUnavailable(self.status())
            self.sequence += 1
            sequence = self.sequence
            self.active = {'id':sequence,'request_id':request_id,'name':name,'started':time.monotonic()}
            try:
                self.connection.send((sequence,name,arguments))
            except (BrokenPipeError,OSError):
                self.state,self.error = 'failed','Native worker connection closed'
                self.active = None
                raise AnalysisUnavailable(self.status()) from None
            while sequence not in self.responses and self.state=='ready':
                self.condition.wait(0.1)
            response = self.responses.pop(sequence,None)
            if response is None:
                raise AnalysisUnavailable(self.status())
            if response['kind']=='error':
                raise RuntimeError(response['error'])
            return response['value']

    def cancel_request(self, request_id):
        """Mark cancellation on the reader, reap the owner off the reader.

        The state changes before returning, so no new native work can slip in
        while the owned shutdown thread waits for the worker to exit.
        """
        with self.condition:
            self.cancelled_requests.add(request_id)
            initial = self.state=='running' and self.initializer==request_id
            token = self._begin_cancel(None if initial else request_id)
            if token is None:
                return False
            self.shutdown_thread = threading.Thread(
                target=self._finish_cancel, name='eaos-cancel')
            self.shutdown_thread.start()
            return True

    def forget_request(self, request_id):
        with self.condition:
            self.cancelled_requests.discard(request_id)

    def _begin_cancel(self, request_id=None, reason='Cancelled by client; evidence preserved.', generation=None, sequence=None):
        # Caller holds condition; no process waits or control-lock acquisition.
        if self.closed or self.state in ('cancelling','cancelled'):
            return None
        if generation is not None:
            if generation != self.generation:
                return None
            if sequence is not None and (not self.active or self.active['id'] != sequence):
                return None
            if sequence is None and self.state != 'running':
                return None
        if request_id is not None and (not self.active or self.active['request_id']!=request_id):
            return None
        self.state,self.stage,self.error = 'cancelling','cancelling',reason
        self.retryable = False
        self.condition.notify_all()
        return self.generation

    def _finish_cancel(self):
        with self.control:
            with self.condition:
                # A profile switch may have reaped the old generation while
                # cancellation waited for control. It must still finish; the
                # cancelling gate prevents any replacement owner from starting.
                if self.closed or self.state != 'cancelling':
                    return
            self._stop_worker()
            with self.condition:
                self.state = self.stage = 'cancelled'
                self.finished = time.monotonic()
                self.condition.notify_all()

    def cancel(self, request_id=None, reason='Cancelled by client; evidence preserved.', generation=None, sequence=None):
        with self.condition:
            token = self._begin_cancel(request_id,reason,generation,sequence)
        if token is None:
            return False
        self._finish_cancel()
        return True

    def _stop_worker(self):
        with self.condition:
            self.generation += 1
            process,connection = self.process,self.connection
            self.stopping_process = process
            self.process = self.connection = None
            self.active = None
            self.initializer = None
            self.condition.notify_all()
        if process is not None:
            if process.is_alive():
                try:
                    connection.send(None)
                except (BrokenPipeError,OSError):
                    pass
                process.join(timeout=1)
            if process.is_alive():
                try:
                    if os.name=='posix' and os.getpgid(process.pid)==process.pid:
                        os.killpg(process.pid,signal.SIGTERM)
                    else:
                        process.terminate()
                except ProcessLookupError:
                    pass
                process.join(timeout=3)
            if process.is_alive():
                process.kill()
                process.join()
            with self.condition:
                self.stopping_process = None
                process.close()
        if connection is not None:
            connection.close()

    def close(self):
        with self.control:
            if self.closed:
                return
            self.closed = True
            with self.condition:
                self.state,self.error = 'cancelled','Session closed'
                self.condition.notify_all()
            self._stop_worker()
            self.backend.close()
        # Never join while holding control: an accepted cancellation may still
        # be waiting to acquire it. Shutdown threads belong to this session.
        thread = self.shutdown_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
