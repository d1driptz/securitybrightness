"""Opt-in process-owned metadata review. No desktop, HTTP, read or delivery API."""
from dataclasses import asdict
import hmac
import math
import os
import secrets
import threading
import time
from . import broker_transport as transport
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_live_review import LiveBrokerReview
from .broker_operator_handoff import OperatorResponseQueued
from .broker_pending_review import PendingDisplay
from .broker_process import _ReviewWaitChild, BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .broker_review_profile import _ReviewWaitExchange
from .registry import ApplicationRegistry
from .file_read_review import FileReadReviewLedger


class BrokerReviewHostError(RuntimeError):
    pass


class _ReviewWaitMapping(LiveBrokerReview):
    _max_timeout = 30
    _exchange_type = _ReviewWaitExchange


class _WorkerPort:
    def __init__(self, host): self._host = host
    def run(self, app, credential, proposal, draft_id, revision):
        return self._host._run(app, credential, proposal, draft_id, revision)


class _OperatorPort:
    def __init__(self, host): self._host = host
    def pending(self): return self._host._pending()
    def respond(self, display, answer): return self._host._respond(display, answer)
    def cancel(self): self._host.close()


class BrokerReviewHost:
    """One worker owns one fixed child and all I/O/cleanup; operator only queues.

    Fixed total budget <=30s, including startup, review, retirement and cleanup.
    close() signals cancellation; the caller must join its worker to confirm cleanup.
    No caller-supplied executable, pipe, key, observation, callback or operation.
    Operator port possession is trusted-local bootstrap, not person authentication.
    """
    def __init__(self, registry, ledger, *, timeout=30):
        if type(registry) is not ApplicationRegistry or type(ledger) is not FileReadReviewLedger:
            raise TypeError('expected registry and ledger')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError('invalid_host_lifetime')
        self._registry, self._ledger, self._timeout = registry, ledger, timeout
        self._condition = threading.Condition()
        self._cancel = threading.Event()
        self._started = self._finished = False
        self._display = self._answer = None
        self.worker, self.operator = _WorkerPort(self), _OperatorPort(self)

    def _check(self):
        if self._cancel.is_set() or time.monotonic() >= self._deadline:
            raise BrokerReviewHostError('cancelled_or_expired')

    def _pending(self):
        with self._condition:
            if not self._started or self._finished or self._display is None or self._answer is not None:
                return ()
            try:
                self._check()
                if _canonical(asdict(self._display)) != self._snapshot:
                    raise BrokerReviewHostError('changed_display')
                return (self._display,)
            except Exception:
                self.close()
                return ()

    def _respond(self, display, answer):
        with self._condition:
            try:
                if not self._started: raise BrokerReviewHostError('no_request')
                self._check()
                if (self._finished or self._answer is not None or type(display) is not PendingDisplay
                        or display is not self._display or _canonical(asdict(display)) != self._snapshot
                        or type(answer) is not str or answer not in {'ALLOW ONCE', 'DENY'}):
                    raise BrokerReviewHostError('invalid_response')
                self._answer = answer
                self._condition.notify_all()
                return OperatorResponseQueued()
            except Exception:
                self.close()
                raise BrokerReviewHostError('response_rejected') from None

    def close(self):
        with self._condition:
            self._cancel.set()
            self._condition.notify_all()

    def _run(self, app, credential, proposal, draft_id, revision):
        with self._condition:
            if self._started or self._cancel.is_set():
                self.close()
                raise BrokerReviewHostError('host_unavailable')
            self._started = True
            self._deadline = time.monotonic()+self._timeout
        child = model = None
        acquired = False
        cleanup_ok = True
        result = None
        try:
            self._check()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            model = _ReviewWaitMapping(self._registry, self._ledger, key=key, session=session, timeout=self._timeout)
            first = model.coordinator.begin(app, credential, proposal, draft_id, revision)
            acquired = transport._slot.acquire(blocking=False)
            if not acquired: raise BrokerReviewHostError('busy_or_unavailable')
            self._check()
            child = _ReviewWaitChild()

            def write(data):
                offset = 0
                while offset < len(data):
                    self._check()
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if count <= 0: raise BrokerReviewHostError('pipe_failed')
                        offset += count
                    except BlockingIOError: time.sleep(.002)

            def read(size):
                output = bytearray()
                while len(output) < size:
                    self._check()
                    try:
                        chunk = os.read(child.stdout_fd, size-len(output))
                        if not chunk: raise BrokerReviewHostError('truncated_output')
                        output.extend(chunk)
                    except BlockingIOError: time.sleep(.002)
                return bytes(output)

            def frame():
                prefix = read(4); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32: raise BrokerReviewHostError('output_limit')
                return prefix+read(size)

            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, child.pid)):
                raise BrokerReviewHostError('startup_rejected')
            write(first)
            model.coordinator.observe(frame())
            display = model.operator.display()
            with self._condition:
                self._check()
                self._display, self._snapshot = display, _canonical(asdict(display))
                self._condition.notify_all()
                while self._answer is None:
                    self._check()
                    if child.poll() is not None: raise BrokerReviewHostError('child_exited')
                    self._condition.wait(.01)
                self._check()
                answer = self._answer
            model.operator.record(display, answer)
            write(model.coordinator.finish())
            child.close_input()
            retirement = frame()  # Withhold even metadata evidence until clean exit/cleanup.
            while True:
                self._check()
                try:
                    if os.read(child.stdout_fd, 1): raise BrokerReviewHostError('trailing_output')
                    break
                except BlockingIOError: time.sleep(.002)
            while child.poll() is None:
                self._check(); time.sleep(.002)
            if child.poll() != 0: raise BrokerReviewHostError('child_failed')
            child.close(); child = None
            self._check()
            result = model.coordinator.retire(retirement)
            model = None  # retire already closed it and checked final authority.
        except BrokerProcessError as exc:
            if str(exc) == 'process_cleanup_failed': cleanup_ok = False
            raise BrokerReviewHostError('process_failed') from None
        except Exception:
            raise BrokerReviewHostError('review_session_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally:
                    if model is not None: model.close()
            except BaseException:
                cleanup_ok = False
                raise BrokerReviewHostError('cleanup_failed') from None
            finally:
                if acquired and cleanup_ok: transport._slot.release()
                with self._condition:
                    self._finished = True
                    self._display = self._answer = None
                    self._condition.notify_all()
        # Final cancellation/expiry fence includes all cleanup, even after metadata
        # retirement. The receipt is still not an operation or delivery permission.
        with self._condition:
            self._check()
            return result
