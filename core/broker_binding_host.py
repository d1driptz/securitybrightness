"""Inactive process-owned binding/retirement host. No reads or delivery."""
from dataclasses import asdict
import hashlib
import hmac
import math
import os
import secrets
import time
from . import broker_transport as transport
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_review_host import BrokerReviewHost, BrokerReviewHostError
from .broker_live_review import LiveBrokerReview, RetiredMappedReview
from .broker_acquisition_draft import AcquisitionDraft
from .broker_binding_protocol import AcquisitionBindingExchange
from .broker_process import _BindingMetadataChild, BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .json_input import loads


class BrokerBindingHost(BrokerReviewHost):
    """Separate opt-in five-second diagnostic, not the verified desktop host.

    Inherits only operator queuing/cancellation/status semantics. One worker owns
    the fixed child. ALLOW ONCE reserves evidence, binds native metadata and retires
    it; DENY kills/joins the child without issuing a reservation. Neither reads.
    close signals cancellation; the caller must join its worker.
    """
    def __init__(self, registry, ledger, *, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_binding_host_lifetime')
        super().__init__(registry, ledger, timeout=timeout)

    def _run(self, app, credential, proposal, draft_id, revision):
        with self._condition:
            if self._started or self._cancel.is_set():
                self.close()
                if not self._started:
                    self._cleanup_confirmed = self._finished = True
                raise BrokerReviewHostError('host_unavailable')
            self._started = True
            self._deadline = time.monotonic()+self._timeout
        child = model = acquisition = wire = token = None
        acquired = False
        cleanup_ok = True
        result = None
        try:
            self._check()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            model = LiveBrokerReview(self._registry, self._ledger, key=key, session=session, timeout=self._timeout)
            first = model.coordinator.begin(app, credential, proposal, draft_id, revision)
            acquired = transport._slot.acquire(blocking=False)
            if not acquired: raise BrokerReviewHostError('busy_or_unavailable')
            self._check()
            child = _BindingMetadataChild()

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
            if answer == 'DENY':
                # No reservation or binding command may be minted from DENY.
                child.close(); child = None
                with model._lock:
                    model._current('recorded')
                    result = RetiredMappedReview(model._facts_snapshot, 'deny')
            else:
                acquisition = AcquisitionDraft(model)
                token = acquisition.coordinator.reserve()
                wire = AcquisitionBindingExchange(role='coordinator', key=key, session=session,
                                                   timeout=self._timeout)
                message = dict(context=loads(token.canonical_context), display_digest=token.display_digest)
                digest = hashlib.sha256(_canonical(message)).hexdigest()
                write(wire.send(message))
                wire.receive(frame())
                with model._lock:
                    acquisition._live('acquisition_reserved')
                write(wire.send(dict(action='retire', binding_digest=digest)))
                child.close_input()
                retirement = frame()  # Do not consume until EOF, exit and cleanup.
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
                wire.receive(retirement)
                acquisition.adapter.consume(token, app, credential, proposal)
                result = RetiredMappedReview(model._facts_snapshot, 'allow_once')
        except BrokerProcessError as exc:
            if str(exc) == 'process_cleanup_failed': cleanup_ok = False
            raise BrokerReviewHostError('process_failed') from None
        except Exception:
            raise BrokerReviewHostError('binding_session_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally:
                    try:
                        if wire is not None: wire.close()
                    finally:
                        if acquisition is not None: acquisition.close()
                        elif model is not None: model.close()
            except BaseException:
                cleanup_ok = False
                raise BrokerReviewHostError('cleanup_failed') from None
            finally:
                if acquired and cleanup_ok: transport._slot.release()
                with self._condition:
                    self._cleanup_confirmed = cleanup_ok
                    self._finished = True
                    self._display = self._answer = None
                    self._condition.notify_all()
        # Recheck after ALL cleanup, including retirement hooks and slot release.
        # Registry/ledger serialization establishes a metadata-return boundary,
        # not authority for any later operation. Cancellation also serializes here.
        with self._condition, model._lock:
            try:
                self._check()
                with model._lease(), model._ledger._lock:
                    if (model._app_state() != model._app_snapshot or model._draft() != model._draft_snapshot
                            or proposal.canonical_bytes() != model._proposal_snapshot
                            or _canonical(asdict(display)) != model._facts_snapshot
                            or time.monotonic() >= model._deadline
                            or (token is not None and not acquisition._matches(token))):
                        raise ValueError('changed_after_cleanup')
                    self._check()
                    return result
            except Exception:
                raise BrokerReviewHostError('stale_binding_retirement') from None
