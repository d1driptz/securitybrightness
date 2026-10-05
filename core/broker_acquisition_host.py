"""Inactive child-owned native fixture acquisition into discard-only quarantine."""
from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import os
import secrets
import time
from . import broker_transport as transport
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_binding_host import BrokerBindingHost
from .broker_review_host import BrokerReviewHostError
from .broker_live_review import LiveBrokerReview
from .broker_acquisition_draft import AcquisitionDraft
from .broker_acquisition_lifecycle import LiveAcquisitionLifecycle, PublicationCheckResult
from .broker_process import _AcquisitionDiscardChild, BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical


@dataclass(frozen=True)
class RetiredNativeAcquisitionCheck:
    canonical_display: bytes = field(repr=False)
    decision: str
    staged_bytes: int
    staged_digest: str
    released_bytes: int = field(default=0, init=False)
    lifecycle: str = field(default='retired', init=False)
    meaning: str = field(default='native fixture diagnostic; no delivery or later-operation permission', init=False)
    def __bool__(self): raise TypeError('A retired acquisition check is not permission')


class BrokerAcquisitionDiscardHost(BrokerBindingHost):
    """Separate diagnostic; no existing owner UI, /check or v1 route selects it.

    Five-second total budget. Trusted operator/worker ports are inherited; one
    worker owns all keys, process I/O, quarantine and cleanup. close cancels; caller
    must join the worker. Native bytes never appear in the returned metadata.
    """
    def _run(self, app, credential, proposal, draft_id, revision):
        with self._condition:
            if self._started or self._cancel.is_set():
                self.close()
                if not self._started: self._cleanup_confirmed = self._finished = True
                raise BrokerReviewHostError('host_unavailable')
            self._started = True
            self._deadline = time.monotonic()+self._timeout
        child = model = lifecycle = None
        acquired = False
        cleanup_ok = True
        result = None
        try:
            self._check()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            model = LiveBrokerReview(self._registry, self._ledger, key=key, session=session, timeout=self._timeout)
            lifecycle = LiveAcquisitionLifecycle(AcquisitionDraft(model))
            first = model.coordinator.begin(app, credential, proposal, draft_id, revision)
            acquired = transport._slot.acquire(blocking=False)
            if not acquired: raise BrokerReviewHostError('busy_or_unavailable')
            self._check()
            child = _AcquisitionDiscardChild()

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
                child.close(); child = None
                with model._lock:
                    model._current('recorded')
                    result = RetiredNativeAcquisitionCheck(model._facts_snapshot, 'deny', 0,
                                                          hashlib.sha256(b'').hexdigest())
            else:
                token = lifecycle.coordinator.reserve()
                write(lifecycle.adapter.begin(token, app, credential, proposal))
                summary = lifecycle.adapter.stage(frame())
                write(lifecycle.adapter.retire())  # Quarantine cleared before native cleanup.
                child.close_input()
                ack = frame()  # Keep ack private until EOF, exit and cleanup.
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
                lifecycle.adapter.confirm_retirement(ack)
                checked = lifecycle.coordinator.check_publication(app, credential, proposal)
                summary_values = lifecycle._summary_snapshot
                if (type(checked) is not PublicationCheckResult
                        or type(checked.binding_digest) is not str
                        or checked.binding_digest != summary_values[0][1]
                        or type(checked.staged_digest) is not str
                        or checked.staged_digest != summary_values[1][1]
                        or type(checked.staged_bytes) is not int
                        or checked.staged_bytes != summary_values[2][1]
                        or type(checked.released_bytes) is not int or checked.released_bytes != 0
                        or type(checked.disposition) is not str or checked.disposition != 'eligible_discarded'):
                    raise ValueError('changed_publication_check')
                result = RetiredNativeAcquisitionCheck(model._facts_snapshot, 'allow_once',
                                                       checked.staged_bytes, checked.staged_digest)
        except BrokerProcessError as exc:
            if str(exc) == 'process_cleanup_failed': cleanup_ok = False
            raise BrokerReviewHostError('process_failed') from None
        except Exception:
            raise BrokerReviewHostError('acquisition_session_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally:
                    if lifecycle is not None: lifecycle._shutdown()
                    elif model is not None: model.close()
            except BaseException:
                cleanup_ok = False
                raise BrokerReviewHostError('cleanup_failed') from None
            finally:
                try:
                    if acquired and cleanup_ok: transport._slot.release()
                except BaseException:
                    cleanup_ok = False
                    raise BrokerReviewHostError('cleanup_failed') from None
                finally:
                    with self._condition:
                        self._cleanup_confirmed = cleanup_ok
                        self._finished = True
                        self._display = self._answer = None
                        self._condition.notify_all()
        # All cleanup, including slot release, precedes the metadata-return fence.
        with self._condition, lifecycle._lock, lifecycle._acquisition._lock, model._lock:
            try:
                self._check()
                with model._lease(), model._ledger._lock:
                    if (lifecycle._cancelled or model._app_state() != model._app_snapshot
                            or model._draft() != model._draft_snapshot
                            or _canonical(asdict(model._ticket)) != model._ticket_snapshot
                            or type(proposal) is not type(model._proposal)
                            or proposal.canonical_bytes() != model._proposal_snapshot
                            or model._proposal.canonical_bytes() != model._proposal_snapshot
                            or model._shown is not display or model._facts is not display
                            or _canonical(asdict(display)) != model._facts_snapshot
                            or type(model._decision) is not str
                            or model._decision != ('allow_once' if answer == 'ALLOW ONCE' else 'deny')
                            or model._ledger._reviews.get(model._ticket.review.draft_id) is not None
                            or model._reviews._pending.get(model._ticket.review.draft_id) is not None
                            or time.monotonic() >= model._deadline):
                        raise ValueError('changed_after_cleanup')
                    if answer == 'ALLOW ONCE':
                        if (not lifecycle._acquisition._matches(token)
                                or lifecycle._summary_values() != lifecycle._summary_snapshot
                                or lifecycle._retirement_values() != lifecycle._retirement_snapshot
                                or time.monotonic() >= lifecycle._wire._deadline):
                            raise ValueError('changed_acquisition_evidence')
                    expected_count = lifecycle._summary_snapshot[2][1] if answer == 'ALLOW ONCE' else 0
                    expected_digest = (lifecycle._summary_snapshot[1][1] if answer == 'ALLOW ONCE'
                                       else hashlib.sha256(b'').hexdigest())
                    if (type(result) is not RetiredNativeAcquisitionCheck
                            or type(result.canonical_display) is not bytes
                            or result.canonical_display != model._facts_snapshot
                            or type(result.decision) is not str or result.decision != model._decision
                            or type(result.staged_bytes) is not int or result.staged_bytes != expected_count
                            or type(result.staged_digest) is not str or result.staged_digest != expected_digest
                            or type(result.released_bytes) is not int or result.released_bytes != 0
                            or type(result.lifecycle) is not str or result.lifecycle != 'retired'):
                        raise ValueError('changed_public_result')
                    self._check()
                    return result
            except Exception:
                raise BrokerReviewHostError('stale_acquisition_retirement') from None
