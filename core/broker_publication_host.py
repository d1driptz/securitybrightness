"""Inactive child cleanup with retained quarantine and a terminal dry-run check."""
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
from .broker_publication_lifecycle import LivePublicationDraft, FinalPublicationDraftCheck
from .broker_publication_protocol import PublicationCheckExchange, RetiredForCheckReceipt, _publication_binding
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .broker_quarantine import QuarantineSummary
from .broker_process import _PublicationCheckChild, BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .json_input import loads


@dataclass(frozen=True)
class RetiredNativePublicationCheck:
    canonical_display: bytes = field(repr=False)
    decision: str
    binding_digest: str
    recipient_digest: str
    staged_bytes: int
    staged_digest: str
    released_bytes: int = field(default=0, init=False)
    lifecycle: str = field(default='retired', init=False)
    meaning: str = field(default='Inactive native fixture final check; no delivery or later-operation permission.', init=False)
    def __bool__(self): raise TypeError('A retired publication check is not permission')


def _result_values(value):
    # The display is immutable bytes; snapshot typed values without attempting
    # to serialize those bytes as JSON or exposing transport/data contents.
    return tuple((name, type(item), item) for name, item in asdict(value).items())


class BrokerPublicationDiscardHost(BrokerBindingHost):
    """Fixed private child diagnostic, never selected by an existing product route.

    Trusted bootstrap creates one logical recipient owner. Its descriptor is not
    an authenticated recipient channel. The coordinator retains bytes until
    native cleanup, exact EOF, zero exit and child cleanup, then the final check
    discards them. The only public result is terminal metadata with zero release.
    """
    def _run(self, app, credential, proposal, draft_id, revision):
        with self._condition:
            if self._started or self._cancel.is_set():
                self.close()
                if not self._started: self._cleanup_confirmed = self._finished = True
                raise BrokerReviewHostError('host_unavailable')
            self._started = True
            self._deadline = time.monotonic()+self._timeout
            host_deadline = self._deadline
        child = model = lifecycle = recipient = token = None
        acquired = False
        cleanup_ok = True
        result = None
        try:
            self._check()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            model = LiveBrokerReview(self._registry, self._ledger, key=key, session=session, timeout=self._timeout)
            first = model.coordinator.begin(app, credential, proposal, draft_id, revision)
            source_deadline = model._deadline
            recipient = LogicalPublicationRecipient(app, timeout=self._timeout)
            descriptor = recipient.descriptor
            recipient_snapshot = _canonical(asdict(descriptor))
            recipient_deadline = recipient._deadline_snapshot
            lifecycle = LivePublicationDraft(AcquisitionDraft(model), recipient)
            acquired = transport._slot.acquire(blocking=False)
            if not acquired: raise BrokerReviewHostError('busy_or_unavailable')
            self._check()
            child = _PublicationCheckChild()

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
                    result = RetiredNativePublicationCheck(model._facts_snapshot, 'deny',
                        hashlib.sha256(b'').hexdigest(), hashlib.sha256(recipient_snapshot).hexdigest(),
                        0, hashlib.sha256(b'').hexdigest())
            else:
                token = lifecycle.coordinator.reserve()
                write(lifecycle.adapter.begin(token, app, credential, proposal))
                lifecycle.adapter.stage(frame())
                write(lifecycle.adapter.retire())  # This profile retains private quarantine.
                child.close_input()
                ack = frame()  # Do not trust cleanup evidence before EOF, exit and job cleanup.
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
                checked = lifecycle.coordinator.check_publication(app, credential, proposal, descriptor)
                summary = lifecycle._summary_snapshot
                if (type(checked) is not FinalPublicationDraftCheck
                        or type(checked.binding_digest) is not str or checked.binding_digest != summary[0][1]
                        or type(checked.recipient_digest) is not str
                        or checked.recipient_digest != hashlib.sha256(recipient_snapshot).hexdigest()
                        or type(checked.staged_digest) is not str or checked.staged_digest != summary[1][1]
                        or type(checked.staged_bytes) is not int or checked.staged_bytes != summary[2][1]
                        or type(checked.released_bytes) is not int or checked.released_bytes != 0
                        or type(checked.disposition) is not str or checked.disposition != 'eligible_discarded'):
                    raise ValueError('changed_publication_check')
                result = RetiredNativePublicationCheck(model._facts_snapshot, 'allow_once',
                    checked.binding_digest, checked.recipient_digest, checked.staged_bytes, checked.staged_digest)
            result_snapshot = _result_values(result)
        except BrokerProcessError as exc:
            if str(exc) == 'process_cleanup_failed': cleanup_ok = False
            raise BrokerReviewHostError('process_failed') from None
        except Exception:
            raise BrokerReviewHostError('publication_session_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally:
                    try:
                        if lifecycle is not None: lifecycle._shutdown()
                        elif model is not None: model.close()
                    finally:
                        if recipient is not None: recipient.close()
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
        # All owner cleanup and admission-slot release precede this terminal fence.
        # No bytes or executable authority cross it, even when every check succeeds.
        with self._condition, lifecycle._lock, recipient._lock, lifecycle._acquisition._lock, model._lock:
            try:
                self._check()
                recipient._validate_descriptor()
                with model._lease(), model._ledger._lock:
                    if (type(self._deadline) is not float or self._deadline != host_deadline
                            or type(model._deadline) is not float or model._deadline != source_deadline
                            or lifecycle._cancelled is not False
                            or type(lifecycle._state) is not str or lifecycle._state != 'closed'
                            or lifecycle._acquisition._closed is not True
                            or type(model._state) is not str or model._state != 'closed'
                            or model._app_state() != model._app_snapshot
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
                            or type(recipient._terminal) is not bool or recipient._terminal is not True
                            or type(recipient._state) is not str or recipient._state != 'closed'
                            or recipient._claim is not None
                            or recipient._issued is not descriptor or recipient._descriptor is not descriptor
                            or type(descriptor) is not RecipientDescriptor
                            or descriptor.application_id != app
                            or recipient._snapshot != recipient_snapshot
                            or _canonical(asdict(descriptor)) != recipient_snapshot
                            or type(recipient._deadline) is not float or recipient._deadline != recipient_deadline
                            or recipient._deadline_snapshot != recipient_deadline
                            or time.monotonic() >= min(model._deadline, recipient_deadline)):
                        raise ValueError('changed_after_cleanup')
                    if answer == 'ALLOW ONCE':
                        wire = lifecycle._wire
                        if (lifecycle._publication_attempted is not True
                                or recipient._ever_claimed is not True
                                or descriptor is not lifecycle._recipient_descriptor
                                or lifecycle._recipient_snapshot != recipient_snapshot
                                or token is not lifecycle._token or token is not lifecycle._issued_token
                                or not lifecycle._acquisition._matches(token)
                                or type(lifecycle._summary) is not QuarantineSummary
                                or lifecycle._summary is not lifecycle._issued_summary
                                or type(lifecycle._retirement) is not RetiredForCheckReceipt
                                or lifecycle._retirement is not lifecycle._issued_retirement
                                or lifecycle._summary_values() != lifecycle._summary_snapshot
                                or lifecycle._retirement_values() != lifecycle._retirement_snapshot
                                or type(wire) is not PublicationCheckExchange
                                or type(wire._state) is not str or wire._state != 'closed'
                                or type(wire._step) is not int or wire._step != 4
                                or type(wire._key) is not bytes or wire._key
                                or wire._buffer is not lifecycle._owned_buffer
                                or wire._issued_buffer is not lifecycle._owned_buffer
                                or type(lifecycle._owned_buffer) is not bytearray or lifecycle._owned_buffer
                                or type(wire._deadline) is not float or wire._deadline != wire._deadline_snapshot
                                or type(model._deadline) is not float
                                or model._deadline != lifecycle._source_deadline_snapshot
                                or wire._context_snapshot != lifecycle._publication_binding_snapshot
                                or lifecycle._publication_binding_snapshot != _publication_binding(dict(
                                    context=loads(lifecycle._acquisition._snapshot[1]), recipient=loads(recipient_snapshot)))
                                or lifecycle._summary_snapshot[0][1] != hashlib.sha256(
                                    lifecycle._publication_binding_snapshot).hexdigest()
                                or time.monotonic() >= min(lifecycle._source_deadline_snapshot, wire._deadline_snapshot)):
                            raise ValueError('changed_publication_evidence')
                        expected_binding = lifecycle._summary_snapshot[0][1]
                        expected_count = lifecycle._summary_snapshot[2][1]
                        expected_digest = lifecycle._summary_snapshot[1][1]
                    else:
                        if (recipient._ever_claimed is not False or token is not None
                                or lifecycle._publication_attempted is not False
                                or lifecycle._wire is not None or lifecycle._owned_buffer is not None):
                            raise ValueError('changed_denial_state')
                        expected_binding = expected_digest = hashlib.sha256(b'').hexdigest()
                        expected_count = 0
                    if (type(result) is not RetiredNativePublicationCheck
                            or type(result.canonical_display) is not bytes or result.canonical_display != model._facts_snapshot
                            or type(result.decision) is not str or result.decision != model._decision
                            or type(result.binding_digest) is not str or result.binding_digest != expected_binding
                            or type(result.recipient_digest) is not str
                            or result.recipient_digest != hashlib.sha256(recipient_snapshot).hexdigest()
                            or type(result.staged_bytes) is not int or result.staged_bytes != expected_count
                            or type(result.staged_digest) is not str or result.staged_digest != expected_digest
                            or type(result.released_bytes) is not int or result.released_bytes != 0
                            or type(result.lifecycle) is not str or result.lifecycle != 'retired'
                            or _result_values(result) != result_snapshot):
                        raise ValueError('changed_public_result')
                    self._check()
                    return result
            except Exception:
                # A post-cleanup hook or late state mutation must not leave
                # bytes reinserted in retired quarantine. Dispose again before
                # reporting a rejected result; uncertainty withholds status.
                try:
                    lifecycle.close()
                except BaseException:
                    transport._slot.acquire(blocking=False)  # Poison free admission.
                    with self._condition: self._cleanup_confirmed = False
                raise BrokerReviewHostError('stale_publication_retirement') from None
