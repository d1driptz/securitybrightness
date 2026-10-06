"""Inactive live channel plus retained quarantine; final dry run discards bytes.

The exact source lifecycle must already be cleaned. Its cleanup receipt is only
a claim here; the enclosing fixed host supplies actual native EOF/exit/join proof.
No retired witness, caller channel, content selector or delivery operation exists.
"""
from dataclasses import asdict
import hashlib
import hmac
import math
import os
import secrets
from threading import Event, RLock, Timer
from time import monotonic, sleep
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_process import BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .broker_publication_lifecycle import LivePublicationDraft, FinalPublicationDraftCheck
from .broker_publication_protocol import PublicationCheckExchange, RetiredForCheckReceipt, _publication_binding
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .broker_quarantine import QuarantineSummary
from .broker_recipient_channel import RecipientChannelProbe, RecipientChannelShutdownStatus, _values
from .broker_recipient_process import _RecipientWitnessChild, ProcessChannelObservation
from .broker_recipient_protocol import RecipientWitnessExchange
from .json_input import loads
from .structured_proposal import StructuredActionProposal


class LiveChannelCheckError(RuntimeError):
    pass


class LiveChannelPublicationCheck:
    """One already-owned lifecycle, one original live test peer, no publication.

    Lock order: helper -> lifecycle -> recipient -> acquisition -> review ->
    registry -> ledger -> native channel ownership. No authority lock spans a
    transport wait. Started workers alone own native cleanup; close cancels and
    callers join. Original source/quarantine/recipient deadlines are not renewed.
    """
    # Reuse only exact native/protocol validators, never the retired probe's run,
    # reservation, source-state transitions or authority/result semantics.
    _observe = RecipientChannelProbe._observe
    _native_current = RecipientChannelProbe._native_current
    _evidence_current = RecipientChannelProbe._evidence_current
    _wire_current = RecipientChannelProbe._wire_current
    _identity_current = RecipientChannelProbe._identity_current
    _clock_current = RecipientChannelProbe._clock_current

    def __init__(self, lifecycle, *, timeout=5):
        if type(lifecycle) is not LivePublicationDraft:
            raise TypeError('expected exact live publication draft')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_live_channel_lifetime')
        with lifecycle._lock, lifecycle._recipient._lock, lifecycle._acquisition._lock, lifecycle._review._lock:
            lifecycle._current('cleaned'); lifecycle._wire_current(4)
            self._lifecycle = self._issued_lifecycle = lifecycle
            self._acquisition = self._issued_acquisition = lifecycle._acquisition
            self._review = self._issued_review = lifecycle._review
            self._recipient = self._issued_recipient = lifecycle._recipient
            self._descriptor = self._recipient_descriptor = lifecycle._recipient_descriptor
            self._recipient_snapshot = lifecycle._recipient_snapshot
            self._source_deadline = lifecycle._source_deadline_snapshot
            self._recipient_deadline = self._recipient._deadline_snapshot
            self._quarantine = lifecycle._wire
            self._quarantine_deadline = self._quarantine._deadline_snapshot
            self._owned_buffer = lifecycle._owned_buffer
            self._token = lifecycle._token
            self._summary = lifecycle._summary
            self._retirement = lifecycle._retirement
            self._summary_snapshot = lifecycle._summary_snapshot
            self._retirement_snapshot = lifecycle._retirement_snapshot
            self._binding_snapshot = lifecycle._publication_binding_snapshot
            remaining = min(timeout, self._source_deadline-monotonic(),
                self._recipient_deadline-monotonic(), self._quarantine_deadline-monotonic())
            if remaining <= 0: raise LiveChannelCheckError('expired_live_source')
        self._lock, self._cancel = RLock(), Event()
        self._issued_cancel = self._cancel
        self._cancelled = self._owner_changed = False
        self._deadline = self._deadline_snapshot = monotonic()+remaining
        self._child = self._issued_child = self._native_observation = self._child_snapshot = self._native_snapshot = None
        self._wire = self._issued_wire = self._proof = self._issued_proof = self._ack = self._issued_ack = None
        self._proof_snapshot = self._ack_snapshot = self._wire_identity_snapshot = self._ack_transcript_digest = None
        self._result = self._issued_result = self._result_snapshot = None
        self._state, self._started, self._finished, self._cleanup_confirmed = 'prepared', False, False, False
        self._timer = self._issued_timer = Timer(remaining, self.close); self._timer.daemon = True
        try:
            self._timer.start(); self._current()
        except Exception:
            self.close(); raise LiveChannelCheckError('live_channel_unavailable') from None

    def _source_identity(self):
        self._identity_current()
        source = self._lifecycle
        if (type(source) is not LivePublicationDraft or source is not self._issued_lifecycle
                or source._acquisition is not self._acquisition or source._review is not self._review
                or source._recipient is not self._recipient or type(self._recipient) is not LogicalPublicationRecipient
                or source._recipient_descriptor is not self._descriptor
                or type(self._descriptor) is not RecipientDescriptor
                or self._recipient_descriptor is not self._descriptor
                or source._token is not self._token or source._issued_token is not self._token
                or not self._acquisition._matches(self._token)
                or source._summary is not self._summary or source._issued_summary is not self._summary
                or type(self._summary) is not QuarantineSummary
                or source._retirement is not self._retirement or source._issued_retirement is not self._retirement
                or type(self._retirement) is not RetiredForCheckReceipt
                or source._summary_values() != self._summary_snapshot
                or source._retirement_values() != self._retirement_snapshot
                or source._wire is not self._quarantine or type(self._quarantine) is not PublicationCheckExchange
                or source._owned_buffer is not self._owned_buffer or type(self._owned_buffer) is not bytearray
                or self._quarantine._buffer is not self._owned_buffer or self._quarantine._issued_buffer is not self._owned_buffer
                or type(self._binding_snapshot) is not bytes or source._publication_binding_snapshot != self._binding_snapshot
                or self._binding_snapshot != _publication_binding(dict(context=loads(self._token.canonical_context),
                    recipient=asdict(self._descriptor)))
                or type(self._recipient_snapshot) is not bytes or source._recipient_snapshot != self._recipient_snapshot
                or self._recipient._snapshot != self._recipient_snapshot
                or self._recipient._issued is not self._descriptor
                or _canonical(asdict(self._descriptor)) != self._recipient_snapshot
                or type(self._quarantine_deadline) is not float
                or type(self._quarantine._deadline) is not float or self._quarantine._deadline != self._quarantine_deadline
                or self._quarantine._deadline_snapshot != self._quarantine_deadline
                or source._source_deadline_snapshot != self._source_deadline
                or monotonic() >= self._quarantine_deadline):
            raise LiveChannelCheckError('changed_live_source')

    def _checked_source(self, proposal=None):
        source, review = self._lifecycle, self._review
        self._source_identity(); self._clock_current()
        self._recipient._validate_descriptor()
        with review._lease(), review._ledger._lock:
            if (source._cancelled is not False or source._publication_attempted is not True
                    or type(source._state) is not str or source._state != 'closed'
                    or self._acquisition._closed is not True or self._acquisition._attempted is not True
                    or self._acquisition._issued is not None
                    or type(review._state) is not str or review._state != 'closed'
                    or review._app_state() != review._app_snapshot or review._draft() != review._draft_snapshot
                    or _canonical(asdict(review._ticket)) != review._ticket_snapshot
                    or review._proposal.canonical_bytes() != review._proposal_snapshot
                    or (proposal is not None and (type(proposal) is not StructuredActionProposal
                        or proposal.canonical_bytes() != review._proposal_snapshot))
                    or review._shown is not review._facts or _canonical(asdict(review._shown)) != review._facts_snapshot
                    or type(review._decision) is not str or review._decision != 'allow_once'
                    or review._ledger._reviews.get(review._ticket.review.draft_id) is not None
                    or review._reviews._pending.get(review._ticket.review.draft_id) is not None
                    or self._recipient._terminal is not True or type(self._recipient._state) is not str
                    or self._recipient._state != 'closed' or self._recipient._claim is not None
                    or self._recipient._ever_claimed is not True
                    or type(self._quarantine._state) is not str or self._quarantine._state != 'closed'
                    or type(self._quarantine._step) is not int or self._quarantine._step != 4
                    or type(self._quarantine._key) is not bytes or self._quarantine._key or self._owned_buffer
                    or self._quarantine._context_snapshot != self._binding_snapshot):
                raise LiveChannelCheckError('changed_final_dry_run')
            self._clock_current()

    def _current(self):
        with self._lock, self._lifecycle._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            self._source_identity(); self._clock_current()
            if type(self._state) is not str or self._state not in ('prepared', 'witnessed', 'checked'):
                raise LiveChannelCheckError('live_channel_unavailable')
            if self._state == 'checked': self._checked_source()
            else:
                self._lifecycle._current('cleaned'); self._lifecycle._wire_current(4)
                if self._lifecycle._publication_attempted is not False:
                    raise LiveChannelCheckError('spent_final_check')

    def _result_current(self):
        value = self._result
        if (type(value) is not FinalPublicationDraftCheck or value is not self._issued_result
                or _values(value) != self._result_snapshot
                or type(value.binding_digest) is not str or value.binding_digest != hashlib.sha256(self._binding_snapshot).hexdigest()
                or type(value.recipient_digest) is not str or value.recipient_digest != hashlib.sha256(self._recipient_snapshot).hexdigest()
                or type(value.staged_digest) is not str or value.staged_digest != self._summary_snapshot[1][1]
                or type(value.staged_bytes) is not int or value.staged_bytes != self._summary_snapshot[2][1]
                or type(value.released_bytes) is not int or value.released_bytes != 0
                or type(value.disposition) is not str or value.disposition != 'eligible_discarded'
                or type(value.meaning) is not str or value.meaning != FinalPublicationDraftCheck.__dataclass_fields__['meaning'].default):
            raise LiveChannelCheckError('changed_final_result')

    def _proof_current(self):
        if self._proof is not self._issued_proof: raise LiveChannelCheckError('changed_live_proof')
        self._evidence_current(self._proof, 'witnessed')
        if _values(self._proof) != self._proof_snapshot: raise LiveChannelCheckError('changed_live_proof')

    def run(self, app, credential, proposal, descriptor):
        with self._lock:
            if self._started is not False or self._finished is not False:
                self.close(); raise LiveChannelCheckError('live_channel_unavailable')
            self._started = True  # Invalid first attempts also spend this helper.
        child = None
        cleanup_ok = True
        try:
            self._current()
            if type(descriptor) is not RecipientDescriptor or descriptor is not self._descriptor:
                raise LiveChannelCheckError('wrong_live_recipient')
            with self._lock, self._lifecycle._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
                with self._review._lease(), self._review._ledger._lock:
                    self._lifecycle._authenticate(app, credential, proposal); self._current()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            self._wire = self._issued_wire = RecipientWitnessExchange(role='coordinator', key=key, session=session)
            self._wire_identity_snapshot = tuple((type(item), item) for item in (self._wire._role,
                self._wire._role_snapshot, self._wire._session, self._wire._session_snapshot, self._wire._key_snapshot))
            request = self._wire.request(loads(self._binding_snapshot)); self._wire_current(1)
            self._current()
            child = self._child = self._issued_child = _RecipientWitnessChild()
            self._observe(); self._native_snapshot = self._child_snapshot; self._native_current()

            def check(retiring=False):
                self._current()
                if retiring:
                    if child is not self._child or self._native_observation is not child._issued_observation:
                        raise LiveChannelCheckError('changed_retiring_channel')
                    child._validate(retiring=True)
                else: self._native_current()
            def write(data):
                offset = 0
                while offset < len(data):
                    check()
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if count <= 0: raise LiveChannelCheckError('pipe_failed')
                        offset += count
                    except BlockingIOError: sleep(.002)
                    check()
            def read(size, *, retiring=False):
                output = bytearray()
                while len(output) < size:
                    check(retiring)
                    try:
                        data = os.read(child.stdout_fd, size-len(output))
                        if not data: raise LiveChannelCheckError('truncated_peer_output')
                        output.extend(data)
                    except BlockingIOError: sleep(.002)
                    check(retiring)
                return bytes(output)
            def frame(*, retiring=False):
                prefix = read(4, retiring=retiring); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32: raise LiveChannelCheckError('peer_output_limit')
                return prefix+read(size, retiring=retiring)

            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, self._native_observation.pid)):
                raise LiveChannelCheckError('peer_startup_rejected')
            write(request)
            self._proof = self._issued_proof = self._wire.accept_proof(frame())
            self._proof_snapshot = _values(self._proof)
            self._proof_current(); self._wire_current(2); self._current(); self._native_current()
            self._state = 'witnessed'
            # The only final operation is a dry run. Keep the same original
            # native channel alive and owned across the entire locked decision.
            with self._lock, self._lifecycle._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
                with self._review._lease(), self._review._ledger._lock, child._ownership_lock:
                    self._current(); self._native_current(); self._proof_current(); self._wire_current(2)
                    self._result = self._issued_result = self._lifecycle.coordinator.check_publication(
                        app, credential, proposal, descriptor)
                    self._result_snapshot = _values(self._result)
                    self._state = 'checked'
                    self._result_current(); self._checked_source(proposal); self._proof_current()
                    self._wire_current(2); self._native_current(); self._clock_current()
            write(self._wire.retire()); self._wire_current(3)
            child.close_input()
            ack = frame(retiring=True)
            while True:
                check(True)
                try:
                    if os.read(child.stdout_fd, 1): raise LiveChannelCheckError('trailing_peer_output')
                    break
                except BlockingIOError: sleep(.002)
            while child.poll() is None: check(True); sleep(.002)
            if child.poll() != 0: raise LiveChannelCheckError('peer_failed')
            child.close(); child._retired()
            if type(child._exit) is not int or child._exit != 0: raise LiveChannelCheckError('peer_failed')
            self._current(); self._wire_current(3)
            self._ack = self._issued_ack = self._wire.accept_ack(ack)
            self._ack_transcript_digest = hashlib.sha256(ack).hexdigest()
            self._ack_snapshot = _values(self._ack)
            self._evidence_current(self._ack, 'retired'); self._wire_current(4)
        except BrokerProcessError as error:
            if str(error) == 'process_cleanup_failed': cleanup_ok = False
            raise LiveChannelCheckError('live_peer_process_failed') from None
        except Exception:
            raise LiveChannelCheckError('live_channel_check_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally: self._dispose()
            except BaseException:
                cleanup_ok = False
                raise LiveChannelCheckError('live_channel_cleanup_failed') from None
            finally:
                with self._lock:
                    self._finished, self._cleanup_confirmed = True, cleanup_ok
                    self._state = 'retired'
        try:
            with self._lock, self._lifecycle._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
                with self._review._lease(), self._review._ledger._lock:
                    self.retired_check(); self._result_current(); self.retired_check()
                    return self._result
        except BrokerProcessError:
            with self._lock: self._cleanup_confirmed = False
            raise LiveChannelCheckError('live_channel_cleanup_failed') from None
        except Exception: raise LiveChannelCheckError('stale_live_channel_check') from None

    def _dispose(self):
        source = self._issued_lifecycle
        try: self._issued_timer.cancel()
        finally:
            try:
                if self._issued_wire is not None: self._issued_wire.close()
            finally:
                # Preserve foreign owner objects. Restore original references
                # for disposal only, keeping terminal substitution evidence.
                if (source._wire is not self._quarantine or source._recipient is not self._issued_recipient
                        or source._acquisition is not self._issued_acquisition or source._review is not self._issued_review
                        or self._issued_acquisition._review is not self._issued_review):
                    self._owner_changed = True
                    source._wire, source._recipient = self._quarantine, self._issued_recipient
                    source._acquisition, source._review = self._issued_acquisition, self._issued_review
                    self._issued_acquisition._review = self._issued_review
                try: source._shutdown()
                finally:
                    if type(self._owned_buffer) is bytearray:
                        self._owned_buffer[:] = b'\0'*len(self._owned_buffer); self._owned_buffer.clear()

    def retired_check(self):
        """Terminal freshness/cleanup only. No live channel or authority returned."""
        try:
            self._retired_check()
        except BrokerProcessError:
            # The enclosing host must distinguish uncertain native ownership
            # from ordinary stale evidence and retain poisoned admission.
            raise
        except Exception:
            raise LiveChannelCheckError('changed_retired_live_channel') from None

    def _retired_check(self):
        with self._lock, self._lifecycle._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            self._checked_source(); self._wire_current(4); self._proof_current(); self._result_current()
            self._issued_child._retired()
            if (type(self._state) is not str or self._state != 'retired' or self._started is not True
                    or self._finished is not True or self._cleanup_confirmed is not True
                    or self._child is not self._issued_child or type(self._child) is not self._expected_child_type()
                    or type(self._native_observation) is not ProcessChannelObservation
                    or self._native_observation is not self._child._issued_observation
                    or _values(self._native_observation) != self._child_snapshot
                    or self._native_snapshot != self._child_snapshot
                    or type(self._child._exit) is not int or self._child._exit != 0
                    or self._ack is not self._issued_ack or _values(self._ack) != self._ack_snapshot):
                raise LiveChannelCheckError('changed_retired_live_channel')
            self._evidence_current(self._ack, 'retired'); self._checked_source()

    def _expected_child_type(self):
        return _RecipientWitnessChild

    def close(self):
        with self._lock:
            self._cancelled = True; self._issued_cancel.set()
            if not self._started:
                cleanup_ok = True
                try: self._dispose()
                except BaseException:
                    cleanup_ok = False; raise LiveChannelCheckError('live_channel_cleanup_failed') from None
                finally:
                    self._state, self._finished, self._cleanup_confirmed = 'retired', True, cleanup_ok

    def shutdown_status(self):
        with self._lock:
            if self._finished is not True: return None
            return RecipientChannelShutdownStatus(self._cleanup_confirmed is True)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
