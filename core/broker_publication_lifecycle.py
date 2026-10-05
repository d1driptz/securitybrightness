"""Inactive recipient-bound retained quarantine and terminal final-check draft.

Synthetic adapter cleanup claims only: no native/process proof, transport, byte
delivery, executable permission or product integration. A successful final check
still discards all bytes and irreversibly retires the recipient and live review.
"""
from dataclasses import asdict, dataclass, field
import hashlib
from time import monotonic
from .broker_acquisition_lifecycle import LiveAcquisitionLifecycle, AcquisitionLifecycleError
from .broker_protocol import _canonical
from .broker_quarantine import QuarantineSummary
from .broker_publication_protocol import PublicationCheckExchange, RetiredForCheckReceipt, _publication_binding
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .json_input import loads

PublicationLifecycleError = AcquisitionLifecycleError


@dataclass(frozen=True)
class FinalPublicationDraftCheck:
    binding_digest: str
    recipient_digest: str
    staged_digest: str
    staged_bytes: int
    disposition: str = field(default='eligible_discarded', init=False)
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default='Inactive logical-recipient check; no delivery permission or cleanup proof.', init=False)
    def __bool__(self): raise TypeError('A retired final check is not permission')


class _CoordinatorPort:
    def __init__(self, owner): self._owner = owner
    def reserve(self): return self._owner._reserve()
    def check_publication(self, app, credential, proposal, recipient):
        return self._owner._check_publication(app, credential, proposal, recipient)
    def cancel(self): self._owner.close()


class _AdapterPort:
    def __init__(self, owner): self._owner = owner
    def begin(self, reservation, app, credential, proposal):
        return self._owner._begin(reservation, app, credential, proposal)
    def stage(self, frame): return self._owner._stage(frame)
    def retire(self): return self._owner._retire()
    def confirm_retirement(self, frame): return self._owner._confirm_retirement(frame)
    def cancel(self): self._owner.close()


class LivePublicationDraft(LiveAcquisitionLifecycle):
    """Distinct inactive profile; the verified discard-only lifecycle is unchanged.

    Lock order: lifecycle -> recipient -> acquisition -> review -> registry
    -> ledger -> wire. No registry lock is held across an external wait. The final
    attempt burns before validating even bad recipient/credentials; no retry,
    restoration, renewal or final-check token survives successful retirement.
    """
    def __init__(self, acquisition, recipient):
        if type(recipient) is not LogicalPublicationRecipient:
            raise TypeError('expected exact trusted logical recipient owner')
        super().__init__(acquisition)
        self._recipient = recipient
        self._recipient_snapshot = self._recipient_descriptor = None
        self._owned_buffer = None
        self._source_deadline_snapshot = None
        self._publication_attempted = False
        self.coordinator, self.adapter = _CoordinatorPort(self), _AdapterPort(self)

    def _abort(self, error):
        try: self.close()
        finally: raise PublicationLifecycleError(error) from None

    def _recipient_current(self):
        self._recipient._current_for(self)
        if (self._recipient._issued is not self._recipient_descriptor
                or self._recipient._snapshot != self._recipient_snapshot
                or _canonical(asdict(self._recipient_descriptor)) != self._recipient_snapshot):
            raise PublicationLifecycleError('changed_recipient')

    def _current(self, state, review_state='acquisition_inflight'):
        super()._current(state, review_state)
        if self._source_deadline_snapshot is not None and (type(self._review._deadline) is not float
                or self._review._deadline != self._source_deadline_snapshot):
            raise PublicationLifecycleError('changed_source_deadline')
        self._recipient_current()
        if self._summary is not None and (type(self._summary) is not QuarantineSummary
                or self._summary is not self._issued_summary):
            raise PublicationLifecycleError('changed_staging_owner')
        if self._retirement is not None and (type(self._retirement) is not RetiredForCheckReceipt
                or self._retirement is not self._issued_retirement):
            raise PublicationLifecycleError('changed_retirement_owner')

    def _retirement_values(self):
        value = self._retirement
        return tuple((type(item), item) for item in (value.binding_digest, value.staged_digest,
                    value.staged_bytes, value.outcome, value.released_bytes, value.meaning))

    def _wire_current(self, step):
        wire = self._wire
        if (type(wire) is not PublicationCheckExchange or type(wire._step) is not int or wire._step != step
                or wire._state != ('retired_for_check' if step == 4 else 'new')
                or monotonic() >= wire._deadline_snapshot):
            raise PublicationLifecycleError('quarantine_unavailable')
        with wire._lock:
            wire._integrity()
            if wire._binding != self._publication_binding_snapshot:
                raise PublicationLifecycleError('changed_publication_binding')
            if wire._buffer is not self._owned_buffer:
                raise PublicationLifecycleError('changed_buffer_owner')
            if self._summary is not None and (len(wire._buffer) != self._summary.staged_bytes
                    or hashlib.sha256(wire._buffer).hexdigest() != self._summary.staged_digest):
                raise PublicationLifecycleError('changed_quarantine')

    def _reserve(self):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                self._recipient._claim_for(self)
                self._recipient_descriptor = self._recipient._issued
                self._recipient_snapshot = self._recipient._snapshot
                token = super()._reserve()
                self._issued_token = token
                self._source_deadline_snapshot = self._review._deadline
                if self._recipient_descriptor.application_id != self._review._app.application_id:
                    raise PublicationLifecycleError('wrong_recipient_application')
                self._publication_binding_snapshot = _publication_binding(dict(
                    context=loads(token.canonical_context), recipient=asdict(self._recipient_descriptor)))
                self._recipient_current()
                return token
            except Exception: self._abort('publication_reservation_rejected')

    def _begin(self, token, app, credential, proposal):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                if self._acquisition._attempted: raise PublicationLifecycleError('already_attempted')
                self._acquisition._attempted = True
                with self._review._lease(), self._review._ledger._lock:
                    self._current('reserved', 'acquisition_reserved')
                    if token is not self._token: raise PublicationLifecycleError('wrong_reservation')
                    self._authenticate(app, credential, proposal)
                    remaining = min(5, self._review._deadline-monotonic(), self._recipient._deadline_snapshot-monotonic())
                    self._wire = PublicationCheckExchange(role='coordinator', key=self._review._exchange._key,
                        session=bytes.fromhex(self._review._exchange._session), timeout=remaining)
                    self._owned_buffer = self._wire._buffer
                    frame = self._wire.request(loads(self._acquisition._snapshot[1]),
                                               asdict(self._recipient_descriptor))
                    self._wire_current(1)
                    self._current('reserved', 'acquisition_reserved')
                    self._review._state = 'acquisition_inflight'
                    self._state = 'inflight'
                    return frame
            except Exception: self._abort('publication_acquisition_rejected')

    def _stage(self, frame):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('inflight'); self._wire_current(1)
                    self._summary = self._wire.accept_reply(frame)
                    self._issued_summary = self._summary
                    self._summary_snapshot = self._summary_values()
                    if self._summary.outcome != 'staged': raise PublicationLifecycleError('adapter_denied')
                    self._wire_current(2); self._current('inflight')
                    self._state = 'staged'
                    return self._summary
            except Exception: self._abort('publication_staging_rejected')

    def _retire(self):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('staged'); self._wire_current(2)
                    frame = self._wire.retire_for_check()  # Retain private bytes; no delivery.
                    self._wire_current(3); self._current('staged')
                    self._state = 'retiring'
                    return frame
            except Exception: self._abort('publication_retirement_rejected')

    def _confirm_retirement(self, frame):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('retiring'); self._wire_current(3)
                    self._retirement = self._wire.accept_retirement_ack(frame)
                    self._issued_retirement = self._retirement
                    self._retirement_snapshot = self._retirement_values()
                    self._wire_current(4); self._current('retiring')
                    self._state = 'cleaned'
                    return self._retirement
            except Exception: self._abort('publication_confirmation_rejected')

    def _check_publication(self, app, credential, proposal, recipient):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                if self._publication_attempted: raise PublicationLifecycleError('already_attempted')
                self._publication_attempted = True  # Invalid final attempts are spent too.
                with self._review._lease(), self._review._ledger._lock:
                    self._current('cleaned'); self._wire_current(4)
                    if type(recipient) is not RecipientDescriptor or recipient is not self._recipient_descriptor:
                        raise PublicationLifecycleError('wrong_recipient')
                    self._authenticate(app, credential, proposal)
                    self._current('cleaned'); self._wire_current(4)
                    summary = self._summary_snapshot
                    result = FinalPublicationDraftCheck(summary[0][1], hashlib.sha256(self._recipient_snapshot).hexdigest(),
                                                        summary[1][1], summary[2][1])
                    result_snapshot = _canonical(asdict(result))
                    self._shutdown()  # A dry run always discards, never releases.
                    self._recipient._validate_descriptor()
                    with self._review._lease():
                        if (self._cancelled or self._publication_attempted is not True
                                or type(self._state) is not str or self._state != 'closed'
                                or self._acquisition._closed is not True
                                or type(self._review._state) is not str or self._review._state != 'closed'
                                or self._review._app_state() != self._review._app_snapshot
                                or self._review._draft() != self._review._draft_snapshot
                                or _canonical(asdict(self._review._ticket)) != self._review._ticket_snapshot
                                or self._review._proposal.canonical_bytes() != self._review._proposal_snapshot
                                or self._review._shown is not self._review._facts
                                or _canonical(asdict(self._review._shown)) != self._review._facts_snapshot
                                or type(self._review._decision) is not str or self._review._decision != 'allow_once'
                                or not self._acquisition._matches(self._token)
                                or self._token is not self._issued_token
                                or type(self._summary) is not QuarantineSummary
                                or self._summary is not self._issued_summary
                                or type(self._retirement) is not RetiredForCheckReceipt
                                or self._retirement is not self._issued_retirement
                                or self._summary_values() != self._summary_snapshot
                                or self._retirement_values() != self._retirement_snapshot
                                or self._review._ledger._reviews.get(self._review._ticket.review.draft_id) is not None
                                or self._review._reviews._pending.get(self._review._ticket.review.draft_id) is not None
                                or self._recipient._terminal is not True
                                or type(self._recipient._state) is not str or self._recipient._state != 'closed'
                                or self._recipient._claim is not None or self._recipient._ever_claimed is not True
                                or self._recipient._snapshot != self._recipient_snapshot
                                or self._recipient._issued is not recipient
                                or type(self._wire._state) is not str or self._wire._state != 'closed'
                                or type(self._wire._key) is not bytes or self._wire._key
                                or type(self._wire._step) is not int or self._wire._step != 4
                                or self._wire._buffer is not self._owned_buffer
                                or self._wire._issued_buffer is not self._owned_buffer
                                or type(self._owned_buffer) is not bytearray or self._owned_buffer
                                or type(self._wire._deadline) is not float
                                or self._wire._deadline != self._wire._deadline_snapshot
                                or self._wire._context_snapshot != self._publication_binding_snapshot
                                or self._publication_binding_snapshot != _publication_binding(dict(
                                    context=loads(self._acquisition._snapshot[1]),
                                    recipient=loads(self._recipient_snapshot)))
                                or summary[0][1] != hashlib.sha256(self._publication_binding_snapshot).hexdigest()
                                or type(self._recipient._deadline) is not float
                                or self._recipient._deadline != self._recipient._deadline_snapshot
                                or type(self._review._deadline) is not float
                                or self._review._deadline != self._source_deadline_snapshot
                                or monotonic() >= min(self._source_deadline_snapshot, self._wire._deadline_snapshot,
                                                     self._recipient._deadline_snapshot)
                                or type(result) is not FinalPublicationDraftCheck
                                or _canonical(asdict(result)) != result_snapshot):
                            raise PublicationLifecycleError('changed_during_final_check')
                    return result
            except Exception: self._abort('final_publication_check_rejected')

    def _shutdown(self):
        try: super()._shutdown()
        finally:
            try:
                if type(self._owned_buffer) is bytearray:
                    self._owned_buffer[:] = b'\0'*len(self._owned_buffer)
                    self._owned_buffer.clear()
            finally: self._recipient.close()

    def close(self):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            self._cancelled = True
            self._shutdown()
