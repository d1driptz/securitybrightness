"""Inactive live one-use acquisition/quarantine/publication-check composition.

No I/O, native acquisition, child command or byte delivery. The private adapter
port accepts authenticated synthetic staging frames in tests. Final checks return
discard-only metadata; they never create a token for a later operation.
"""
from dataclasses import asdict, dataclass, field
import hashlib
from threading import RLock
from time import monotonic
from .broker_acquisition_draft import AcquisitionDraft
from .broker_protocol import _canonical
from .broker_quarantine import QuarantinedReadExchange
from .json_input import loads
from .structured_proposal import StructuredActionProposal


class AcquisitionLifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class PublicationCheckResult:
    binding_digest: str
    staged_digest: str
    staged_bytes: int
    disposition: str = 'eligible_discarded'
    released_bytes: int = 0
    meaning: str = field(default='coordinator checks only; no native/process proof or delivery permission', init=False)
    def __bool__(self): raise TypeError('A retired publication check is not permission')


class _CoordinatorPort:
    def __init__(self, owner): self._owner = owner
    def reserve(self): return self._owner._reserve()
    def check_publication(self, app, credential, proposal):
        return self._owner._check_publication(app, credential, proposal)
    def cancel(self): self._owner.close()


class _AdapterPort:
    def __init__(self, owner): self._owner = owner
    def begin(self, reservation, app, credential, proposal):
        return self._owner._begin(reservation, app, credential, proposal)
    def stage(self, frame): return self._owner._stage(frame)
    def retire(self): return self._owner._retire()
    def confirm_retirement(self, frame): return self._owner._confirm_retirement(frame)
    def cancel(self): self._owner.close()


class LiveAcquisitionLifecycle:
    """Exact live review stays current until the separate final check.

    Trusted bootstrap transfers the acquisition owner and separates ports. Lock
    order: lifecycle -> acquisition -> review -> registry -> ledger -> codec.
    One request and attempt, no reset/restore/extension. Receipt fields and signed
    frames are binding evidence, not resource truth or human authentication.
    """
    def __init__(self, acquisition):
        if type(acquisition) is not AcquisitionDraft:
            raise TypeError('expected exact inactive acquisition owner')
        self._acquisition = acquisition
        self._review = acquisition._review
        self._lock = RLock()
        self._state = 'new'
        self._cancelled = self._closing = False
        self._wire = self._token = self._summary = self._retirement = None
        self.coordinator, self.adapter = _CoordinatorPort(self), _AdapterPort(self)

    def _current(self, state, review_state='acquisition_inflight'):
        if self._cancelled or self._state != state or self._acquisition._closed:
            raise AcquisitionLifecycleError('unavailable')
        self._acquisition._live(review_state)
        if (self._token is not self._acquisition._issued
                or not self._acquisition._matches(self._token)):
            raise AcquisitionLifecycleError('changed_reservation')
        if self._summary is not None and self._summary_values() != self._summary_snapshot:
            raise AcquisitionLifecycleError('changed_staging_evidence')
        if self._retirement is not None and self._retirement_values() != self._retirement_snapshot:
            raise AcquisitionLifecycleError('changed_retirement_evidence')

    def _authenticate(self, app, credential, proposal):
        if (type(app) is not str or type(credential) is not str or not 1 <= len(credential) <= 512
                or type(proposal) is not StructuredActionProposal
                or self._review._registry.authenticate(app, credential) is not self._review._app
                or proposal.canonical_bytes() != self._review._proposal_snapshot):
            raise AcquisitionLifecycleError('wrong_application_or_proposal')

    def _summary_values(self):
        value = self._summary
        return tuple((type(item), item) for item in (value.binding_digest, value.staged_digest,
                                                    value.staged_bytes, value.outcome))

    def _retirement_values(self):
        value = self._retirement
        return tuple((type(item), item) for item in (value.binding_digest, value.staged_digest,
                                                    value.released_bytes))

    def _wire_current(self, step):
        wire = self._wire
        if (wire is None or wire._step != step or monotonic() >= wire._deadline
                or (wire._state == 'closed') != (step == 4)):
            raise AcquisitionLifecycleError('quarantine_unavailable')
        if step == 2:
            if (type(wire._buffer) is not bytearray
                    or len(wire._buffer) != self._summary.staged_bytes
                    or hashlib.sha256(wire._buffer).hexdigest() != self._summary.staged_digest):
                raise AcquisitionLifecycleError('changed_quarantined_data')
        elif wire._buffer:
            raise AcquisitionLifecycleError('unexpected_quarantined_data')

    def _reserve(self):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                if self._state != 'new': raise AcquisitionLifecycleError('unavailable')
                self._token = self._acquisition.coordinator.reserve()
                self._state = 'reserved'
                self._current('reserved', 'acquisition_reserved')
                return self._token
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('reservation_rejected') from None

    def _begin(self, token, app, credential, proposal):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                # Burn before validating an attempt; invalid first attempts cannot
                # fall back to the original draft's consumption path.
                if self._acquisition._attempted: raise AcquisitionLifecycleError('already_attempted')
                self._acquisition._attempted = True
                with self._review._lease(), self._review._ledger._lock:
                    self._current('reserved', 'acquisition_reserved')
                    if token is not self._token: raise AcquisitionLifecycleError('wrong_reservation')
                    self._authenticate(app, credential, proposal)
                    remaining = min(5, self._review._deadline-monotonic())
                    self._wire = QuarantinedReadExchange(role='coordinator',
                        key=self._review._exchange._key,
                        session=bytes.fromhex(self._review._exchange._session), timeout=remaining)
                    frame = self._wire.request(loads(self._acquisition._snapshot[1]))
                    self._wire_current(1)
                    self._current('reserved', 'acquisition_reserved')
                    self._review._state = 'acquisition_inflight'
                    self._state = 'inflight'
                    self._current('inflight')
                    return frame
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('acquisition_rejected') from None

    def _stage(self, frame):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('inflight')
                    self._wire_current(1)
                    self._summary = self._wire.accept_reply(frame)
                    self._summary_snapshot = self._summary_values()
                    if self._summary.outcome != 'staged': raise AcquisitionLifecycleError('adapter_denied')
                    self._wire_current(2)
                    self._current('inflight')
                    self._state = 'staged'
                    return self._summary  # No bytes leave the quarantine.
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('staging_rejected') from None

    def _retire(self):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('staged')
                    self._wire_current(2)
                    frame = self._wire.discard()  # Clear quarantined bytes before peer cleanup.
                    self._wire_current(3)
                    self._current('staged')
                    self._state = 'discarding'
                    return frame
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('retirement_rejected') from None

    def _confirm_retirement(self, frame):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('discarding')
                    self._wire_current(3)
                    self._retirement = self._wire.accept_discard_ack(frame)
                    self._retirement_snapshot = self._retirement_values()
                    self._wire_current(4)
                    self._current('discarding')
                    self._state = 'cleaned'
                    return self._retirement
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('retirement_confirmation_rejected') from None

    def _check_publication(self, app, credential, proposal):
        with self._lock, self._acquisition._lock, self._review._lock:
            try:
                with self._review._lease(), self._review._ledger._lock:
                    self._current('cleaned')
                    self._wire_current(4)
                    self._authenticate(app, credential, proposal)
                    self._current('cleaned')
                    summary = self._summary_snapshot
                    result = PublicationCheckResult(summary[0][1], summary[1][1], summary[2][1])
                    self._shutdown()  # Retire internally; public close also marks cancellation.
                    # Catch same-thread changes injected during cleanup as well
                    # as serialized registry changes. The source is now closed,
                    # so compare immutable snapshots, never restore live review.
                    with self._review._lease():
                        if (self._cancelled or self._review._app_state() != self._review._app_snapshot
                                or self._review._draft() != self._review._draft_snapshot
                                or _canonical(asdict(self._review._ticket)) != self._review._ticket_snapshot
                                or self._review._proposal.canonical_bytes() != self._review._proposal_snapshot
                                or _canonical(asdict(self._review._shown)) != self._review._facts_snapshot
                                or self._review._decision != 'allow_once'
                                or not self._acquisition._matches(self._token)
                                or self._summary_values() != self._summary_snapshot
                                or self._retirement_values() != self._retirement_snapshot
                                or self._review._ledger._reviews.get(self._review._ticket.review.draft_id) is not None
                                or self._review._reviews._pending.get(self._review._ticket.review.draft_id) is not None
                                or monotonic() >= self._wire._deadline
                                or monotonic() >= self._review._deadline):
                            raise AcquisitionLifecycleError('changed_during_publication_check')
                    return result
            except Exception:
                self.close()
                raise AcquisitionLifecycleError('publication_check_rejected') from None

    def close(self):
        with self._lock, self._acquisition._lock, self._review._lock:
            self._cancelled = True
            self._shutdown()

    def _shutdown(self):
        with self._lock, self._acquisition._lock, self._review._lock:
            self._state = 'closed'
            if self._closing: return
            self._closing = True
            try:
                try:
                    if self._wire is not None:
                        with self._wire._lock:
                            try:
                                self._wire.close()
                            finally:
                                # Independently clear owned quarantine even when
                                # the codec's close operation itself fails.
                                if type(self._wire._buffer) is bytearray:
                                    self._wire._buffer[:] = b'\0'*len(self._wire._buffer)
                                    self._wire._buffer.clear()
                                else:
                                    self._wire._buffer = bytearray()
                finally:
                    self._acquisition.close()
            finally:
                self._closing = False

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
