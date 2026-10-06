"""Inactive one-use fixed-peer channel witness. No acquisition or delivery API.

Trusted bootstrap assigns the fixed test peer to current application evidence.
This proves private launched-channel provenance, not installed application code
identity, human identity, resource truth or permission for a later operation.
"""
from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import math
import os
import secrets
from threading import Event, RLock, Timer
from time import monotonic, sleep
from . import broker_transport as transport
from .broker_acquisition_draft import AcquisitionDraft
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_live_review import LiveBrokerReview
from .broker_process import BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .broker_publication_protocol import _publication_binding
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .broker_recipient_process import _RecipientWitnessChild, ProcessChannelObservation
from .broker_recipient_protocol import RecipientWitnessExchange, RecipientWitnessEvidence, _MEANING as _WITNESS_MEANING
from .json_input import loads
from .structured_proposal import StructuredActionProposal


class RecipientChannelError(RuntimeError):
    pass


_RESULT_MEANING = 'Inactive fixed-peer channel witness; no later authority or delivery permission.'


@dataclass(frozen=True)
class RetiredRecipientChannelWitness:
    binding_digest: str
    recipient_digest: str
    process_id: int
    process_creation_time: int
    released_bytes: int = field(default=0, init=False)
    lifecycle: str = field(default='retired', init=False)
    meaning: str = field(default=_RESULT_MEANING, init=False)
    def __bool__(self): raise TypeError('A retired channel witness is not permission')


@dataclass(frozen=True)
class RecipientChannelShutdownStatus:
    cleanup_confirmed: bool


class _CoordinatorPort:
    def __init__(self, owner): self._owner = owner
    def reserve(self): return self._owner._reserve()
    def cancel(self): self._owner.close()


class _WorkerPort:
    def __init__(self, owner): self._owner = owner
    def run(self, token, app, credential, proposal): return self._owner._run(token, app, credential, proposal)


def _values(value):
    return tuple((name, type(item), item) for name, item in asdict(value).items())


class RecipientChannelProbe:
    """One exact live review/recipient owner, one fixed process, terminal evidence.

    Locks: probe -> recipient -> acquisition -> review -> registry -> ledger.
    External process I/O never holds registry/ledger locks. Cancellation sets an
    event; the worker alone closes and joins its child. Callers must join that
    worker before accepting shutdown status. <=5-second total lifetime, no renewal.
    """
    def __init__(self, acquisition, recipient, *, timeout=5):
        if type(acquisition) is not AcquisitionDraft or type(acquisition._review) is not LiveBrokerReview:
            raise TypeError('expected exact acquisition/review owner')
        if type(recipient) is not LogicalPublicationRecipient:
            raise TypeError('expected exact logical recipient owner')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_channel_lifetime')
        self._lock, self._cancel = RLock(), Event()
        self._issued_cancel = self._cancel
        self._cancelled = False
        self._acquisition = self._issued_acquisition = acquisition
        self._review = self._issued_review = acquisition._review
        self._recipient = self._issued_recipient = recipient
        self._deadline = self._deadline_snapshot = monotonic()+timeout
        self._source_deadline = None
        self._recipient_deadline = recipient._deadline_snapshot
        self._recipient_descriptor = self._recipient_snapshot = None
        self._token = self._issued_token = self._binding_snapshot = None
        self._child = self._issued_child = self._native_observation = self._child_snapshot = None
        self._wire = self._issued_wire = self._proof = self._proof_snapshot = self._ack = self._ack_snapshot = None
        self._wire_identity_snapshot = self._ack_transcript_digest = None
        self._state, self._started, self._finished = 'new', False, False
        self._cleanup_confirmed = self._owner_changed = False
        self.coordinator, self.worker = _CoordinatorPort(self), _WorkerPort(self)
        self._timer = self._issued_timer = Timer(timeout, self.close); self._timer.daemon = True
        try: self._timer.start()
        except Exception:
            self.close(); raise RecipientChannelError('channel_unavailable') from None

    def _identity_current(self):
        if (self._acquisition is not self._issued_acquisition
                or self._review is not self._issued_review
                or self._acquisition._review is not self._issued_review
                or self._recipient is not self._issued_recipient
                or self._owner_changed is not False):
            raise RecipientChannelError('changed_channel_owner')

    def _clock_current(self):
        if (type(self._deadline_snapshot) is not float or type(self._recipient_deadline) is not float
                or self._cancel is not self._issued_cancel or type(self._cancel) is not Event
                or self._cancelled is not False or self._timer is not self._issued_timer
                or type(self._timer) is not Timer
                or type(self._deadline) is not float or self._deadline != self._deadline_snapshot
                or self._cancel.is_set() or monotonic() >= self._deadline_snapshot
                or type(self._recipient._deadline) is not float
                or self._recipient._deadline != self._recipient_deadline
                or self._recipient._deadline_snapshot != self._recipient_deadline
                or monotonic() >= self._recipient_deadline
                or (self._source_deadline is not None and (type(self._source_deadline) is not float
                    or type(self._review._deadline) is not float
                    or self._review._deadline != self._source_deadline
                    or monotonic() >= self._source_deadline))):
            raise RecipientChannelError('expired_or_cancelled_channel')

    def _current(self):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            self._identity_current(); self._clock_current()
            if (type(self._state) is not str or self._state not in ('reserved', 'inflight')
                    or self._acquisition._closed is not False
                    or self._acquisition._attempted is not (self._state == 'inflight')
                    or type(self._binding_snapshot) is not bytes or type(self._recipient_snapshot) is not bytes
                    or self._token is not self._issued_token
                    or self._acquisition._issued is not self._token
                    or not self._acquisition._matches(self._token)):
                raise RecipientChannelError('channel_unavailable')
            self._recipient._current_for(self)
            if (self._recipient._issued is not self._recipient_descriptor
                    or type(self._recipient_descriptor) is not RecipientDescriptor
                    or _canonical(asdict(self._recipient_descriptor)) != self._recipient_snapshot
                    or self._recipient._snapshot != self._recipient_snapshot
                    or _publication_binding(dict(context=loads(self._token.canonical_context),
                        recipient=asdict(self._recipient_descriptor))) != self._binding_snapshot):
                raise RecipientChannelError('changed_channel_binding')
            self._acquisition._live('acquisition_reserved' if self._state == 'reserved' else 'recipient_channel_inflight')

    def _reserve(self):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            try:
                self._identity_current(); self._clock_current()
                if type(self._state) is not str or self._state != 'new' or self._started is not False or self._finished is not False:
                    raise RecipientChannelError('channel_unavailable')
                self._recipient._claim_for(self)
                self._recipient_descriptor = self._recipient._issued
                self._recipient_snapshot = self._recipient._snapshot
                self._token = self._issued_token = self._acquisition.coordinator.reserve()
                self._source_deadline = self._review._deadline
                if self._recipient_descriptor.application_id != self._review._app.application_id:
                    raise RecipientChannelError('wrong_recipient_application')
                self._binding_snapshot = _publication_binding(dict(context=loads(self._token.canonical_context),
                    recipient=asdict(self._recipient_descriptor)))
                self._state = 'reserved'; self._current()
                return self._token
            except Exception:
                self.close(); raise RecipientChannelError('channel_reservation_rejected') from None

    def _observe(self):
        self._native_observation = self._child._observe()
        if (type(self._native_observation) is not ProcessChannelObservation
                or self._native_observation is not self._child._issued_observation
                or type(self._native_observation.pid) is not int or not 0 < self._native_observation.pid <= 0xffffffff
                or type(self._native_observation.creation_time) is not int
                or not 0 < self._native_observation.creation_time <= 0xffffffffffffffff):
            raise RecipientChannelError('invalid_native_channel_observation')
        self._child_snapshot = _values(self._native_observation)

    def _native_current(self):
        if (type(self._child) is not _RecipientWitnessChild or self._child is not self._issued_child
                or type(self._native_observation) is not ProcessChannelObservation
                or _values(self._native_observation) != self._child_snapshot
                or self._child._observe() is not self._native_observation):
            raise RecipientChannelError('changed_native_channel')
        self._child._validate()

    def _evidence_current(self, evidence, outcome):
        if (type(evidence) is not RecipientWitnessEvidence
                or type(evidence.canonical_binding) is not bytes or evidence.canonical_binding != self._binding_snapshot
                or type(evidence.binding_digest) is not str
                or evidence.binding_digest != hashlib.sha256(self._binding_snapshot).hexdigest()
                or type(evidence.outcome) is not str or evidence.outcome != outcome
                or type(evidence.released_bytes) is not int or evidence.released_bytes != 0
                or type(evidence.meaning) is not str or evidence.meaning != _WITNESS_MEANING):
            raise RecipientChannelError('changed_channel_proof')

    def _wire_current(self, step):
        wire = self._wire
        if (type(wire) is not RecipientWitnessExchange or wire is not self._issued_wire
                or type(wire._step) is not int or wire._step != step):
            raise RecipientChannelError('changed_channel_exchange')
        with wire._lock:
            if step < 4:
                wire._integrity()
                if wire._binding != self._binding_snapshot: raise RecipientChannelError('changed_channel_exchange')
            elif (type(wire._state) is not str or wire._state != 'closed'
                    or type(wire._key) is not bytes or wire._key
                    or wire._binding is not None or wire._binding_snapshot is not None
                    or wire._binding_digest is not None
                    or tuple((type(item), item) for item in (wire._role, wire._role_snapshot,
                        wire._session, wire._session_snapshot, wire._key_snapshot)) != self._wire_identity_snapshot
                    or type(wire._previous) is not str or wire._previous != self._ack_transcript_digest
                    or type(wire._phase_snapshot) is not tuple
                    or wire._phase_snapshot != (4, self._ack_transcript_digest, 'closed')
                    or any(type(item) is not expected for item, expected in zip(wire._phase_snapshot, (int, str, str)))):
                raise RecipientChannelError('unretired_channel_exchange')

    def _run(self, token, app, credential, proposal):
        with self._lock:
            if self._started is not False or self._finished is not False:
                self.close(); raise RecipientChannelError('channel_unavailable')
            self._started = True
        child = None
        acquired, cleanup_ok = False, True
        try:
            with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
                self._current()
                self._acquisition._attempted = True  # Spend invalid attempts before authentication.
                with self._review._lease(), self._review._ledger._lock:
                    if (token is not self._token or type(app) is not str
                            or type(credential) is not str or not 1 <= len(credential) <= 512
                            or type(proposal) is not StructuredActionProposal
                            or self._review._registry.authenticate(app, credential) is not self._review._app
                            or proposal.canonical_bytes() != self._review._proposal_snapshot):
                        raise RecipientChannelError('wrong_channel_request')
                    self._acquisition._live('acquisition_reserved')
                    self._state, self._review._state = 'inflight', 'recipient_channel_inflight'
                    self._current()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            self._wire = self._issued_wire = RecipientWitnessExchange(role='coordinator', key=key, session=session)
            self._wire_identity_snapshot = tuple((type(item), item) for item in (self._wire._role,
                self._wire._role_snapshot, self._wire._session, self._wire._session_snapshot, self._wire._key_snapshot))
            request = self._wire.request(loads(self._binding_snapshot)); self._wire_current(1)
            acquired = transport._slot.acquire(blocking=False)
            if not acquired: raise RecipientChannelError('busy_or_unavailable')
            self._current()
            child = self._child = self._issued_child = _RecipientWitnessChild()
            self._observe(); self._native_current()

            def check():
                self._current(); self._native_current()
            def write(data):
                offset = 0
                while offset < len(data):
                    check()
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if count <= 0: raise RecipientChannelError('pipe_failed')
                        offset += count
                    except BlockingIOError: sleep(.002)
                    check()
            def read(size, *, retired=False):
                output = bytearray()
                while len(output) < size:
                    self._current()
                    if retired: child._validate(retiring=True)
                    else: self._native_current()
                    try:
                        chunk = os.read(child.stdout_fd, size-len(output))
                        if not chunk: raise RecipientChannelError('truncated_channel_output')
                        output.extend(chunk)
                    except BlockingIOError: sleep(.002)
                    self._current()
                    if retired: child._validate(retiring=True)
                    else: self._native_current()
                return bytes(output)
            def frame(*, retired=False):
                prefix = read(4, retired=retired); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32: raise RecipientChannelError('channel_output_limit')
                return prefix+read(size, retired=retired)

            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, self._native_observation.pid)):
                raise RecipientChannelError('channel_startup_rejected')
            write(request)
            self._proof = self._wire.accept_proof(frame())
            self._evidence_current(self._proof, 'witnessed'); self._proof_snapshot = _values(self._proof)
            self._wire_current(2); check()
            write(self._wire.retire()); self._wire_current(3); check()
            child.close_input()
            # A retiring peer can exit immediately. Validate remaining ownership
            # without requiring liveness during EOF/exit, then join before ACK use.
            ack = frame(retired=True)
            while True:
                self._current(); child._validate(retiring=True)
                try:
                    if os.read(child.stdout_fd, 1): raise RecipientChannelError('trailing_channel_output')
                    break
                except BlockingIOError: sleep(.002)
            while child.poll() is None:
                self._current(); child._validate(retiring=True); sleep(.002)
            if child.poll() != 0: raise RecipientChannelError('channel_child_failed')
            child.close(); child._retired()
            if type(child._exit) is not int or child._exit != 0:
                raise RecipientChannelError('channel_child_failed')
            self._current(); self._wire_current(3)
            self._ack = self._wire.accept_ack(ack)
            self._ack_transcript_digest = hashlib.sha256(ack).hexdigest()
            self._evidence_current(self._ack, 'retired'); self._ack_snapshot = _values(self._ack)
            self._wire_current(4); self._current()
            result = RetiredRecipientChannelWitness(hashlib.sha256(self._binding_snapshot).hexdigest(),
                hashlib.sha256(self._recipient_snapshot).hexdigest(), self._native_observation.pid,
                self._native_observation.creation_time)
            result_snapshot = _values(result)
        except BrokerProcessError as error:
            if str(error) == 'process_cleanup_failed': cleanup_ok = False
            raise RecipientChannelError('channel_process_failed') from None
        except Exception:
            raise RecipientChannelError('channel_witness_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally: self._dispose_sources()
            except BaseException:
                cleanup_ok = False
                raise RecipientChannelError('channel_cleanup_failed') from None
            finally:
                try:
                    if acquired and cleanup_ok: transport._slot.release()
                except BaseException:
                    cleanup_ok = False
                    raise RecipientChannelError('channel_cleanup_failed') from None
                finally:
                    with self._lock:
                        self._state, self._finished, self._cleanup_confirmed = 'closed', True, cleanup_ok
        try:
            with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
                with self._review._lease(), self._review._ledger._lock:
                    self._final_current(token, proposal)
                    if (type(result) is not RetiredRecipientChannelWitness or _values(result) != result_snapshot
                            or type(result.binding_digest) is not str
                            or result.binding_digest != hashlib.sha256(self._binding_snapshot).hexdigest()
                            or type(result.recipient_digest) is not str
                            or result.recipient_digest != hashlib.sha256(self._recipient_snapshot).hexdigest()
                            or type(result.process_id) is not int or result.process_id != self._native_observation.pid
                            or type(result.process_creation_time) is not int
                            or result.process_creation_time != self._native_observation.creation_time
                            or type(result.released_bytes) is not int or result.released_bytes != 0
                            or type(result.lifecycle) is not str or result.lifecycle != 'retired'
                            or type(result.meaning) is not str or result.meaning != _RESULT_MEANING):
                        raise RecipientChannelError('changed_channel_result')
                    # Reentrant validation hooks cannot cancel, expire or change
                    # authority between the evidence check and metadata return.
                    self._final_current(token, proposal)
                    return result
        except BrokerProcessError:
            transport._slot.acquire(blocking=False)  # Poison free admission on native uncertainty.
            with self._lock: self._cleanup_confirmed = False
            raise RecipientChannelError('stale_channel_retirement') from None
        except Exception: raise RecipientChannelError('stale_channel_retirement') from None

    def _dispose_sources(self):
        try:
            self._issued_timer.cancel()
        finally:
            if self._issued_acquisition._review is not self._issued_review:
                self._owner_changed = True
                self._issued_acquisition._review = self._issued_review  # Cleanup original ownership only.
            try:
                if self._issued_wire is not None: self._issued_wire.close()
            finally:
                try: self._issued_acquisition.close()
                finally: self._issued_recipient.close()

    def _final_current(self, token, proposal):
        with self._lock, self._recipient._lock, self._acquisition._lock, self._review._lock:
            self._identity_current(); self._clock_current(); self._wire_current(4)
            self._recipient._validate_descriptor(); self._issued_child._retired()
            self._evidence_current(self._proof, 'witnessed'); self._evidence_current(self._ack, 'retired')
            with self._review._lease(), self._review._ledger._lock:
                if (type(self._state) is not str or self._state != 'closed' or self._started is not True
                        or self._finished is not True or self._cleanup_confirmed is not True
                        or type(self._binding_snapshot) is not bytes or type(self._recipient_snapshot) is not bytes
                        or self._child is not self._issued_child
                        or type(self._native_observation) is not ProcessChannelObservation
                        or self._native_observation is not self._issued_child._issued_observation
                        or type(self._issued_child._exit) is not int or self._issued_child._exit != 0
                        or _values(self._native_observation) != self._child_snapshot
                        or _values(self._proof) != self._proof_snapshot or _values(self._ack) != self._ack_snapshot
                        or self._token is not self._issued_token or token is not self._token
                        or not self._acquisition._matches(token) or self._acquisition._issued is not None
                        or self._acquisition._attempted is not True or self._acquisition._closed is not True
                        or type(self._review._state) is not str or self._review._state != 'closed'
                        or self._review._app_state() != self._review._app_snapshot
                        or self._review._draft() != self._review._draft_snapshot
                        or _canonical(asdict(self._review._ticket)) != self._review._ticket_snapshot
                        or type(proposal) is not StructuredActionProposal
                        or proposal.canonical_bytes() != self._review._proposal_snapshot
                        or self._review._proposal.canonical_bytes() != self._review._proposal_snapshot
                        or self._review._shown is not self._review._facts
                        or _canonical(asdict(self._review._shown)) != self._review._facts_snapshot
                        or type(self._review._decision) is not str or self._review._decision != 'allow_once'
                        or self._review._ledger._reviews.get(self._review._ticket.review.draft_id) is not None
                        or self._review._reviews._pending.get(self._review._ticket.review.draft_id) is not None
                        or self._recipient._terminal is not True or type(self._recipient._state) is not str
                        or self._recipient._state != 'closed' or self._recipient._claim is not None
                        or self._recipient._ever_claimed is not True
                        or self._recipient._issued is not self._recipient_descriptor
                        or self._recipient._snapshot != self._recipient_snapshot
                        or _publication_binding(dict(context=loads(token.canonical_context),
                            recipient=asdict(self._recipient_descriptor))) != self._binding_snapshot):
                    raise RecipientChannelError('changed_after_channel_cleanup')
                self._clock_current()

    def close(self):
        with self._lock:
            self._cancelled = True
            self._issued_cancel.set()
            if not self._started:
                cleanup_ok = True
                try: self._dispose_sources()
                except BaseException:
                    cleanup_ok = False
                    raise RecipientChannelError('channel_cleanup_failed') from None
                finally:
                    self._state, self._finished = 'closed', True
                    self._cleanup_confirmed = cleanup_ok

    def shutdown_status(self):
        with self._lock:
            if self._finished is not True: return None
            return RecipientChannelShutdownStatus(self._cleanup_confirmed is True)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
