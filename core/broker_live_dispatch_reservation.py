"""Inactive original-source reservation composition; consume and discard only.

The model envelope is derived from an exact ready live dry-commit owner. No
caller receipt, observation, endpoint or payload is accepted. The native worker
still owns its child and join; this component performs no transport or file I/O.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field, asdict
import hashlib
import math
from threading import Event, RLock, Timer
from time import monotonic

from .broker_dispatch_attempt import PublicationDispatchLedger
from .broker_acquisition_draft import AcquisitionDraft
from .broker_live_channel_check import LiveChannelPublicationCheck
from .broker_live_review import LiveBrokerReview
from .broker_live_protocol import LiveMetadataExchange
from .broker_publication_commit_draft import PublicationCommitDraft
from .broker_publication_commit_protocol import PublicationCommitExchange
from .broker_publication_lifecycle import FinalPublicationDraftCheck, LivePublicationDraft
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .broker_publication_protocol import PublicationCheckExchange
from .broker_recipient_protocol import RecipientWitnessExchange
from .broker_recipient_process import _RecipientWitnessChild, _OwnershipApi
from .file_read_review import FileReadReviewLedger
from .registry import ApplicationRegistry
from .registry_bound_review import RegistryBoundFileReadReviews
from .json_input import loads

_MEANING = 'Retired inactive live dry reservation; not permission or delivery proof.'
_LOCK_TYPE = type(RLock())
_Original = namedtuple('_Original', 'gate draft helper source recipient acquisition review child buffer '
    'draft_wire draft_timer draft_cancel helper_wire helper_timer helper_cancel quarantine descriptor token '
    'lease registry registry_lock review_ledger review_ledger_lock reviews reviews_lock owner_locks native_lock '
    'model_ledger attempt model_envelope envelope deadline cancel timer codec_locks review_exchange review_timer native_api')


class LiveDispatchReservationError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveDispatchReservationEvidence:
    canonical_binding: bytes = field(repr=False)
    attempt_id: str
    binding_digest: str
    source_binding_digest: str
    recipient_digest: str
    staged_bytes: int
    staged_digest: str
    released_bytes: int = field(default=0, init=False)
    disposition: str = field(default='reserved_discarded', init=False)
    model_outcome: str = field(default='outcome_unknown', init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('A retired dry reservation is not permission')


def _values(value):
    return tuple((name, type(item), item) for name, item in asdict(value).items())


@contextmanager
def _review_guard(lock):
    # The original parent may already hold registry authority. Never wait on a
    # coordinator that could itself be waiting for that registry lock.
    if not lock.acquire(blocking=False):
        raise LiveDispatchReservationError('busy_live_review_owner')
    try: yield
    finally: lock.release()


class LiveDispatchReservationDryRun:
    """Bind current original authority to an irreversible *dry* reservation.

    Lock order: original helper -> commit -> reservation -> source -> recipient
    -> acquisition -> review -> nonblocking review coordinator -> registry -> review ledger -> native ownership
    -> model ledger. All model work is local metadata. No I/O or external wait
    occurs under the authority locks. The original worker alone joins its child.
    """
    def __init__(self, commit_draft, *, key, session, timeout=5):
        if type(commit_draft) is not PublicationCommitDraft:
            raise TypeError('expected exact original live commit draft')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_live_reservation_lifetime')
        self._lock, self._cancel = RLock(), Event()
        self._issued_cancel = self._cancel
        self._cancelled = False
        self._draft = self._issued_draft = commit_draft
        self._helper = self._issued_helper = helper = getattr(commit_draft, '_issued_helper', None)
        source, recipient = (getattr(commit_draft, name, None) for name in ('_issued_source', '_issued_recipient'))
        acquisition, review = (getattr(commit_draft, name, None) for name in ('_issued_acquisition', '_issued_review'))
        expected = ((helper, LiveChannelPublicationCheck), (source, LivePublicationDraft),
            (recipient, LogicalPublicationRecipient), (acquisition, AcquisitionDraft), (review, LiveBrokerReview))
        if (any(type(value) is not kind for value, kind in expected)
                or type(review._registry) is not ApplicationRegistry or type(review._ledger) is not FileReadReviewLedger
                or type(review._reviews) is not RegistryBoundFileReadReviews
                or review._registry is not review._reviews._registry or review._ledger is not review._reviews._ledger
                or type(commit_draft._issued_wire) is not PublicationCommitExchange
                or type(helper._issued_wire) is not RecipientWitnessExchange
                or type(source._wire) is not PublicationCheckExchange
                or type(review._exchange) is not LiveMetadataExchange
                or type(commit_draft._issued_child) is not _RecipientWitnessChild
                or type(commit_draft._issued_child._ownership) is not _OwnershipApi
                or type(commit_draft._issued_buffer) is not bytearray
                or type(helper._descriptor) is not RecipientDescriptor
                or helper._started is not True or helper._finished is not False or helper._cleanup_confirmed is not False
                or any(type(value) is not Timer for value in (commit_draft._issued_timer, helper._issued_timer, review._timer))
                or any(type(value) is not Event for value in (commit_draft._issued_cancel, helper._issued_cancel))):
            raise LiveDispatchReservationError('invalid_live_reservation_owner')
        locks = (helper._lock, commit_draft._lock, self._lock, source._lock,
                 recipient._lock, acquisition._lock, review._lock)
        if any(type(lock) is not _LOCK_TYPE for lock in locks):
            raise LiveDispatchReservationError('invalid_live_reservation_owner')
        # Bootstrap accepts a coherent, quiescent owner graph, not arbitrary
        # preexisting runtime mutations. Never wait on an unverifiable lock.
        bootstrap_locks = locks+(review._registry._lock, review._ledger._lock, review._reviews._lock,
            commit_draft._issued_child._ownership_lock)+tuple(wire._lock for wire in
            (commit_draft._issued_wire, helper._issued_wire, source._wire, review._exchange))
        for lock in bootstrap_locks:
            if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                raise LiveDispatchReservationError('busy_or_invalid_live_reservation_owner')
            lock.release()
        with ExitStack() as stack:
            for lock in locks: stack.enter_context(lock)
            stack.enter_context(_review_guard(review._reviews._lock))
            commit_draft._current('ready', 2)
            if commit_draft._attempted is not False:
                raise LiveDispatchReservationError('spent_live_reservation_owner')
            self._deadline = self._deadline_snapshot = min(monotonic()+timeout, commit_draft._deadline_snapshot)
            remaining = self._deadline-monotonic()
            if remaining <= 0: raise LiveDispatchReservationError('expired_live_reservation_owner')
            self._ledger = self._issued_ledger = PublicationDispatchLedger(max_attempts=1)
            try:
                self._attempt = self._issued_attempt = self._ledger.open(loads(commit_draft._envelope),
                    key=key, session=session, timeout=remaining)
                self._owned_buffer = commit_draft._issued_buffer
                self._timer = self._issued_timer = Timer(remaining, self.close)
                self._timer.daemon = True
                codec_locks = tuple((wire, wire._lock) for wire in
                    (commit_draft._issued_wire, helper._issued_wire, source._wire, review._exchange, self._attempt._issued_wire))
                if any(type(lock) is not _LOCK_TYPE for _, lock in codec_locks):
                    raise LiveDispatchReservationError('invalid_live_reservation_owner')
                original = _Original(self, commit_draft, helper, source, recipient, acquisition, review,
                    commit_draft._issued_child, self._owned_buffer, commit_draft._issued_wire,
                    commit_draft._issued_timer, commit_draft._issued_cancel, helper._issued_wire,
                    helper._issued_timer, helper._issued_cancel, source._wire, helper._descriptor,
                    source._issued_token, review._lease, review._registry, review._registry._lock,
                    review._ledger, review._ledger._lock, review._reviews, review._reviews._lock, locks,
                    commit_draft._issued_child._ownership_lock, self._ledger, self._attempt,
                    self._attempt._envelope, commit_draft._envelope, self._deadline, self._cancel, self._timer,
                    codec_locks, review._exchange, review._timer, commit_draft._issued_child._ownership)
                self._origin = self._issued_origin = self._recovery_origin = original
                self._save('new', False, False)
                self._timer.start()
                with self._authority(original): self._current('new', model_state='new')
            except Exception:
                if hasattr(self, '_origin'):
                    self.close()
                else: self._issued_ledger.close()
                raise LiveDispatchReservationError('live_reservation_unavailable') from None

    def _original(self):
        aliases = tuple(getattr(self, name, None) for name in ('_origin', '_issued_origin', '_recovery_origin'))
        for value in aliases:
            if type(value) is _Original and value.gate is self and sum(item is value for item in aliases) >= 2:
                return value
        raise LiveDispatchReservationError('uncertain_live_reservation_owner')

    @contextmanager
    def _owners(self, original):
        with ExitStack() as stack:
            for lock in original.owner_locks: stack.enter_context(lock)
            yield

    @contextmanager
    def _authority(self, original):
        self._identity(original)
        # Never recreate a lease from current requester data or a new activation.
        with _review_guard(original.reviews_lock), original.lease(), original.review_ledger_lock, original.native_lock:
            self._identity(original)
            yield

    def _save(self, state, attempted, terminal, *, result=None, notice=None, evidence=None):
        self._state, self._attempted, self._terminal = state, attempted, terminal
        self._issued_result, self._commit_notice = result, notice
        self._evidence = self._issued_evidence = evidence
        self._status = self._issued_status = (state, attempted, terminal, result,
            None if result is None else _values(result), notice, evidence,
            None if evidence is None else _values(evidence))
        history = self._original_history() if any(hasattr(self, name) for name in
            ('_history', '_issued_history', '_recovery_history')) else ()
        if history and history[-1][0] == 'closed': history = history[:-1]
        self._history = self._issued_history = self._recovery_history = history+(self._status,)

    def _original_history(self):
        aliases = tuple(getattr(self, name, None) for name in ('_history', '_issued_history', '_recovery_history'))
        for value in aliases:
            if (type(value) is tuple and 1 <= len(value) <= 8
                    and all(type(record) is tuple and len(record) == 8 for record in value)
                    and sum(item is value for item in aliases) >= 2):
                return value
        raise LiveDispatchReservationError('uncertain_live_reservation_state')

    def _identity(self, original, *, active=True):
        o = original
        if any(getattr(self, name, None) is not o for name in ('_origin', '_issued_origin', '_recovery_origin')):
            raise LiveDispatchReservationError('changed_live_reservation_owner')
        pointers = ((self, '_draft', o.draft), (self, '_issued_draft', o.draft),
            (self, '_helper', o.helper), (self, '_issued_helper', o.helper),
            (self, '_ledger', o.model_ledger), (self, '_issued_ledger', o.model_ledger),
            (self, '_attempt', o.attempt), (self, '_issued_attempt', o.attempt),
            (self, '_owned_buffer', o.buffer), (self, '_lock', o.owner_locks[2]),
            (self, '_cancel', o.cancel), (self, '_issued_cancel', o.cancel),
            (self, '_timer', o.timer), (self, '_issued_timer', o.timer),
            (o.draft, '_helper', o.helper), (o.draft, '_issued_helper', o.helper),
            (o.draft, '_source', o.source), (o.draft, '_issued_source', o.source),
            (o.draft, '_recipient', o.recipient), (o.draft, '_issued_recipient', o.recipient),
            (o.draft, '_acquisition', o.acquisition), (o.draft, '_issued_acquisition', o.acquisition),
            (o.draft, '_review', o.review), (o.draft, '_issued_review', o.review),
            (o.draft, '_buffer', o.buffer), (o.draft, '_issued_buffer', o.buffer),
            (o.draft, '_wire', o.draft_wire), (o.draft, '_issued_wire', o.draft_wire),
            (o.draft, '_timer', o.draft_timer), (o.draft, '_issued_timer', o.draft_timer),
            (o.draft, '_cancel', o.draft_cancel), (o.draft, '_issued_cancel', o.draft_cancel),
            (o.draft, '_child', o.child), (o.draft, '_issued_child', o.child),
            (o.helper, '_lifecycle', o.source), (o.helper, '_issued_lifecycle', o.source),
            (o.helper, '_recipient', o.recipient), (o.helper, '_issued_recipient', o.recipient),
            (o.helper, '_acquisition', o.acquisition), (o.helper, '_issued_acquisition', o.acquisition),
            (o.helper, '_review', o.review), (o.helper, '_issued_review', o.review),
            (o.helper, '_owned_buffer', o.buffer), (o.helper, '_wire', o.helper_wire),
            (o.helper, '_issued_wire', o.helper_wire), (o.helper, '_child', o.child),
            (o.helper, '_issued_child', o.child), (o.source, '_owned_buffer', o.buffer),
            (o.source, '_wire', o.quarantine), (o.source, '_recipient', o.recipient),
            (o.source, '_acquisition', o.acquisition), (o.source, '_review', o.review),
            (o.source, '_issued_token', o.token), (o.acquisition, '_review', o.review),
            (o.review, '_lease', o.lease), (o.review, '_registry', o.registry),
            (o.review, '_ledger', o.review_ledger), (o.review, '_reviews', o.reviews),
            (o.review, '_exchange', o.review_exchange), (o.review, '_timer', o.review_timer),
            (o.reviews, '_registry', o.registry), (o.reviews, '_ledger', o.review_ledger),
            (o.reviews, '_lock', o.reviews_lock),
            (o.registry, '_lock', o.registry_lock), (o.review_ledger, '_lock', o.review_ledger_lock),
            (o.child, '_ownership_lock', o.native_lock), (o.child, '_ownership', o.native_api))
        if any(getattr(owner, name, None) is not value for owner, name, value in pointers):
            raise LiveDispatchReservationError('changed_live_reservation_owner')
        if o.helper._started is not True or o.helper._finished is not False or o.helper._cleanup_confirmed is not False:
            raise LiveDispatchReservationError('changed_live_reservation_worker')
        owners = (o.helper, o.draft, self, o.source, o.recipient, o.acquisition, o.review)
        if any(getattr(owner, '_lock', None) is not lock for owner, lock in zip(owners, o.owner_locks)):
            raise LiveDispatchReservationError('changed_live_reservation_lock')
        if any(getattr(wire, '_lock', None) is not lock for wire, lock in o.codec_locks):
            raise LiveDispatchReservationError('changed_live_reservation_codec_lock')
        history = self._original_history()
        if (any(getattr(self, name, None) is not history for name in ('_history', '_issued_history', '_recovery_history'))
                or type(self._deadline) is not float or self._deadline != o.deadline
                or type(self._deadline_snapshot) is not float or self._deadline_snapshot != o.deadline
                or self._status is not self._issued_status or self._status is not history[-1]
                or type(self._attempted) is not bool or type(self._terminal) is not bool
                or (type(self._state), self._state, self._attempted, self._terminal) !=
                    (str, self._status[0], self._status[1], self._status[2])
                or self._issued_result is not self._status[3]
                or (self._issued_result is not None and _values(self._issued_result) != self._status[4])
                or self._commit_notice is not self._status[5]
                or self._evidence is not self._status[6] or self._issued_evidence is not self._status[6]
                or (self._evidence is not None and _values(self._evidence) != self._status[7])
                or type(o.draft._envelope) is not bytes or o.draft._envelope != o.envelope
                or o.draft._envelope_snapshot != o.envelope
                or o.attempt._envelope is not o.model_envelope):
            raise LiveDispatchReservationError('changed_live_reservation_state')
        if active and (self._cancelled is not False or o.cancel.is_set() or monotonic() >= o.deadline):
            raise LiveDispatchReservationError('expired_live_reservation')

    def _current(self, state, *, consumed=False, model_state):
        o = self._original()
        self._identity(o)
        if self._state != state: raise LiveDispatchReservationError('wrong_live_reservation_phase')
        o.draft._current('consumed' if consumed else 'ready', 3 if consumed else 2)
        self._identity(o)
        snapshot = o.attempt.inspect()
        if (type(snapshot.state) is not str or snapshot.state != model_state
                or type(snapshot.binding_digest) is not str or snapshot.binding_digest != hashlib.sha256(o.model_envelope).hexdigest()
                or type(snapshot.model_written_bytes) is not int or snapshot.model_written_bytes != 0
                or snapshot.receiver_claimed_bytes is not None or snapshot.observed_delivery != 'unproven'):
            raise LiveDispatchReservationError('changed_live_reservation_model')
        self._identity(o)

    def _cleanup_original(self, o):
        # Restore captured *ownership for disposal only*, never authority/state.
        # Foreign substituted owners, locks, timers and codecs are not invoked.
        for owner, lock in zip((o.helper, o.draft, self, o.source, o.recipient, o.acquisition, o.review), o.owner_locks):
            owner._lock = lock
        o.draft._helper = o.draft._issued_helper = o.helper
        o.draft._source = o.draft._issued_source = o.source
        o.draft._recipient = o.draft._issued_recipient = o.recipient
        o.draft._acquisition = o.draft._issued_acquisition = o.acquisition
        o.draft._review = o.draft._issued_review = o.review
        o.draft._buffer = o.draft._issued_buffer = o.buffer
        o.draft._wire = o.draft._issued_wire = o.draft_wire
        o.draft._timer = o.draft._issued_timer = o.draft_timer
        o.draft._cancel = o.draft._issued_cancel = o.draft_cancel
        o.helper._issued_lifecycle, o.helper._issued_recipient = o.source, o.recipient
        o.helper._issued_acquisition, o.helper._issued_review = o.acquisition, o.review
        o.helper._lifecycle, o.helper._recipient = o.source, o.recipient
        o.helper._acquisition, o.helper._review = o.acquisition, o.review
        o.helper._owned_buffer = o.buffer
        o.helper._started = True  # Admitted running worker; cancellation only signals it.
        o.helper._issued_wire, o.helper._issued_timer, o.helper._issued_cancel = o.helper_wire, o.helper_timer, o.helper_cancel
        o.source._wire, o.source._recipient = o.quarantine, o.recipient
        o.source._acquisition, o.source._review = o.acquisition, o.review
        o.acquisition._review = o.review
        o.review._registry, o.review._ledger, o.review._reviews, o.review._lease = o.registry, o.review_ledger, o.reviews, o.lease
        o.review._exchange, o.review._timer = o.review_exchange, o.review_timer
        o.registry._lock, o.review_ledger._lock = o.registry_lock, o.review_ledger_lock
        o.reviews._registry, o.reviews._ledger, o.reviews._lock = o.registry, o.review_ledger, o.reviews_lock
        for wire, lock in o.codec_locks: wire._lock = lock
        o.child._ownership_lock, o.child._ownership = o.native_lock, o.native_api
        o.draft._attempted, o.draft._terminal = True, False
        o.source._publication_attempted = True
        PublicationCommitDraft.close(o.draft)  # Signals worker, never joins child.

    def _close(self, o):
        try: status = self._original_history()[-1]
        except LiveDispatchReservationError: status = None
        success = (status is not None and status[0] in ('retired', 'closed')
                   and status[1] is True and status[2] is True
                   and type(status[3]) is FinalPublicationDraftCheck
                   and type(status[6]) is LiveDispatchReservationEvidence)
        failed = False
        if success:
            try:
                if _values(status[3]) != status[4] or _values(status[6]) != status[7]:
                    raise LiveDispatchReservationError('changed_archived_live_reservation')
            except Exception: success, failed = False, True
        try:
            # Disposal uses captured locks even if a codec's live alias changed.
            # This cannot make an operation fresh: the gate is being retired.
            for wire, lock in o.codec_locks: wire._lock = lock
            try: o.cancel.set()
            finally:
                try: o.model_ledger.close()
                finally: o.timer.cancel()
            snapshot = o.attempt.inspect()
            if o.model_ledger._closed is not True or snapshot.state not in ('not_started', 'outcome_unknown'):
                raise LiveDispatchReservationError('uncertain_live_reservation_cleanup')
            if not o.cancel.is_set() or not o.timer.finished.is_set():
                raise LiveDispatchReservationError('uncertain_live_reservation_cleanup')
        except Exception: failed = True
        finally:
            if not success:
                try: self._cleanup_original(o)
                except Exception: failed = True
                finally:
                    o.buffer[:] = b'\0'*len(o.buffer); o.buffer.clear()
            self._cancelled = True
            self._save('closed', True, True, result=status[3] if success else None,
                notice=status[5] if success else None, evidence=status[6] if success else None)
        if failed: raise LiveDispatchReservationError('live_reservation_cleanup_failed') from None

    def _reject(self, o):
        self._close(o)
        raise LiveDispatchReservationError('live_reservation_rejected') from None

    def _phase(self, state, operation):
        o = self._original()
        with self._owners(o):
            try:
                with self._authority(o):
                    self._current(state, model_state=state)
                    return operation(o)
            except Exception: self._reject(o)

    def prepare(self):
        def operation(o):
            frame = o.attempt.prepare()
            self._identity(o); o.draft._current('ready', 2); self._identity(o)
            self._save('prepared', False, False)
            self._current('prepared', model_state='prepared')
            return frame
        return self._phase('new', operation)

    def accept_ready(self, frame):
        def operation(o):
            o.attempt.accept_ready(frame)
            self._identity(o); o.draft._current('ready', 2); self._identity(o)
            self._save('ready', False, False)
            self._current('ready', model_state='ready')
        return self._phase('prepared', operation)

    def reserve_and_discard(self, app, credential, proposal, descriptor):
        o = self._original()
        with self._owners(o):
            try:
                self._identity(o)
                if self._attempted is not False: raise LiveDispatchReservationError('spent_live_reservation')
                self._save(self._state, True, False)
                with self._authority(o):
                    self._current('ready', model_state='ready')
                    notice = PublicationCommitDraft.commit(o.draft, app, credential, proposal, descriptor)
                    self._current('ready', consumed=True, model_state='ready')
                    result = o.draft._issued_result
                    if type(result) is not FinalPublicationDraftCheck or type(notice) is not bytes:
                        raise LiveDispatchReservationError('changed_live_reservation_result')
                    # Original source is now irreversibly spent/discarded. This
                    # private model barrier never exposes even a metadata notice.
                    o.attempt.begin_model_visibility()
                    self._current('ready', consumed=True, model_state='visibility_possible')
                    o.model_ledger.close()
                    self._current('ready', consumed=True, model_state='outcome_unknown')
                    o.timer.cancel()
                    if not o.timer.finished.is_set(): raise LiveDispatchReservationError('uncertain_live_reservation_cleanup')
                    envelope = loads(o.model_envelope)
                    evidence = LiveDispatchReservationEvidence(o.model_envelope, envelope['attempt_id'],
                        hashlib.sha256(o.model_envelope).hexdigest(), result.binding_digest, result.recipient_digest,
                        result.staged_bytes, result.staged_digest)
                    self._current('ready', consumed=True, model_state='outcome_unknown')
                    expected = (('canonical_binding', bytes, o.model_envelope),
                        ('attempt_id', str, envelope['attempt_id']),
                        ('binding_digest', str, hashlib.sha256(o.model_envelope).hexdigest()),
                        ('source_binding_digest', str, result.binding_digest), ('recipient_digest', str, result.recipient_digest),
                        ('staged_bytes', int, result.staged_bytes), ('staged_digest', str, result.staged_digest),
                        ('released_bytes', int, 0), ('disposition', str, 'reserved_discarded'),
                        ('model_outcome', str, 'outcome_unknown'), ('meaning', str, _MEANING))
                    if type(evidence) is not LiveDispatchReservationEvidence or _values(evidence) != expected:
                        raise LiveDispatchReservationError('changed_live_reservation_evidence')
                    self._save('retired', True, True, result=result, notice=notice, evidence=evidence)
                    self._current('retired', consumed=True, model_state='outcome_unknown')
                    return evidence
            except Exception: self._reject(o)

    def close(self):
        o = self._original()
        with self._owners(o): self._close(o)
