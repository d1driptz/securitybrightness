"""Inactive logical-source admission custody; no fixture launcher or delivery.

Trusted bootstrap owns the exact logical source and synthetic adapter transitions.
One original shared slot stays held across those transitions and a fixed private
two-worker rendezvous. Native fixture acquisition and human-wait composition are
NOT implemented here. No requester flag, cleanup callback or permission exists.
"""
from collections import deque, namedtuple
from contextlib import contextmanager, ExitStack
from dataclasses import asdict
import math
from threading import BoundedSemaphore, Condition, Event, Lock, RLock, Thread, Timer, current_thread
from time import monotonic

from . import broker_transport as transport
from .broker_acquisition_draft import AcquisitionDraft
from .broker_live_protocol import LiveMetadataExchange
from .broker_live_review import LiveBrokerReview
from .broker_protocol import _canonical
from .broker_publication_lifecycle import LivePublicationDraft
from .broker_publication_protocol import PublicationCheckExchange
from .broker_publication_recipient import LogicalPublicationRecipient, RecipientDescriptor
from .broker_source_native_association import SourceNativeAssociationEvidence, _facts
from .broker_source_rendezvous import SourceAssociationRendezvousDryRun, SourceRendezvousError, _History
from .file_read_review import FileReadReviewLedger
from .registry import ApplicationRegistry
from .registry_bound_review import RegistryBoundFileReadReviews

_RLOCK, _LOCK, _SLOT = type(RLock()), type(Lock()), type(BoundedSemaphore(1))
_Owner = namedtuple('_Owner', 'custody lock cancel deadline thread ident slot condition slot_lock waiters notify notify_function is_owned owned_function source_seen review_seen wire_seen handoff_seen retired')
_Source = namedtuple('_Source', 'source acquisition review recipient registry ledger fields locks descriptor descriptor_snapshot recipient_timer recipient_finished recipient_deadline')
_Review = namedtuple('_Review', 'timer finished lease deadline ticket ticket_snapshot draft_id proposal proposal_snapshot app app_snapshot draft_snapshot identity')
_Wire = namedtuple('_Wire', 'wire lock buffer deadline timer finished')
_Status = namedtuple('_Status', 'stage acquired bound begun wire_seen attempted claimed returned cleanup released poisoned gate gate_owner seal result snapshot')
_Link = namedtuple('_Link', 'gate custody owner source gate_owner')


class SourceAdmissionError(RuntimeError):
    pass


class _SourceAdmissionCustody:
    """Private, one-thread bootstrap custody, <=5 seconds, never authority.

    acquire -> bind NEW source -> begin_review -> begin_acquisition -> finish.
    Existing separate operator/model ports still perform synthetic review and
    authenticated staging. close only signals; the original bootstrap worker
    must finish/abort. Unknown cleanup poisons admission with no reset API.
    """
    def __init__(self, *, timeout=5):
        if type(self) is not _SourceAdmissionCustody:
            raise TypeError('expected exact admission custody')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise SourceAdmissionError('invalid_admission_lifetime')
        slot = transport._slot
        if (type(slot) is not _SLOT or type(slot._initial_value) is not int or slot._initial_value != 1
                or type(slot._cond) is not Condition or type(slot._cond._lock) is not _LOCK
                or type(slot._cond._waiters) is not deque):
            raise SourceAdmissionError('invalid_admission_owner')
        owner = _Owner(self, RLock(), Event(), monotonic()+timeout, current_thread(), current_thread().ident,
            slot, slot._cond, slot._cond._lock, slot._cond._waiters, slot._cond.notify,
            Condition.notify, slot._cond.__dict__.get('_is_owned'), Condition._is_owned,
            Event(), Event(), Event(), Event(), Event())
        self._origin = self._issued_origin = self._recovery_origin = owner
        self._lock, self._cancel, self._deadline = owner.lock, owner.cancel, owner.deadline
        self._source = self._issued_source = self._recovery_source = None
        self._review = self._issued_review = self._recovery_review = None
        self._wire = self._issued_wire = self._recovery_wire = None
        self._save('new')

    @staticmethod
    def _recover(values, kind, *, optional=False):
        if optional and all(value is None for value in values): return None
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise SourceAdmissionError('uncertain_admission_archive')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Owner)

    def _archive(self, name, kind):
        value = self._recover(tuple(getattr(self, prefix+name, None) for prefix in
            ('_', '_issued_', '_recovery_')), kind, optional=True)
        if any(getattr(self, prefix+name, None) is not value for prefix in ('_', '_issued_', '_recovery_')):
            raise SourceAdmissionError('changed_admission_archive')
        return value

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _Status)

    def _save(self, stage=None, **changes):
        if not hasattr(self, '_history'):
            history = _Status('new', *(False for _ in range(10)), None, None, None, None, None)
        else: history = self._status()
        if stage is not None: changes['stage'] = stage
        history = history._replace(**changes)
        self._history = self._issued_history = self._recovery_history = history
        self._state = history.stage
        return history

    def _identity(self, *, active=True, thread=False):
        owner, history = self._original(), self._status()
        if (owner.custody is not self
                or any(getattr(self, name, None) is not owner for name in ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in ('_history', '_issued_history', '_recovery_history'))
                or self._lock is not owner.lock or self._cancel is not owner.cancel
                or type(self._deadline) is not float or self._deadline != owner.deadline
                or type(self._state) is not str or self._state != history.stage
                or type(history.stage) is not str or any(type(flag) is not bool for flag in history[1:11])
                or transport._slot is not owner.slot or owner.slot._cond is not owner.condition
                or owner.condition._lock is not owner.slot_lock or owner.condition._waiters is not owner.waiters
                or type(owner.slot._initial_value) is not int or owner.slot._initial_value != 1
                or Condition.notify is not owner.notify_function or Condition._is_owned is not owner.owned_function
                or getattr(owner.notify, '__self__', None) is not owner.condition
                or getattr(owner.notify, '__func__', None) is not owner.notify_function
                or owner.condition.__dict__.get('_is_owned') is not owner.is_owned
                or owner.condition.notify.__self__ is not owner.condition
                or owner.condition.notify.__func__ is not owner.notify_function
                or any(type(waiter) is not _LOCK for waiter in owner.waiters)
                or (thread and (current_thread() is not owner.thread or current_thread().ident != owner.ident))):
            raise SourceAdmissionError('changed_admission_owner')
        if (history.bound is not owner.source_seen.is_set() or history.begun is not owner.review_seen.is_set()
                or history.wire_seen is not owner.wire_seen.is_set()
                or history.attempted is not owner.handoff_seen.is_set()
                or owner.retired.is_set() and history.released is not True):
            raise SourceAdmissionError('rolled_back_admission_history')
        source = self._archive('source', _Source)
        review, wire = self._archive('review', _Review), self._archive('wire', _Wire)
        if (history.bound is not (source is not None) or history.begun is not (review is not None)
                or history.wire_seen is not (wire is not None)):
            raise SourceAdmissionError('missing_admission_archive')
        if history.gate is not None and history.stage != 'constructing' and history.gate_owner is None:
            raise SourceAdmissionError('missing_admission_gate_owner')
        if source is not None:
            if (any(getattr(obj, name, None) is not value for obj, name, value in source.fields)
                    or source.recipient._descriptor is not source.descriptor or source.recipient._issued is not source.descriptor
                    or type(source.descriptor) is not RecipientDescriptor
                    or _canonical(asdict(source.descriptor)) != source.descriptor_snapshot
                    or source.recipient._snapshot != source.descriptor_snapshot
                    or source.recipient._timer is not source.recipient_timer
                    or source.recipient_timer.finished is not source.recipient_finished
                    or type(source.recipient._deadline) is not float or source.recipient._deadline != source.recipient_deadline
                    or type(source.recipient._deadline_snapshot) is not float
                    or source.recipient._deadline_snapshot != source.recipient_deadline):
                raise SourceAdmissionError('changed_admission_source')
            if (review is None and source.review._timer is not None
                    or wire is None and (source.source._wire is not None or source.source._owned_buffer is not None)):
                raise SourceAdmissionError('untracked_admission_resource')
        if review is not None and (source.review._timer is not review.timer or review.timer.finished is not review.finished
                or source.review._lease is not review.lease or type(source.review._deadline) is not float
                or source.review._deadline != review.deadline or source.review._ticket is not review.ticket
                or _canonical(asdict(review.ticket)) != review.ticket_snapshot
                or source.review._ticket_snapshot != review.ticket_snapshot
                or source.review._proposal is not review.proposal or source.review._proposal_snapshot != review.proposal_snapshot
                or review.proposal.canonical_bytes() != review.proposal_snapshot
                or source.review._app is not review.app or source.review._app_snapshot != review.app_snapshot
                or source.review._draft_snapshot != review.draft_snapshot or source.review._identity != review.identity):
            raise SourceAdmissionError('changed_admission_review')
        if wire is not None and (source.source._wire is not wire.wire or source.source._owned_buffer is not wire.buffer
                or wire.wire._lock is not wire.lock or wire.wire._buffer is not wire.buffer
                or wire.wire._issued_buffer is not wire.buffer or wire.wire._timer is not wire.timer
                or wire.wire._timer_snapshot is not wire.timer or wire.timer.finished is not wire.finished
                or type(wire.buffer) is not bytearray or type(wire.wire._deadline) is not float
                or wire.wire._deadline != wire.deadline or wire.wire._deadline_snapshot != wire.deadline):
            raise SourceAdmissionError('changed_admission_quarantine')
        if history.poisoned or (active and (owner.cancel.is_set() or monotonic() >= owner.deadline)):
            raise SourceAdmissionError('unavailable_admission')
        return history

    @contextmanager
    def _control(self):
        owner = self._original()
        if type(owner.lock) is not _RLOCK or not owner.lock.acquire(blocking=False):
            raise SourceAdmissionError('busy_admission_control')
        try: yield owner
        except BaseException:
            # Structural/protocol rejection while still owning admission is
            # irreversible. Restoring fields cannot make this owner usable.
            if owner.custody is self and current_thread() is owner.thread:
                history = self._status()
                if history.acquired and not history.released: self._poison()
            raise
        finally: owner.lock.release()

    @contextmanager
    def _guards(self):
        source = self._archive('source', _Source)
        wire = self._archive('wire', _Wire)
        locks = (() if source is None else source.locks)+( () if wire is None else (wire.lock,))
        with ExitStack() as stack:
            for lock in locks:
                if type(lock) is not _RLOCK or not lock.acquire(blocking=False):
                    raise SourceAdmissionError('busy_admission_source')
                stack.callback(lock.release)
            yield

    def acquire(self):
        with self._control() as owner:
            history = self._identity(thread=True)
            if history.stage != 'new': raise SourceAdmissionError('admission_attempt_spent')
            self._save('attempted')  # Even a busy admission is a spent attempt.
            if not owner.slot_lock.acquire(blocking=False): raise SourceAdmissionError('busy_admission')
            try:
                self._identity(thread=True)
                if type(owner.slot._value) is not int or owner.slot._value != 1:
                    raise SourceAdmissionError('busy_admission')
                owner.slot._value = 0
                self._save('fixture', acquired=True)
            finally: owner.slot_lock.release()

    def bind_source(self, source):
        with self._control():
            history = self._identity(thread=True)
            if history.stage != 'fixture' or history.bound or type(source) is not LivePublicationDraft:
                raise SourceAdmissionError('invalid_admission_source')
            acquisition, review, recipient = source._acquisition, source._review, source._recipient
            if (type(acquisition) is not AcquisitionDraft or type(review) is not LiveBrokerReview
                    or type(recipient) is not LogicalPublicationRecipient or acquisition._review is not review
                    or type(review._registry) is not ApplicationRegistry or type(review._ledger) is not FileReadReviewLedger
                    or type(review._reviews) is not RegistryBoundFileReadReviews
                    or review._reviews._registry is not review._registry or review._reviews._ledger is not review._ledger
                    or type(review._exchange) is not LiveMetadataExchange):
                raise SourceAdmissionError('invalid_admission_source')
            fields = tuple((obj, name, getattr(obj, name)) for obj, names in (
                (source, ('_lock', '_acquisition', '_review', '_recipient')),
                (acquisition, ('_lock', '_review')), (recipient, ('_lock',)),
                (review, ('_lock', '_registry', '_ledger', '_reviews', '_exchange')),
                (review._registry, ('_lock',)), (review._ledger, ('_lock',)),
                (review._reviews, ('_lock', '_registry', '_ledger')), (review._exchange, ('_lock',))) for name in names)
            locks = (source._lock, recipient._lock, acquisition._lock, review._lock,
                review._reviews._lock, review._registry._lock, review._ledger._lock, review._exchange._lock)
            if (any(type(lock) is not _RLOCK for lock in locks) or type(recipient._timer) is not Timer
                    or type(recipient._timer.finished) is not Event):
                raise SourceAdmissionError('invalid_admission_source')
            with ExitStack() as stack:
                for lock in locks:
                    if not lock.acquire(blocking=False): raise SourceAdmissionError('busy_admission_source')
                    stack.callback(lock.release)
                recipient._current()
                if (type(source._state) is not str or source._state != 'new' or source._cancelled is not False
                        or source._publication_attempted is not False or source._wire is not None
                        or source._owned_buffer is not None or source._token is not None or source._closing is not False
                        or source._summary is not None or source._retirement is not None
                        or source._recipient_snapshot is not None or source._recipient_descriptor is not None
                        or source._source_deadline_snapshot is not None
                        or type(review._state) is not str or review._state != 'new'
                        or review._ticket is not None or review._timer is not None or review._shown is not None
                        or acquisition._closed is not False or acquisition._attempted is not False
                        or acquisition._issued is not None or recipient._ever_claimed is not False
                        or recipient._claim is not None or recipient._state != 'new'):
                    raise SourceAdmissionError('source_already_started')
                value = _Source(source, acquisition, review, recipient, review._registry, review._ledger,
                    fields, locks, recipient._issued, recipient._snapshot, recipient._timer,
                    recipient._timer.finished, recipient._deadline_snapshot)
                self._source = self._issued_source = self._recovery_source = value
                self._original().source_seen.set()
                self._save(bound=True)
                self._identity(thread=True)

    def begin_review(self, app, credential, proposal, draft_id, revision):
        with self._control(), self._guards():
            history = self._identity(thread=True)
            if history.stage != 'fixture' or not history.bound or history.begun:
                raise SourceAdmissionError('review_attempt_spent')
            source = self._source
            self._save('review_starting')
            self._original().review_seen.set()
            try:
                frame = source.review.coordinator.begin(app, credential, proposal, draft_id, revision)
                timer = source.review._timer
                if type(timer) is not Timer or type(timer.finished) is not Event:
                    raise SourceAdmissionError('invalid_review_timer')
                value = _Review(timer, timer.finished, source.review._lease, source.review._deadline,
                    source.review._ticket, source.review._ticket_snapshot, source.review._ticket.review.draft_id,
                    source.review._proposal, source.review._proposal_snapshot, source.review._app,
                    source.review._app_snapshot, source.review._draft_snapshot, source.review._identity)
                self._review = self._issued_review = self._recovery_review = value
                self._save('fixture', begun=True)
                self._identity(thread=True)
                return frame
            except BaseException:
                self._poison()
                raise SourceAdmissionError('review_begin_rejected') from None

    def begin_acquisition(self, token, app, credential, proposal):
        with self._control(), self._guards():
            history = self._identity(thread=True)
            if history.stage != 'fixture' or not history.begun or self._wire is not None:
                raise SourceAdmissionError('acquisition_attempt_spent')
            self._save('acquisition_starting')
            self._original().wire_seen.set()
            try:
                frame = self._source.source.adapter.begin(token, app, credential, proposal)
                wire = self._source.source._wire
                if (type(wire) is not PublicationCheckExchange or type(wire._lock) is not _RLOCK
                        or type(wire._buffer) is not bytearray or type(wire._timer) is not Timer
                        or type(wire._timer.finished) is not Event or wire._timer_snapshot is not wire._timer):
                    raise SourceAdmissionError('invalid_source_quarantine')
                value = _Wire(wire, wire._lock, wire._buffer, wire._deadline_snapshot, wire._timer, wire._timer.finished)
                self._wire = self._issued_wire = self._recovery_wire = value
                self._save('fixture', wire_seen=True)
                self._identity(thread=True)
                return frame
            except BaseException:
                self._poison()
                raise SourceAdmissionError('acquisition_begin_rejected') from None

    def _gate_current(self, gate, *, active=True):
        history = self._identity(active=active)
        if (type(gate) is not _CustodiedRendezvous or history.gate is not gate
                or history.stage not in ('constructing', 'rendezvous', 'retained', 'sealing', 'retired')
                or not history.acquired or not history.attempted or self._wire is None):
            raise SourceAdmissionError('wrong_admission_handoff')
        return history

    def _claim(self, gate):
        with self._control():
            history = self._gate_current(gate)
            self._identity(thread=True)
            if history.stage != 'rendezvous' or history.claimed:
                raise SourceAdmissionError('admission_handoff_spent')
            self._save(claimed=True)

    def _returned(self, gate, seal):
        with self._control():
            history = self._gate_current(gate, active=False)
            self._identity(active=False, thread=True)
            if history.stage != 'rendezvous' or not history.claimed or history.returned:
                raise SourceAdmissionError('admission_return_spent')
            gate._terminal_current(seal, gate._issued_result)
            self._save('retained', returned=True, seal=seal)

    def _cleanup_current(self):
        history = self._identity(active=False)
        source, review, wire = self._source, self._review, self._wire
        if source is not None:
            if (source.source._state != 'closed' or type(source.source._state) is not str
                    or source.acquisition._closed is not True or source.review._state != 'closed'
                    or type(source.review._state) is not str or source.recipient._terminal is not True
                    or type(source.recipient._state) is not str or source.recipient._state != 'closed' or source.recipient._claim is not None
                    or type(source.review._exchange._key) is not bytes or source.review._exchange._key != b''
                    or type(source.review._exchange._state) is not str or source.review._exchange._state != 'closed'
                    or not source.recipient_finished.is_set()
                    or (source.source._owned_buffer is not None and (type(source.source._owned_buffer) is not bytearray
                        or source.source._owned_buffer))):
                raise SourceAdmissionError('unretired_admission_source')
            if review is not None:
                draft_id = review.draft_id
                if draft_id in source.ledger._reviews or draft_id in source.review._reviews._pending:
                    raise SourceAdmissionError('unretired_admission_review')
        if review is not None and not review.finished.is_set():
            raise SourceAdmissionError('unretired_review_timer')
        if wire is not None and (wire.buffer or type(wire.wire._key) is not bytes
                or wire.wire._key != b'' or type(wire.wire._state) is not str or wire.wire._state != 'closed'
                or not wire.finished.is_set()):
            raise SourceAdmissionError('unretired_source_wire')
        if history.gate is not None:
            if not history.returned or type(history.gate) is not _CustodiedRendezvous:
                raise SourceAdmissionError('uncertain_admission_handoff')
            history.gate._terminal_current(history.seal, history.gate._issued_result)
            history.gate._cleanup_current()
        self._identity(active=False)

    def _terminal_current(self, sealed, candidate):
        history = self._identity(active=False)
        if (history is not sealed or history.stage != 'retired' or history.cleanup is not True
                or history.released is not True or history.result is not candidate
                or (candidate is not None and (type(candidate) is not SourceNativeAssociationEvidence
                    or _facts(candidate) != history.snapshot))):
            raise SourceAdmissionError('changed_admission_terminal')

    def _retire(self, candidate):
        owner = self._original()
        with self._control(), self._guards():
            history = self._identity(active=False, thread=True)
            if not history.acquired or history.released or history.stage not in ('fixture', 'retained'):
                raise SourceAdmissionError('admission_retirement_spent')
            if not owner.slot_lock.acquire(blocking=False): raise SourceAdmissionError('busy_admission_retirement')
            try:
                if type(owner.slot._value) is not int or owner.slot._value != 0:
                    raise SourceAdmissionError('changed_admission_value')
                self._cleanup_current()
                if candidate is not None:
                    try: history.gate._final_current(candidate)
                    except BaseException: candidate = None
                self._save('sealing')
                sealed = self._save('retired', cleanup=True, released=True, result=candidate,
                    snapshot=_facts(candidate) if candidate is not None else None)
                self._terminal_current(sealed, candidate)
                owner.slot._value = 1
                owner.notify()
                self._cleanup_current()
                if candidate is not None: history.gate._final_current(candidate)
                self._terminal_current(sealed, candidate)
                owner.retired.set()  # Irreversible after this original guard unlocks.
                return sealed
            except BaseException:
                # No second admission can race rollback while this guard is held.
                owner.slot._value = 0
                owner.retired.clear()  # Rollback only while no later owner can enter.
                self._poison()
                raise SourceAdmissionError('admission_cleanup_uncertain') from None
            finally: owner.slot_lock.release()

    def _poison(self):
        owner = self._original()
        owner.cancel.set()
        source = self._recover(tuple(getattr(self, prefix+'source', None) for prefix in
            ('_', '_issued_', '_recovery_')), _Source, optional=True)
        wire = self._recover(tuple(getattr(self, prefix+'wire', None) for prefix in
            ('_', '_issued_', '_recovery_')), _Wire, optional=True)
        if source is not None: source.source._publication_attempted = True
        if wire is not None:
            try: wire.buffer[:] = b'\0'*len(wire.buffer); wire.buffer.clear()
            except BaseException: pass
        self._save('poisoned', poisoned=True, cleanup=False, released=False, result=None, snapshot=None)

    def _wipe_original(self):
        # Late rejection after genuine release never changes shared admission.
        wire = self._recover(tuple(getattr(self, prefix+'wire', None) for prefix in
            ('_', '_issued_', '_recovery_')), _Wire, optional=True)
        if wire is not None:
            try: wire.buffer[:] = b'\0'*len(wire.buffer); wire.buffer.clear()
            except BaseException: pass

    def close(self):
        # Cancellation never disposes a foreign object or releases shared admission.
        owner = self._original()
        if owner.custody is not self:
            raise SourceAdmissionError('foreign_admission_custody')
        owner.cancel.set()
        history = self._status()
        if type(history.gate) is _CustodiedRendezvous:
            gate = history.gate
            try:
                link = gate._recover(tuple(getattr(gate, name, None) for name in
                    ('_link', '_issued_link', '_recovery_link')), _Link)
                if (link.gate is not gate or link.custody is not self or link.owner is not owner
                        or link.source is not self._recover(tuple(getattr(self, prefix+'source', None) for prefix in
                            ('_', '_issued_', '_recovery_')), _Source)
                        or any(getattr(gate, name, None) is not link for name in ('_link', '_issued_link', '_recovery_link'))):
                    return  # Own cancellation is set; foreign objects are never signalled.
                original = history.gate_owner
                if original is not None and link.gate_owner is original:
                    original.cancel.set()  # Captured at creation, never selected from mutable gate fields.
            except (SourceAdmissionError, SourceRendezvousError):
                return  # Missing archives cannot certify cleanup or release anything.

    cancel = close

    def abort(self):
        with self._control(), self._guards():
            history = self._identity(active=False, thread=True)
            if history.stage != 'fixture' or history.attempted:
                raise SourceAdmissionError('admission_abort_spent')
            self.close()
            try:
                if self._source is not None: self._source.source._shutdown()
                return self._retire(None)
            except BaseException:
                self._poison()
                raise SourceAdmissionError('admission_cleanup_uncertain') from None

    def finish(self, app, credential, proposal, descriptor):
        with self._control() as owner:
            history = self._identity(thread=True)
            if history.stage != 'fixture' or not history.begun or self._wire is None or history.attempted:
                raise SourceAdmissionError('invalid_admission_finish')
            if any(lock._is_owned() for lock in self._source.locks+(self._wire.lock,)):
                raise SourceAdmissionError('authority_held_across_admission_wait')
            gate = object.__new__(_CustodiedRendezvous)
            owner.handoff_seen.set()
            self._save('constructing', attempted=True, gate=gate)
            try:
                _CustodiedRendezvous.__init__(gate, self)
                self._save('rendezvous', gate_owner=gate._original())
                self._identity(thread=True)
            except BaseException:
                self._poison()
                raise SourceAdmissionError('admission_handoff_rejected') from None
        candidate = None
        try: candidate = gate.run(app, credential, proposal, descriptor)
        except BaseException: self.close()
        try: sealed = self._retire(candidate)
        except BaseException:
            self._poison()
            raise SourceAdmissionError('admission_rejected') from None
        candidate = sealed.result
        if candidate is None:
            self._wipe_original()
            raise SourceAdmissionError('admission_rejected') from None
        # After genuine release never reclaim a slot that may now belong to a
        # later owner. Late corruption withholds this historical metadata only.
        try:
            with self._control(), self._guards():
                self._cleanup_current()
                gate._final_current(candidate)
                self._terminal_current(sealed, candidate)
        except BaseException:
            self._wipe_original()
            raise SourceAdmissionError('late_admission_rejection') from None
        return candidate


class _CustodiedRendezvous(SourceAssociationRendezvousDryRun):
    """Exact private retained-admission profile; public standalone is unchanged."""
    def _admission_deadline_cap(self):
        return self._issued_link.owner.deadline

    def __init__(self, custody):
        if type(self) is not _CustodiedRendezvous or type(custody) is not _SourceAdmissionCustody:
            raise SourceAdmissionError('invalid_private_handoff')
        custody._gate_current(self)
        link = _Link(self, custody, custody._original(), custody._source, None)
        self._link = self._issued_link = self._recovery_link = link
        super().__init__(link.source.source, timeout=min(5, link.owner.deadline-monotonic()))
        link = link._replace(gate_owner=self._original())
        self._link = self._issued_link = self._recovery_link = link

    def _identity(self, owner, *, active=True):
        history = super()._identity(owner, active=active)
        link = self._recover(tuple(getattr(self, name, None) for name in
            ('_link', '_issued_link', '_recovery_link')), _Link)
        if (link.gate is not self
                or any(getattr(self, name, None) is not link for name in ('_link', '_issued_link', '_recovery_link'))
                or link.custody._original() is not link.owner or link.custody._source is not link.source
                or owner.source is not link.source.source or owner.slot is not link.owner.slot
                or owner.slot_lock is not link.owner.slot_lock or owner.deadline > link.owner.deadline):
            raise SourceRendezvousError('changed_private_handoff')
        custody_status = link.custody._gate_current(self, active=active)
        if custody_status.stage != 'constructing' and (owner is not link.gate_owner or owner is not custody_status.gate_owner):
            raise SourceRendezvousError('changed_private_gate_owner')
        return history

    def _acquire_admission(self):
        owner = self._original()
        if not owner.slot_lock.acquire(blocking=False): raise SourceRendezvousError('busy_private_handoff')
        try:
            self._identity(owner)
            if type(owner.slot._value) is not int or owner.slot._value != 0:
                raise SourceRendezvousError('unheld_private_handoff')
            self._issued_link.custody._claim(self)
            self._save('running', True, False, True, False, False, False, False)
        finally: owner.slot_lock.release()

    def _terminal_current(self, sealed, candidate):
        history = self._identity(self._original(), active=False)
        if (type(sealed) is not _History or history is not sealed
                or history.state != ('joined_retained' if candidate is not None else 'failed_retained')
                or any(flag is not True for flag in (history.started, history.finished,
                    history.acquired, history.cleanup, history.source_joined))
                or history.released is not False
                or history.association_joined is not (self._worker_original().association_thread is not None)
                or history.result is not candidate
                or history.snapshot != (self._pending_snapshot if candidate is not None else None)):
            raise SourceRendezvousError('changed_private_terminal_history')

    def _release_admission(self):
        owner = self._original()
        with self._guards(owner):
            if not owner.slot_lock.acquire(blocking=False): raise SourceRendezvousError('busy_private_handoff')
            try:
                self._identity(owner, active=False)
                history = self._status()
                if history.acquired is not True or history.released is not False or type(owner.slot._value) is not int or owner.slot._value != 0:
                    raise SourceRendezvousError('spent_private_handoff')
                self._cleanup_current()
                candidate = self._pending
                if candidate is not None:
                    try: self._final_current(candidate)
                    except BaseException: candidate = self._pending = None
                sealed = self._save('joined_retained' if candidate is not None else 'failed_retained', True, True, True, False,
                    True, True, self._worker_original().association_thread is not None,
                    result=candidate, snapshot=self._pending_snapshot if candidate is not None else None)
                self._terminal_current(sealed, candidate)
                self._issued_link.custody._returned(self, sealed)
                self._cleanup_current()
                self._terminal_current(sealed, candidate)
                return sealed
            except BaseException:
                owner.cancel.set()
                self._wipe_failure(owner)
                raise SourceRendezvousError('private_handoff_cleanup_uncertain') from None
            finally: owner.slot_lock.release()
