"""Inactive two-worker rendezvous over an already cleaned trusted lifecycle.

No source acquisition, payload transport or active route. The original source
worker pauses outside authority, the association worker consumes/discards, and
the coordinator retains shared admission until both original workers retire.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
import math
from threading import BoundedSemaphore, Condition, Event, Lock, RLock, Thread, Timer, current_thread
from collections import deque
from time import monotonic, sleep

from . import broker_transport as transport
from .broker_acquisition_draft import AcquisitionDraft
from .broker_live_channel_check import LiveChannelPublicationCheck
from .broker_live_review import LiveBrokerReview
from .broker_publication_commit_draft import PublicationCommitDraft
from .broker_publication_commit_protocol import PublicationCommitExchange
from .broker_publication_lifecycle import LivePublicationDraft
from .broker_publication_protocol import PublicationCheckExchange
from .broker_publication_recipient import LogicalPublicationRecipient
from .broker_recipient_process import _OwnershipApi
from .broker_resumable_witness import _ResumableWitnessWorker
from .broker_source_association_peer import _SourceAssociationPeer
from .broker_source_native_association import SourceNativeAssociationDryRun, SourceNativeAssociationEvidence, _facts
from .file_read_review import FileReadReviewLedger
from .registry import ApplicationRegistry
from .registry_bound_review import RegistryBoundFileReadReviews
import secrets

_RLOCK = type(RLock())
_SLOT = type(BoundedSemaphore(1))
_Owner = namedtuple('_Owner', 'source recipient acquisition review buffer descriptor locks fields lease deadline '
    'lock cancel slot slot_condition slot_lock notify')
_Workers = namedtuple('_Workers', 'witness helper association_thread done association commit peer native commit_lock commit_wire_lock peer_lock commit_wire commit_timer commit_cancel commit_finished')
_Native = namedtuple('_Native', 'child lock api owned anchors seals observation values')
_History = namedtuple('_History', 'state started finished acquired released cleanup source_joined association_joined result snapshot')


class SourceRendezvousError(RuntimeError):
    pass


class SourceAssociationRendezvousDryRun:
    """Fixed, one-attempt, two-worker metadata experiment; never permission.

    Trusted bootstrap supplies an exact already-cleaned lifecycle. Admission
    bounds only these two new native workers, not earlier fixture acquisition.
    Neither a worker result nor a cleanup boolean releases admission. Unknown
    thread/native/local cleanup leaves the captured shared slot poisoned.
    """
    def _admission_deadline_cap(self):
        return None

    def __init__(self, lifecycle, *, timeout=5):
        if type(lifecycle) is not LivePublicationDraft:
            raise TypeError('expected exact cleaned publication lifecycle')
        if type(timeout) not in (int, float) or not 0 < timeout <= 5 or not math.isfinite(timeout):
            raise SourceRendezvousError('invalid_rendezvous_lifetime')
        source = lifecycle
        recipient, acquisition, review = source._recipient, source._acquisition, source._review
        if (type(recipient) is not LogicalPublicationRecipient or type(acquisition) is not AcquisitionDraft
                or type(review) is not LiveBrokerReview or acquisition._review is not review
                or type(review._registry) is not ApplicationRegistry or type(review._ledger) is not FileReadReviewLedger
                or type(review._reviews) is not RegistryBoundFileReadReviews
                or review._reviews._registry is not review._registry or review._reviews._ledger is not review._ledger):
            raise SourceRendezvousError('invalid_rendezvous_bootstrap')
        if type(source._wire) is not PublicationCheckExchange:
            raise SourceRendezvousError('invalid_rendezvous_bootstrap')
        locks = (source._lock, recipient._lock, acquisition._lock, review._lock,
            review._reviews._lock, review._registry._lock, review._ledger._lock,
            source._wire._lock, review._exchange._lock)
        if any(type(lock) is not _RLOCK for lock in locks):
            raise SourceRendezvousError('invalid_rendezvous_bootstrap')
        fields = tuple((owner, name, getattr(owner, name)) for owner, names in (
            (source, ('_lock', '_recipient', '_acquisition', '_review', '_wire', '_owned_buffer', '_token', '_issued_token')),
            (recipient, ('_lock',)), (acquisition, ('_lock', '_review')),
            (review, ('_lock', '_registry', '_ledger', '_reviews', '_exchange', '_lease')),
            (review._registry, ('_lock',)), (review._ledger, ('_lock',)),
            (review._reviews, ('_lock', '_registry', '_ledger')), (source._wire, ('_lock',)),
            (review._exchange, ('_lock',))) for name in names)
        slot = transport._slot
        if (type(slot) is not _SLOT or type(slot._initial_value) is not int or slot._initial_value != 1
                or type(slot._cond) is not Condition or type(slot._cond._lock) is not type(Lock())
                or type(slot._cond._waiters) is not deque):
            raise SourceRendezvousError('invalid_rendezvous_admission')
        fields += ((slot._cond, '_lock', slot._cond._lock), (slot._cond, '_waiters', slot._cond._waiters))
        self._slot_is_owned = slot._cond.__dict__.get('_is_owned')
        self._slot_owned_function = Condition._is_owned
        deadline = min(monotonic()+timeout, source._source_deadline_snapshot,
            recipient._deadline_snapshot, source._wire._deadline_snapshot)
        cap = self._admission_deadline_cap()
        if cap is not None:
            if type(cap) is not float or not math.isfinite(cap):
                raise SourceRendezvousError('invalid_admission_deadline_cap')
            deadline = min(deadline, cap)  # A private outer owner may only shorten.
        owner = _Owner(source, recipient, acquisition, review, source._owned_buffer, source._recipient_descriptor,
            locks, fields, review._lease, deadline, RLock(), Event(), slot, slot._cond, slot._cond._lock, slot._cond.notify)
        self._origin = self._issued_origin = self._recovery_origin = owner
        self._lock, self._cancel, self._deadline = owner.lock, owner.cancel, deadline
        self._workers = self._issued_workers = self._recovery_workers = _Workers(*(None for _ in _Workers._fields))
        self._witness = self._issued_witness = self._association = self._issued_association = None
        self._association_thread = self._issued_association_thread = None
        self._result = self._issued_result = self._pending = self._pending_snapshot = None
        self._association_error = False
        self._save('new', False, False, False, False, False, False, False)
        with self._guards(owner):
            self._identity(owner)
            source._current('cleaned'); source._wire_current(4)
            self._identity(owner)

    @staticmethod
    def _recover(values, kind):
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise SourceRendezvousError('uncertain_rendezvous_owner')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Owner)

    def _worker_original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_workers', '_issued_workers', '_recovery_workers')), _Workers)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _History)

    def _save(self, state, started, finished, acquired, released, cleanup, source_joined, association_joined,
              *, result=None, snapshot=None):
        history = _History(state, started, finished, acquired, released, cleanup,
            source_joined, association_joined, result, snapshot)
        self._history = self._issued_history = self._recovery_history = history
        self._state = state
        self._result = self._issued_result = result
        return history

    def _set_workers(self, **values):
        workers = self._worker_original()._replace(**values)
        self._workers = self._issued_workers = self._recovery_workers = workers
        self._witness = self._issued_witness = workers.witness
        self._association = self._issued_association = workers.association
        self._association_thread = self._issued_association_thread = workers.association_thread
        return workers

    def _identity(self, owner, *, active=True):
        history, workers = self._status(), self._worker_original()
        if (any(getattr(self, name, None) is not owner for name in ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in ('_history', '_issued_history', '_recovery_history'))
                or any(getattr(self, name, None) is not workers for name in ('_workers', '_issued_workers', '_recovery_workers'))
                or self._lock is not owner.lock or self._cancel is not owner.cancel
                or type(self._deadline) is not float or self._deadline != owner.deadline
                or type(self._state) is not str or self._state != history.state
                or type(history.state) is not str
                or any(type(flag) is not bool for flag in history[1:8])
                or self._witness is not workers.witness or self._issued_witness is not workers.witness
                or self._association is not workers.association or self._issued_association is not workers.association
                or self._association_thread is not workers.association_thread
                or self._issued_association_thread is not workers.association_thread
                or self._result is not history.result or self._issued_result is not history.result
                or (history.result is not None and (type(history.result) is not SourceNativeAssociationEvidence
                    or _facts(history.result) != history.snapshot))
                or any(getattr(obj, name, None) is not value for obj, name, value in owner.fields)
                or owner.source._owned_buffer is not owner.buffer or type(owner.buffer) is not bytearray
                or transport._slot is not owner.slot or owner.slot._cond is not owner.slot_condition
                or owner.slot_condition._lock is not owner.slot_lock or type(owner.slot) is not _SLOT
                or type(owner.slot._initial_value) is not int or owner.slot._initial_value != 1
                or owner.slot_condition.__dict__.get('_is_owned') is not self._slot_is_owned
                or Condition._is_owned is not self._slot_owned_function
                or any(type(waiter) is not type(Lock()) for waiter in owner.slot_condition._waiters)):
            raise SourceRendezvousError('changed_rendezvous_owner')
        if active and (owner.cancel.is_set() or monotonic() >= owner.deadline):
            raise SourceRendezvousError('expired_or_cancelled_rendezvous')
        return history

    def _terminal_current(self, sealed, candidate):
        history = self._identity(self._original(), active=False)
        if (type(sealed) is not _History or history is not sealed
                or history.state != ('joined_discarded' if candidate is not None else 'failed')
                or any(flag is not True for flag in (history.started, history.finished,
                    history.acquired, history.released, history.cleanup, history.source_joined))
                or history.association_joined is not (self._worker_original().association_thread is not None)
                or history.result is not candidate
                or history.snapshot != (self._pending_snapshot if candidate is not None else None)):
            raise SourceRendezvousError('changed_rendezvous_terminal_history')

    @contextmanager
    def _guards(self, owner, *, extra=()):
        with ExitStack() as stack:
            for lock in owner.locks+tuple(extra)+(owner.lock,):
                if type(lock) is not _RLOCK or not lock.acquire(blocking=False):
                    raise SourceRendezvousError('busy_rendezvous_owner')
                stack.callback(lock.release)
            yield

    def _io_unlocked(self, owner):
        workers = self._worker_original()
        locks = owner.locks+(owner.lock,)
        if workers.witness is not None:
            locks += workers.witness._original().locks
            native, wire = workers.witness._native_original(), workers.witness._wire_original()
            if native is not None: locks += (native.lock,)
            if wire is not None: locks += (wire.lock,)
        if workers.association is not None:
            channel = workers.association._channel_original()
            if channel is not None: locks += (channel.lock, channel.wire_lock)
        if workers.commit is not None: locks += (workers.commit_lock, workers.commit_wire_lock)
        if workers.peer is not None: locks += (workers.peer_lock,)
        if any(type(lock) is not _RLOCK for lock in locks):
            raise SourceRendezvousError('changed_rendezvous_wait_owner')
        if any(lock._is_owned() for lock in locks):
            raise SourceRendezvousError('authority_held_across_rendezvous_wait')

    def _acquire_admission(self):
        owner = self._original()
        if not owner.slot_lock.acquire(blocking=False): raise SourceRendezvousError('busy_rendezvous_admission')
        try:
            self._identity(owner)
            if type(owner.slot._value) is not int or owner.slot._value != 1:
                raise SourceRendezvousError('busy_rendezvous_admission')
            owner.slot._value = 0
            self._save('running', True, False, True, False, False, False, False)
        finally: owner.slot_lock.release()

    def _ready_helper(self):
        owner, workers = self._original(), self._worker_original()
        self._identity(owner)
        if type(workers.witness) is not _ResumableWitnessWorker:
            raise SourceRendezvousError('invalid_rendezvous_worker')
        helper = workers.witness.ready_helper()
        if helper is not None and (type(helper) is not LiveChannelPublicationCheck or helper is not workers.helper):
            raise SourceRendezvousError('wrong_rendezvous_ready_owner')
        return helper

    def _poll_current(self, owner):
        # The second worker holds control while constructing its guarded exact
        # source graph. Wait only outside every authority guard and only until
        # the original deadline; this grants nothing and renews no lifetime.
        until = owner.deadline
        self._io_unlocked(owner)
        while not owner.lock.acquire(blocking=False):
            if owner.cancel.is_set() or monotonic() >= until:
                raise SourceRendezvousError('busy_rendezvous_control')
            sleep(.001)
        try: self._identity(owner)
        finally: owner.lock.release()

    def _association_worker(self, app, credential, proposal, descriptor):
        owner, workers = self._original(), self._worker_original()
        association = None
        try:
            if current_thread() is not workers.association_thread:
                raise SourceRendezvousError('wrong_association_worker')
            helper = workers.helper
            witness_owner = workers.witness._original()
            witness_native = workers.witness._native_original()
            if witness_native is None: raise SourceRendezvousError('missing_rendezvous_witness')
            extra = (helper._lock, witness_native.lock, witness_native.wire_lock)
            with self._guards(owner, extra=extra):
                self._identity(owner)
                key, session = secrets.token_bytes(32), secrets.token_bytes(32)
                commit = PublicationCommitDraft(helper, key=key, session=session,
                    timeout=min(5, owner.deadline-monotonic()))
                with owner.lock:
                    self._identity(owner, active=False)
                    self._set_workers(commit=commit, commit_lock=commit._lock,
                        commit_wire_lock=commit._issued_wire._lock,
                        commit_wire=commit._issued_wire, commit_timer=commit._issued_timer, commit_cancel=commit._issued_cancel,
                        commit_finished=commit._issued_timer.finished)
                    self._identity(owner)
                peer = PublicationCommitExchange(role='broker', key=key, session=session)
                with owner.lock:
                    self._identity(owner, active=False)
                    self._set_workers(peer=peer, peer_lock=peer._lock)
                    self._identity(owner)
                peer.accept_prepare(commit.prepare()); commit.accept_ready(peer.ready())
                with self._guards(owner, extra=extra+(commit._lock, commit._issued_wire._lock)):
                    association = SourceNativeAssociationDryRun(commit, timeout=min(5, owner.deadline-monotonic()))
                    with owner.lock:
                        # Retain a structurally intact disposal owner before a
                        # concurrent cancellation can reject active publication.
                        self._identity(owner, active=False)
                        self._set_workers(association=association)
                        self._identity(owner)
            self._io_unlocked(owner)
            candidate = association.run(app, credential, proposal, descriptor)
            archived_channel = association._channel_original()
            if archived_channel is None: raise SourceRendezvousError('missing_association_native_owner')
            child = archived_channel.child
            if type(child) is not _SourceAssociationPeer or association._child is not child:
                raise SourceRendezvousError('wrong_association_native_owner')
            native = _Native(child, archived_channel.lock, archived_channel.api, archived_channel.owned,
                archived_channel.anchors, archived_channel.seals, archived_channel.observation, archived_channel.values)
            with owner.lock:
                self._identity(owner)
                association.inspect()
                if candidate is not association._issued_result or type(candidate) is not SourceNativeAssociationEvidence:
                    raise SourceRendezvousError('wrong_association_result')
                self._set_workers(native=native)
                self._pending, self._pending_snapshot = candidate, association._status().snapshot
        except BaseException:
            self._association_error = True
            owner.cancel.set()
            if association is not None:
                try:
                    original = association._original()
                    if not original.lock.acquire(blocking=False): raise SourceRendezvousError('busy_association_disposal')
                    try: SourceNativeAssociationDryRun.close(association)
                    finally: original.lock.release()
                except BaseException: self._association_error = True
        finally:
            try:
                originals = self._worker_original()
                if originals.peer is not None:
                    lock = originals.peer_lock
                    if originals.peer._lock is not lock: raise SourceRendezvousError('changed_rendezvous_codec')
                    if not lock.acquire(blocking=False): raise SourceRendezvousError('busy_rendezvous_codec')
                    try: originals.peer.close()
                    finally: lock.release()
                if originals.commit is not None:
                    with self._guards(owner, extra=(originals.commit_lock, originals.commit_wire_lock)):
                        if (type(originals.commit_timer) is not Timer or type(originals.commit_finished) is not Event
                                or originals.commit_timer.finished is not originals.commit_finished):
                            self._association_error = True; owner.cancel.set()
                            # Restore only the original disposal signal. The
                            # changed owner can never produce a successful fact.
                            originals.commit_timer.finished = originals.commit_finished
                        originals.commit_cancel.set()
                        originals.commit_timer.cancel()
                        originals.commit_wire.close()
                        originals.commit._terminal = originals.commit._cancelled = True
                        originals.commit._state = 'closed'
            except BaseException: self._association_error = True; owner.cancel.set()
            workers.done.set()

    def _association_native_current(self):
        workers = self._worker_original()
        a, native = workers.association, workers.native
        # Failure may never have constructed a child. The original association
        # itself tracks startup uncertainty; it is not a caller cleanup claim.
        if a is None: return
        if type(a) is not SourceNativeAssociationDryRun: raise SourceRendezvousError('foreign_association_owner')
        status = a.inspect()
        if status['cleanup_confirmed'] is not True: raise SourceRendezvousError('uncertain_association_cleanup')
        archived_channel = a._channel_original()
        if archived_channel is not None:
            a._channel_codec_current(archived_channel, retired=True)
            if status['state'] == 'associated_discarded' and archived_channel.retirement is None:
                raise SourceRendezvousError('missing_association_retirement')
        if a._issued_child is None:
            if native is not None: raise SourceRendezvousError('changed_association_native_owner')
            return
        if native is None:
            # Capture known original native ownership even after a rejected
            # association, so later disposal checks cannot follow substitutes.
            archived_channel = a._channel_original()
            if archived_channel is None: raise SourceRendezvousError('missing_association_native_owner')
            child = archived_channel.child
            if type(child) is not _SourceAssociationPeer or a._child is not child:
                raise SourceRendezvousError('changed_association_native_owner')
            native = _Native(child, archived_channel.lock, archived_channel.api, archived_channel.owned,
                archived_channel.anchors, archived_channel.seals, archived_channel.observation, archived_channel.values)
            self._set_workers(native=native)
        child = native.child
        def identity():
            if (a._child is not child or a._issued_child is not child or child._ownership_lock is not native.lock
                    or child._ownership is not native.api or type(native.api) is not _OwnershipApi
                    or child._owned is not native.owned or child._issued_owned is not native.owned
                    or child._anchor_snapshot is not native.anchors or child._issued_anchors is not native.anchors
                    or child._seal_snapshot is not native.seals or child._issued_seals is not native.seals
                    or child._issued_observation is not native.observation
                    or (type(native.observation.pid), native.observation.pid,
                        type(native.observation.creation_time), native.observation.creation_time) != native.values):
                raise SourceRendezvousError('changed_association_native_owner')
            if (child._closed is not True or child._cleanup_failed is not False
                    or child._process is not None or child._job is not None
                    or type(child._fds) is not set or child._fds
                    or type(child._anchors) is not dict or child._anchors
                    or type(child._seals) is not dict or child._seals
                    or type(child._exit) is not int
                    or type(child._input_closed) is not bool
                    or type(child._retired_snapshot) is not tuple or len(child._retired_snapshot) != 2
                    or type(child._retired_snapshot[0]) is not int or type(child._retired_snapshot[1]) is not bool
                    # Forced cancellation may close the original handles before
                    # protocol input retirement. This is cleanup, not a success
                    # receipt; _final_current separately requires input EOF/0.
                    or child._retired_snapshot != (child._exit, child._input_closed)
                    or type(child.stdin_fd) is not int or child.stdin_fd != native.owned[0]
                    or type(child.stdout_fd) is not int or child.stdout_fd != native.owned[1]
                    or type(child.pid) is not int or child.pid != native.values[1]):
                raise SourceRendezvousError('changed_association_native_retirement')
        identity()
        if type(native.lock) is not _RLOCK or not native.lock.acquire(blocking=False):
            raise SourceRendezvousError('busy_rendezvous_native_owner')
        try: identity(); child._retired(); identity()
        finally: native.lock.release()

    def _cleanup_current(self):
        owner, workers = self._original(), self._worker_original()
        self._identity(owner, active=False)
        if workers.witness is not None:
            workers.witness.verify_retired()
        if workers.association_thread is not None:
            if type(workers.association_thread) is not Thread or Thread.is_alive(workers.association_thread):
                raise SourceRendezvousError('unjoined_association_worker')
            if type(workers.done) is not Event or not workers.done.is_set():
                raise SourceRendezvousError('unfinished_association_worker')
        self._association_native_current()
        if workers.peer is not None and (workers.peer._lock is not workers.peer_lock
                or type(workers.peer._key) is not bytes or workers.peer._key != b''
                or type(workers.peer._state) is not str or workers.peer._state != 'closed'):
            raise SourceRendezvousError('unretired_rendezvous_codec')
        if workers.commit is not None and (workers.commit._issued_wire is not workers.commit_wire
                or workers.commit._wire is not workers.commit_wire or workers.commit_wire._lock is not workers.commit_wire_lock
                or type(workers.commit_wire._key) is not bytes or workers.commit_wire._key != b''
                or type(workers.commit_wire._state) is not str or workers.commit_wire._state != 'closed'
                or workers.commit._issued_timer is not workers.commit_timer or workers.commit._timer is not workers.commit_timer
                or type(workers.commit_timer) is not Timer or type(workers.commit_finished) is not Event
                or workers.commit_timer.finished is not workers.commit_finished or not workers.commit_finished.is_set()
                or workers.commit._issued_cancel is not workers.commit_cancel or not workers.commit_cancel.is_set()):
            raise SourceRendezvousError('unretired_rendezvous_commit')
        if type(owner.buffer) is not bytearray or owner.buffer:
            raise SourceRendezvousError('unretired_source_buffer')
        self._identity(owner, active=False)

    def _final_current(self, candidate):
        owner, workers = self._original(), self._worker_original()
        with self._guards(owner):
            self._identity(owner)
            self._cleanup_current()
            if (type(candidate) is not SourceNativeAssociationEvidence or candidate is not self._pending
                    or _facts(candidate) != self._pending_snapshot or workers.association is None
                    or candidate is not workers.association._issued_result
                    or workers.witness._error is not None or workers.witness._issued_error is not None
                    or workers.native.child._exit != 0 or workers.native.child._input_closed is not True):
                raise SourceRendezvousError('changed_rendezvous_result')
            # Cleanup and freshness are independent. The old live-native gate
            # cannot be reused after disposal, and no closed state is reopened.
            with owner.lease(), owner.review._ledger._lock:
                workers.helper._checked_source()
                self._identity(owner)
                if _facts(candidate) != self._pending_snapshot:
                    raise SourceRendezvousError('changed_rendezvous_result')

    def _release_admission(self):
        owner = self._original()
        with self._guards(owner):
            if not owner.slot_lock.acquire(blocking=False): raise SourceRendezvousError('busy_rendezvous_admission')
            try:
                self._identity(owner, active=False)
                history = self._status()
                if history.acquired is not True or history.released is not False or type(owner.slot._value) is not int or owner.slot._value != 0:
                    raise SourceRendezvousError('spent_rendezvous_admission')
                self._cleanup_current()
                candidate = self._pending
                if candidate is not None:
                    try: self._final_current(candidate)
                    except BaseException: candidate = self._pending = None
                sealed = self._save('joined_discarded' if candidate is not None else 'failed', True, True, True, True,
                    True, True, self._worker_original().association_thread is not None,
                    result=candidate, snapshot=self._pending_snapshot if candidate is not None else None)
                self._terminal_current(sealed, candidate)
                # Keep the semaphore's own guard held through notification and
                # the post-hook fence. No second admission can race a rollback.
                owner.slot._value = 1
                owner.notify()
                self._cleanup_current()
                if candidate is not None: self._final_current(candidate)
                self._terminal_current(sealed, candidate)
                return sealed
            except BaseException:
                owner.slot._value = 0
                owner.cancel.set()
                self._wipe_failure(owner)
                self._save('failed', True, True, True, False, False,
                    False, False)
                raise SourceRendezvousError('rendezvous_cleanup_uncertain') from None
            finally: owner.slot_lock.release()

    def _dispose_unstarted(self, owner):
        cleaned = True
        try:
            with self._guards(owner):
                for obj, name, value in owner.fields:
                    if getattr(obj, name, None) is not value:
                        cleaned = False
                        # This owner may never have acquired shared admission.
                        # Dispose source-local originals, never repair shared
                        # synchronization that may belong to another owner.
                        if obj is not owner.slot_condition: setattr(obj, name, value)
                owner.source._shutdown()
        except BaseException: cleaned = False
        try: owner.buffer[:] = b'\0'*len(owner.buffer); owner.buffer.clear()
        except BaseException: cleaned = False
        return cleaned

    @staticmethod
    def _wipe_failure(owner):
        # Removing source usability never grants authority. Do this even when
        # a contended owner prevents complete disposal; admission stays held.
        owner.source._publication_attempted = True
        try: owner.buffer[:] = b'\0'*len(owner.buffer); owner.buffer.clear()
        except BaseException: pass

    def close(self):
        owner = self._original()
        owner.cancel.set()  # Signal originals before any potentially busy guard.
        workers = self._worker_original()
        if workers.witness is not None and workers.association_thread is None:
            workers.witness._original().cancel.set()
        if workers.association is not None:
            workers.association._original().cancel.set()
        if not owner.lock.acquire(blocking=False): return
        try:
            history = self._status()
            if history.finished: return
            if not history.started:
                cleaned = self._dispose_unstarted(owner)
                self._save('failed', True, True, False, False, cleaned, False, False)
        finally: owner.lock.release()

    cancel = close

    def inspect(self):
        owner = self._original()
        if not owner.lock.acquire(blocking=False): raise SourceRendezvousError('busy_rendezvous_owner')
        try:
            history = self._identity(owner, active=False)
            return dict(state=history.state, cleanup_confirmed=history.cleanup,
                admission_held=history.acquired and not history.released,
                source_joined=history.source_joined, association_joined=history.association_joined)
        finally: owner.lock.release()

    def run(self, app, credential, proposal, descriptor):
        owner = self._original()
        caller_held = any(lock._is_owned() for lock in owner.locks+(owner.lock,))
        if not owner.lock.acquire(blocking=False): raise SourceRendezvousError('busy_rendezvous_owner')
        try:
            if self._status().started:
                if not self._status().finished: owner.cancel.set()
                raise SourceRendezvousError('rendezvous_attempt_spent')
            self._identity(owner)
            if caller_held: raise SourceRendezvousError('authority_held_across_rendezvous_wait')
            self._acquire_admission()
        except BaseException:
            if not self._status().started:
                owner.cancel.set()
                cleaned = self._dispose_unstarted(owner)
                self._save('failed', True, True, False, False, cleaned, False, False)
            raise SourceRendezvousError('rendezvous_rejected') from None
        finally: owner.lock.release()
        failed = False
        try:
            with self._guards(owner):
                self._identity(owner)
                helper = LiveChannelPublicationCheck(owner.source, timeout=min(5, owner.deadline-monotonic()))
                self._set_workers(helper=helper)
                witness = _ResumableWitnessWorker(helper)
                self._set_workers(witness=witness, helper=helper)
            self._io_unlocked(owner)
            self._identity(owner)
            witness.start(app, credential, proposal, descriptor)
            while True:
                ready = self._ready_helper()
                if ready is not None:
                    if type(ready) is not LiveChannelPublicationCheck or ready is not self._worker_original().helper:
                        raise SourceRendezvousError('wrong_rendezvous_ready_owner')
                    break
                if not Thread.is_alive(witness._original().thread):
                    raise SourceRendezvousError('witness_worker_failed')
                self._poll_current(owner); sleep(.002)
            done = Event()
            thread = Thread(target=self._association_worker, args=(app, credential, proposal, descriptor), daemon=True)
            with owner.lock: self._identity(owner); self._set_workers(association_thread=thread, done=done)
            self._io_unlocked(owner); self._identity(owner); thread.start()
            while not done.is_set():
                self._poll_current(owner); sleep(.002)
            if self._association_error is not False or self._pending is None:
                raise SourceRendezvousError('association_worker_failed')
        except BaseException:
            failed = True; self.close()
        finally:
            workers = self._worker_original()
            if workers.witness is None:
                self._dispose_unstarted(owner)
                if workers.helper is not None:
                    try:
                        with self._guards(owner, extra=(workers.helper._lock,)): workers.helper._dispose()
                    except BaseException: failed = True
            limit = monotonic()+5
            try:
                self._io_unlocked(owner)
                if workers.association_thread is not None:
                    Thread.join(workers.association_thread, max(0, limit-monotonic()))
                    if Thread.is_alive(workers.association_thread):
                        raise SourceRendezvousError('unjoined_association_worker')
                # Association must stop using the original live source/native
                # guards before its witness enters disposal. Cancellation is
                # already signalled to the coordinator and association.
                if workers.witness is not None:
                    try:
                        if failed: workers.witness.cancel()
                        else: workers.witness.resume()
                    except BaseException: failed = True; workers.witness._original().cancel.set()
                if workers.witness is not None: workers.witness.join(max(0, limit-monotonic()))
                with self._guards(owner): self._cleanup_current()
            except BaseException:
                owner.cancel.set()
                if workers.witness is not None: workers.witness._original().cancel.set()
                self._wipe_failure(owner)
                self._save('failed', True, True, True, False, False, False, False)
                raise SourceRendezvousError('rendezvous_cleanup_uncertain') from None
        if failed: self._pending = None
        try: sealed = self._release_admission()
        except BaseException:
            self._wipe_failure(owner)
            raise SourceRendezvousError('rendezvous_rejected') from None
        candidate = self._issued_result
        if candidate is None: raise SourceRendezvousError('rendezvous_rejected') from None
        try: self._terminal_current(sealed, candidate)
        except BaseException:
            self._wipe_failure(owner)
            raise SourceRendezvousError('rendezvous_rejected') from None
        return candidate
