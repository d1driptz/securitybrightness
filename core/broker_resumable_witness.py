"""Inactive fixed witness worker with a bounded, outside-authority rendezvous.

Trusted enclosing bootstrap supplies an exact cleaned synthetic lifecycle through
its exact helper. This worker establishes only the original metadata witness and
pauses; resume performs disposal, never authorization, file access or delivery.
The enclosing host alone owns shared admission and must poison it on uncertainty.
No existing helper, host, owner walkthrough or product route selects this worker.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import math
import os
import secrets
from threading import Condition, Event, RLock, Thread, current_thread
from time import monotonic, sleep

from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_live_channel_check import LiveChannelPublicationCheck
from .broker_protocol import MAX_BODY_BYTES
from .broker_recipient_channel import _values
from .broker_recipient_process import _RecipientWitnessChild, _OwnershipApi, ProcessChannelObservation
from .broker_recipient_protocol import RecipientWitnessExchange, RecipientWitnessEvidence
from .json_input import loads

_LOCK_TYPE = type(RLock())
_Origin = namedtuple('_Origin', 'helper source recipient acquisition review descriptor buffer deadline '
    'helper_cancel locks fields thread lock condition cancel resume')
_Wire = namedtuple('_Wire', 'codec lock identity')
_Proof = namedtuple('_Proof', 'evidence values previous phase')
_Native = namedtuple('_Native', 'child lock api owned anchors seals observation observation_values wire wire_lock')
_History = namedtuple('_History', 'state started finished cleanup joined ident native_ident wire_seen native_seen proof_seen')


class ResumableWitnessError(RuntimeError):
    pass


class _ResumableWitnessWorker:
    """One original Thread owns one original child until guarded retirement.

    A ready helper is a private original graph reference, not authority. Waiting
    does not renew any original deadline or assert continuing authority. Only the
    separate association worker may consume/discard the source; resume never does.
    Child termination can have a nonzero exit: cleanup is separately proven from
    the captured native handles, not a successful protocol retirement receipt.
    """
    def __init__(self, helper):
        if type(helper) is not LiveChannelPublicationCheck:
            raise TypeError('expected exact original live channel helper')
        source, recipient, acquisition, review = (getattr(helper, name) for name in
            ('_issued_lifecycle', '_issued_recipient', '_issued_acquisition', '_issued_review'))
        locks = (helper._lock, source._lock, recipient._lock, acquisition._lock, review._lock,
            review._reviews._lock, review._registry._lock, review._ledger._lock,
            helper._quarantine._lock, review._exchange._lock)
        if any(type(lock) is not _LOCK_TYPE for lock in locks):
            raise ResumableWitnessError('invalid_witness_owner')
        fields = tuple((owner, name, getattr(owner, name)) for owner, names in (
            (helper, ('_lifecycle', '_issued_lifecycle', '_recipient', '_issued_recipient',
                '_acquisition', '_issued_acquisition', '_review', '_issued_review',
                '_descriptor', '_recipient_descriptor', '_owned_buffer', '_quarantine',
                '_issued_cancel', '_cancel', '_timer', '_issued_timer')),
            (source, ('_wire', '_recipient', '_acquisition', '_review', '_owned_buffer')),
            (acquisition, ('_review',)),
            (review, ('_registry', '_ledger', '_reviews', '_exchange', '_timer', '_lease')),
            (review._reviews, ('_registry', '_ledger', '_lock')),
            (review._registry, ('_lock',)), (review._ledger, ('_lock',)),
            (helper._issued_timer, ('finished',)), (review._timer, ('finished',))
            ) for name in names)
        lock, cancel, resume = RLock(), Event(), Event()
        condition = Condition(lock)
        thread = Thread(target=_ResumableWitnessWorker._run, args=(self,), daemon=True)
        fields += tuple((condition, name, getattr(condition, name)) for name in
            ('_lock', '_release_save', '_acquire_restore', '_is_owned', '_waiters'))
        fields += ((thread, '_started', thread._started),)
        origin = _Origin(helper, source, recipient, acquisition, review, helper._descriptor,
            helper._owned_buffer, helper._deadline_snapshot, helper._issued_cancel, locks, fields,
            thread, lock, condition, cancel, resume)
        self._origin = self._issued_origin = self._recovery_origin = origin
        self._thread = self._issued_thread = thread
        self._lock, self._condition, self._cancel, self._resume = lock, condition, cancel, resume
        self._native = self._issued_native = self._recovery_native = None
        self._witness_wire = self._issued_witness_wire = self._recovery_witness_wire = None
        self._proof = self._issued_proof = self._recovery_proof = None
        self._join_corrupt = self._issued_join_corrupt = self._recovery_join_corrupt = False
        self._error = self._issued_error = None
        self._save('new', False, False, False, False, None, None)
        with self._guards(origin):
            helper._current()
            if helper._started is not False or helper._finished is not False:
                raise ResumableWitnessError('spent_witness_helper')

    @staticmethod
    def _recover(values, kind):
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise ResumableWitnessError('uncertain_witness_owner')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _History)

    def _save(self, *values):
        previous = getattr(self, '_history', None)
        seen = tuple((type(previous) is _History and getattr(previous, name))
            or getattr(self, field, None) is not None for name, field in (
                ('wire_seen', '_issued_witness_wire'), ('native_seen', '_issued_native'), ('proof_seen', '_issued_proof')))
        history = _History(*values, *seen)
        self._history = self._issued_history = self._recovery_history = history
        return history

    @contextmanager
    def _control(self, original, *, wait=False):
        limit = monotonic()+.05 if wait else 0
        while not original.lock.acquire(blocking=False):
            if not wait or monotonic() >= limit:
                raise ResumableWitnessError('busy_witness_control')
            # Only the private worker uses this short scheduling allowance.
            # It is forbidden while any original source/native guard is owned.
            self._assert_unlocked(original)
            sleep(.001)
        try: yield
        finally: original.lock.release()

    def _native_original(self):
        values = tuple(getattr(self, name, None) for name in ('_native', '_issued_native', '_recovery_native'))
        if all(value is None for value in values): return None
        return self._recover(values, _Native)

    def _wire_original(self):
        values = tuple(getattr(self, name, None) for name in
            ('_witness_wire', '_issued_witness_wire', '_recovery_witness_wire'))
        if all(value is None for value in values): return None
        return self._recover(values, _Wire)

    def _proof_original(self):
        values = tuple(getattr(self, name, None) for name in ('_proof', '_issued_proof', '_recovery_proof'))
        if all(value is None for value in values): return None
        return self._recover(values, _Proof)

    def _identity(self, original, *, active=True):
        history = self._status()
        if (any(getattr(self, name, None) is not original for name in
                ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in
                ('_history', '_issued_history', '_recovery_history'))
                or self._thread is not original.thread or self._issued_thread is not original.thread
                or type(original.thread) is not Thread or self._lock is not original.lock
                or self._condition is not original.condition or self._cancel is not original.cancel
                or self._resume is not original.resume or self._error is not self._issued_error
                or any(getattr(self, name, None) is not False for name in
                    ('_join_corrupt', '_issued_join_corrupt', '_recovery_join_corrupt'))
                or (self._error is not None and type(self._error) is not str)
                or type(history.state) is not str
                or any(type(value) is not bool for value in (history.started, history.finished, history.cleanup,
                    history.joined, history.wire_seen, history.native_seen, history.proof_seen))
                or any(value is not None and type(value) is not int for value in (history.ident, history.native_ident))
                or any(getattr(owner, name, None) is not value for owner, name, value in original.fields)
                or any(getattr(owner, '_lock', None) is not lock for owner, lock in zip(
                    (original.helper, original.source, original.recipient, original.acquisition, original.review,
                     original.review._reviews, original.review._registry, original.review._ledger,
                     original.helper._quarantine, original.review._exchange), original.locks))
                or type(original.deadline) is not float or type(original.helper._deadline) is not float
                or original.helper._deadline != original.deadline
                or original.helper._deadline_snapshot != original.deadline):
            raise ResumableWitnessError('changed_witness_owner')
        wire = self._wire_original()
        if wire is None and (history.wire_seen or original.helper._wire is not None
                or original.helper._issued_wire is not None):
            raise ResumableWitnessError('missing_witness_codec')
        if wire is not None:
            if (any(getattr(self, name, None) is not wire for name in
                    ('_witness_wire', '_issued_witness_wire', '_recovery_witness_wire'))
                    or type(wire.codec) is not RecipientWitnessExchange or wire.codec._lock is not wire.lock
                    or original.helper._wire is not wire.codec or original.helper._issued_wire is not wire.codec
                    or original.helper._wire_identity_snapshot != wire.identity
                    or tuple((type(item), item) for item in (wire.codec._role, wire.codec._role_snapshot,
                        wire.codec._session, wire.codec._session_snapshot, wire.codec._key_snapshot)) != wire.identity):
                raise ResumableWitnessError('changed_witness_codec')
        proof = self._proof_original()
        if proof is None and (history.proof_seen or original.helper._proof is not None
                or original.helper._issued_proof is not None or original.helper._proof_snapshot is not None):
            raise ResumableWitnessError('missing_witness_proof')
        if proof is not None:
            helper = original.helper
            if (any(getattr(self, name, None) is not proof for name in ('_proof', '_issued_proof', '_recovery_proof'))
                    or type(proof.evidence) is not RecipientWitnessEvidence
                    or helper._proof is not proof.evidence or helper._issued_proof is not proof.evidence
                    or _values(proof.evidence) != proof.values or helper._proof_snapshot != proof.values
                    or wire is None or type(wire.codec._previous) is not str or wire.codec._previous != proof.previous):
                raise ResumableWitnessError('changed_witness_proof')
        native = self._native_original()
        if native is None and (history.native_seen or original.helper._child is not None
                or original.helper._issued_child is not None or original.helper._native_observation is not None):
            raise ResumableWitnessError('missing_witness_channel')
        if native is not None:
            child, helper = native.child, original.helper
            if (any(getattr(self, name, None) is not native for name in ('_native', '_issued_native', '_recovery_native'))
                    or type(child) is not _RecipientWitnessChild or child._ownership is not native.api
                    or type(native.api) is not _OwnershipApi or child._ownership_lock is not native.lock
                    or child._owned is not native.owned or child._issued_owned is not native.owned
                    or child._anchor_snapshot is not native.anchors or child._issued_anchors is not native.anchors
                    or child._seal_snapshot is not native.seals or child._issued_seals is not native.seals
                    or child._issued_observation is not native.observation
                    or type(native.observation) is not ProcessChannelObservation
                    or _values(native.observation) != native.observation_values
                    or helper._child is not child or helper._issued_child is not child
                    or helper._native_observation is not native.observation
                    or helper._child_snapshot != native.observation_values or helper._native_snapshot != native.observation_values
                    or helper._wire is not native.wire or helper._issued_wire is not native.wire
                    or type(native.wire) is not RecipientWitnessExchange or native.wire._lock is not native.wire_lock):
                raise ResumableWitnessError('changed_witness_channel')
        if active and (original.cancel.is_set() or monotonic() >= original.deadline):
            raise ResumableWitnessError('expired_or_cancelled_witness')
        return history

    def _assert_unlocked(self, original):
        native = self._native_original()
        wire = self._wire_original()
        extra = (() if native is None else (native.lock,))+(() if wire is None else (wire.lock,))
        for lock in original.locks+extra+(original.lock,):
            if type(lock) is not _LOCK_TYPE: raise ResumableWitnessError('invalid_witness_guard')
            if _LOCK_TYPE._is_owned(lock):
                raise ResumableWitnessError('authority_held_across_witness_wait')

    @contextmanager
    def _guards(self, original):
        native = self._native_original()
        wire = self._wire_original()
        extra = (() if native is None else (native.lock,))+(() if wire is None else (wire.lock,))
        with ExitStack() as stack:
            if current_thread() is original.thread:
                # Readiness polling may briefly own control. Resolve that
                # scheduling race before taking any source/authority guard;
                # every subsequent source acquisition remains nonblocking.
                stack.enter_context(self._control(original, wait=True))
            for lock in original.locks+extra+(original.lock,):
                if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                    raise ResumableWitnessError('busy_witness_owner')
                stack.callback(lock.release)
            yield

    def _current(self, original):
        with self._guards(original):
            self._identity(original)
            original.helper._current()
            native = self._native_original()
            if native is not None: original.helper._native_current()
            self._identity(original)

    @contextmanager
    def _disposal_guards(self, original, locks, until):
        # Retry acquisition only; never repeat an operation or recover active
        # authority. Every failed attempt drops ALL acquired guards before the
        # bounded scheduling wait, allowing the cancelled association to unwind.
        self._assert_unlocked(original)
        while True:
            stack = ExitStack()
            try:
                if monotonic() >= until: raise ResumableWitnessError('witness_cleanup_deadline')
                for lock in locks:
                    if type(lock) is not _LOCK_TYPE: raise ResumableWitnessError('invalid_witness_disposal_guard')
                    if not lock.acquire(blocking=False): break
                    stack.callback(lock.release)
                else:
                    try: yield
                    finally: stack.close()
                    return
            except BaseException:
                stack.close()
                raise
            stack.close()
            self._assert_unlocked(original)
            if monotonic() >= until: raise ResumableWitnessError('witness_cleanup_deadline')
            sleep(.002)

    def start(self, app, credential, proposal, descriptor):
        original = self._original()
        self._assert_unlocked(original)
        with self._control(original):
            history = self._identity(original)
            if history.started or history.finished:
                original.cancel.set(); raise ResumableWitnessError('witness_attempt_spent')
            if (original.thread._target is not _ResumableWitnessWorker._run
                    or type(original.thread._args) is not tuple or original.thread._args != (self,)
                    or type(original.thread._kwargs) is not dict or original.thread._kwargs):
                raise ResumableWitnessError('changed_witness_thread')
            self._inputs = self._issued_inputs = (app, credential, proposal, descriptor)
            self._save('starting', True, False, False, False, None, None)
        # The worker must not compete with its own launcher for the control
        # mutex. Inputs and the one-use starting state are sealed before launch.
        try: Thread.start(original.thread)
        except BaseException:
            original.cancel.set()
            with self._control(original):
                self._error = self._issued_error = 'witness_start_failed'
                self._save('failed', True, True, False, True, None, None)
            raise ResumableWitnessError('witness_start_failed') from None

    def ready_helper(self):
        original = self._original()
        try:
            with self._control(original):
                history = self._identity(original)
                if history.state != 'ready' or history.finished: return None
                if original.resume.is_set(): raise ResumableWitnessError('witness_already_resumed')
        except ResumableWitnessError as error:
            if str(error) == 'busy_witness_control': return None
            raise
        try:
            self._current(original)
            with self._guards(original):
                history = self._identity(original)
                if history.state != 'ready' or original.resume.is_set(): raise ResumableWitnessError('witness_not_ready')
                original.helper._proof_current(); original.helper._wire_current(2)
                self._identity(original)
                return original.helper
        except ResumableWitnessError as error:
            # No readiness is released from a contended graph. The enclosing
            # bounded poll may retry after every captured guard has unwound.
            if str(error) in ('busy_witness_owner', 'busy_witness_control'): return None
            raise

    def resume(self):
        original = self._original()
        with self._control(original):
            history = self._identity(original)
            if history.state != 'ready' or history.finished or original.resume.is_set():
                original.cancel.set(); raise ResumableWitnessError('invalid_witness_resume')
            original.resume.set(); original.condition.notify_all()

    def cancel(self):
        original = self._original()
        original.cancel.set()
        with self._control(original): original.condition.notify_all()

    close = cancel

    def join(self, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 5 or not math.isfinite(timeout):
            raise ResumableWitnessError('invalid_witness_join_lifetime')
        original = self._original()
        thread = original.thread
        if type(thread) is not Thread: raise ResumableWitnessError('uncertain_witness_thread')
        invalid = False
        try: self._assert_unlocked(original)
        except ResumableWitnessError as error:
            if str(error) == 'authority_held_across_witness_wait': raise
            invalid = True
        except BaseException: invalid = True
        if current_thread() is original.thread: raise ResumableWitnessError('witness_cannot_join_itself')
        try:
            with self._control(original):
                history = self._identity(original, active=False)
                if not history.started: invalid = True
        except ResumableWitnessError as error:
            # A running worker may briefly own control while publishing its
            # terminal journal. That does not prevent joining its captured
            # original Thread; structural failures remain irreversible.
            if str(error) != 'busy_witness_control': invalid = True
        except BaseException: invalid = True
        if invalid:
            self._join_corrupt = self._issued_join_corrupt = self._recovery_join_corrupt = True
            original.cancel.set()
        # Cleanup never selects the mutable public/issued Thread fields. Even
        # rejected owner state must join its captured original outside guards.
        try: Thread.join(thread, timeout)
        except BaseException: raise ResumableWitnessError('witness_join_failed') from None
        if invalid: raise ResumableWitnessError('changed_witness_join_owner')
        try:
            with self._control(original):
                history = self._identity(original, active=False)
                if Thread.is_alive(thread) or not history.finished: return False
                if (history.ident != thread.ident or history.native_ident != thread.native_id
                        or type(history.ident) is not int or type(history.native_ident) is not int):
                    raise ResumableWitnessError('changed_witness_thread')
                self._save(history.state, True, True, history.cleanup, True, history.ident, history.native_ident)
                return True
        except BaseException:
            self._join_corrupt = self._issued_join_corrupt = self._recovery_join_corrupt = True
            original.cancel.set()
            raise ResumableWitnessError('changed_witness_join_owner') from None

    def inspect(self):
        original = self._original()
        with self._control(original):
            history = self._identity(original, active=False)
            return dict(state=history.state, finished=history.finished,
                        joined=history.joined, cleanup_confirmed=history.cleanup)

    def _run(self):
        original = self._original()
        child = wire = native = wire_origin = None
        cleanup, failure = True, None
        ident, native_ident = current_thread().ident, current_thread().native_id
        try:
            with self._control(original, wait=True):
                history = self._identity(original)
                if current_thread() is not original.thread or history.state != 'starting':
                    raise ResumableWitnessError('wrong_witness_worker')
                self._save('starting', True, False, False, False, ident, native_ident)
                if self._inputs is not self._issued_inputs or type(self._inputs) is not tuple or len(self._inputs) != 4:
                    raise ResumableWitnessError('changed_witness_inputs')
                app, credential, proposal, descriptor = self._inputs
            helper = original.helper
            with self._guards(original):
                self._identity(original)
                if helper._started is not False or helper._finished is not False:
                    raise ResumableWitnessError('spent_witness_helper')
                helper._started = True
                helper._current()
                if descriptor is not original.descriptor: raise ResumableWitnessError('wrong_witness_recipient')
                with original.review._lease(), original.review._ledger._lock:
                    original.source._authenticate(app, credential, proposal)
                    self._identity(original)
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            wire = RecipientWitnessExchange(role='coordinator', key=key, session=session)
            wire_identity = tuple((type(item), item) for item in (wire._role,
                wire._role_snapshot, wire._session, wire._session_snapshot, wire._key_snapshot))
            wire_origin = _Wire(wire, wire._lock, wire_identity)
            with self._control(original, wait=True):
                self._witness_wire = self._issued_witness_wire = self._recovery_witness_wire = wire_origin
                helper._wire = helper._issued_wire = wire
                helper._wire_identity_snapshot = wire_identity
            with self._guards(original):
                self._identity(original)
                request = wire.request(loads(helper._binding_snapshot)); helper._wire_current(1)
                self._identity(original)
            self._current(original); self._assert_unlocked(original)
            child = _RecipientWitnessChild()
            observation = child._issued_observation
            native = _Native(child, child._ownership_lock, child._ownership, child._issued_owned,
                child._anchor_snapshot, child._seal_snapshot, observation, _values(observation), wire, wire._lock)
            with self._control(original, wait=True):
                self._native = self._issued_native = self._recovery_native = native
                helper._child = helper._issued_child = child
                helper._native_observation = observation
                helper._child_snapshot = helper._native_snapshot = native.observation_values
            if (type(native.lock) is not _LOCK_TYPE or type(native.api) is not _OwnershipApi
                    or type(observation) is not ProcessChannelObservation
                    or type(observation.pid) is not int or not 0 < observation.pid <= 0xffffffff
                    or type(observation.creation_time) is not int or not 0 < observation.creation_time <= 0xffffffffffffffff
                    or native.wire_lock is not wire_origin.lock):
                raise ResumableWitnessError('invalid_witness_channel')
            self._current(original)

            def write(data):
                offset = 0
                while offset < len(data):
                    self._current(original); self._assert_unlocked(original)
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if type(count) is not int or not 0 < count <= len(data)-offset:
                            raise ResumableWitnessError('witness_pipe_failed')
                        offset += count
                    except BlockingIOError: sleep(.002)
                    self._current(original)

            def read(size):
                value = bytearray()
                while len(value) < size:
                    self._current(original); self._assert_unlocked(original)
                    try:
                        data = os.read(child.stdout_fd, size-len(value))
                        if type(data) is not bytes or not data or len(data) > size-len(value):
                            raise ResumableWitnessError('truncated_witness_output')
                        value.extend(data)
                    except BlockingIOError: sleep(.002)
                    self._current(original)
                return bytes(value)

            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, observation.pid)):
                raise ResumableWitnessError('witness_startup_failed')
            write(request)
            prefix = read(4); size = int.from_bytes(prefix, 'big')
            if not 32 <= size <= MAX_BODY_BYTES+32: raise ResumableWitnessError('witness_output_limit')
            frame = prefix+read(size)
            expected_previous = hashlib.sha256(frame).hexdigest()
            expected_phase = ((int, 2), (str, expected_previous), (str, 'new'))
            with self._guards(original):
                self._identity(original); helper._current(); helper._native_current()
                helper._proof = helper._issued_proof = wire.accept_proof(frame)
                helper._proof_snapshot = _values(helper._proof)
                helper._proof_current(); helper._wire_current(2); helper._current(); helper._native_current()
                if (type(wire._previous) is not str or wire._previous != expected_previous
                        or type(wire._phase_snapshot) is not tuple
                        or tuple((type(value), value) for value in wire._phase_snapshot) != expected_phase):
                    raise ResumableWitnessError('changed_witness_transcript')
                proof = _Proof(helper._proof, helper._proof_snapshot, expected_previous, expected_phase)
                self._proof = self._issued_proof = self._recovery_proof = proof
                helper._state = 'witnessed'
                self._identity(original); helper._proof_current(); helper._wire_current(2); helper._current()
                self._save('ready', True, False, False, False, ident, native_ident)
                original.condition.notify_all()
            # No authority probe here: association consumes the original source
            # concurrently. This wait carries no freshness claim or permission.
            while True:
                self._assert_unlocked(original)
                with self._control(original, wait=True):
                    self._identity(original)
                    if original.resume.is_set(): break
                    original.condition.wait(min(.01, max(0, original.deadline-monotonic())))
            # A normally resumed original witness must still be the original
            # live process. Association evidence cannot hide a death that occurs
            # after its seal. The source may now be spent, so this is strictly a
            # captured native liveness check, never a second authority decision.
            self._assert_unlocked(original)
            if not native.lock.acquire(blocking=False): raise ResumableWitnessError('busy_witness_resume')
            try:
                self._identity(original); child._validate(); self._identity(original)
            finally: native.lock.release()
        except BaseException:
            failure = 'witness_failed'
        finally:
            original.cancel.set()
            # A single three-second acquisition budget leaves room for the
            # native owner's bounded termination/join; no active deadline or
            # authority is extended. Cleanup operations themselves run once.
            disposal_until = monotonic()+3
            try:
                try: self._identity(original, active=False)
                except BaseException: cleanup = False
                if failure is not None or not cleanup: original.helper_cancel.set()
                try:
                    if self._native_original() is not native: cleanup = False
                except BaseException: cleanup = False
                try:
                    if self._wire_original() is not wire_origin: cleanup = False
                except BaseException: cleanup = False
                if native is not None:
                    self._native = self._issued_native = self._recovery_native = native
                if wire_origin is not None:
                    self._witness_wire = self._issued_witness_wire = self._recovery_witness_wire = wire_origin
                if child is not None:
                    self._assert_unlocked(original)
                    if native is None or native.child is not child: raise ResumableWitnessError('uncertain_witness_channel')
                    if child._ownership is not native.api or child._ownership_lock is not native.lock: cleanup = False
                    child._ownership, child._ownership_lock = native.api, native.lock
                    with self._disposal_guards(original, (native.lock,), disposal_until):
                        child.close()
                        if child._ownership is not native.api or child._ownership_lock is not native.lock:
                            cleanup = False
                            child._ownership, child._ownership_lock = native.api, native.lock
                        child._retired()
                        self._native_retired_shape(native)
                        try: self._identity(original, active=False)
                        except BaseException: cleanup = False
            except BaseException: cleanup = False
            try:
                if not cleanup: original.helper_cancel.set()
                # Running-stack originals are retained before any publication;
                # recover only those disposal targets, never changed aliases.
                try:
                    if self._wire_original() is not wire_origin: cleanup = False
                except BaseException: cleanup = False
                if wire_origin is not None:
                    self._witness_wire = self._issued_witness_wire = self._recovery_witness_wire = wire_origin
                if native is not None:
                    self._native = self._issued_native = self._recovery_native = native
                disposal_locks = original.locks+(() if native is None else (native.lock,))+(
                    () if wire_origin is None else (wire_origin.lock,))+(original.lock,)
                with self._disposal_guards(original, disposal_locks, disposal_until):
                    try: self._identity(original, active=False)
                    except BaseException: cleanup = False
                    # Original graph restoration is disposal only; a detected
                    # substitution can never become a successful cleanup fact.
                    for owner, name, value in original.fields: setattr(owner, name, value)
                    for owner, lock in zip((original.helper, original.source, original.recipient,
                        original.acquisition, original.review, original.review._reviews, original.review._registry,
                        original.review._ledger, original.helper._quarantine, original.review._exchange), original.locks):
                        owner._lock = lock
                    if wire is not None:
                        original.helper._wire = original.helper._issued_wire = wire
                        wire._lock = wire_origin.lock
                    original.helper._dispose()
                    try: self._identity(original, active=False)
                    except BaseException: cleanup = False
            except BaseException: cleanup = False
            try:
                original.buffer[:] = b'\0'*len(original.buffer); original.buffer.clear()
                if type(original.buffer) is not bytearray or original.buffer: cleanup = False
            except BaseException: cleanup = False
            with self._control(original, wait=True):
                helper = original.helper
                helper._finished, helper._cleanup_confirmed, helper._state = True, cleanup, 'retired'
                self._error = self._issued_error = failure
                self._save('retired' if cleanup else 'failed', True, True, cleanup, False, ident, native_ident)
                original.condition.notify_all()

    @staticmethod
    def _native_retired_shape(native):
        child = native.child
        if (child._closed is not True or child._cleanup_failed is not False
                or child._process is not None or child._job is not None
                or type(child._fds) is not set or child._fds
                or type(child._anchors) is not dict or child._anchors
                or type(child._seals) is not dict or child._seals
                or child._owned is not native.owned or child._issued_owned is not native.owned
                or child._anchor_snapshot is not native.anchors or child._issued_anchors is not native.anchors
                or child._seal_snapshot is not native.seals or child._issued_seals is not native.seals
                or child._ownership is not native.api or child._ownership_lock is not native.lock
                or child._issued_observation is not native.observation
                or _values(native.observation) != native.observation_values
                or type(child.stdin_fd) is not int or child.stdin_fd != native.owned[0]
                or type(child.stdout_fd) is not int or child.stdout_fd != native.owned[1]
                or type(child.pid) is not int or child.pid != native.observation_values[0][2]
                or type(child._input_closed) is not bool or type(child._exit) is not int
                or type(child._retired_snapshot) is not tuple or len(child._retired_snapshot) != 2
                or type(child._retired_snapshot[0]) is not int or type(child._retired_snapshot[1]) is not bool
                or child._retired_snapshot != (child._exit, child._input_closed)):
            raise ResumableWitnessError('witness_native_cleanup_uncertain')

    def verify_retired(self):
        original = self._original()
        # Terminal inspection performs no transport, wait or native query. An
        # enclosing final fence may already own these captured original guards.
        with self._guards(original):
            history = self._identity(original, active=False)
            helper, native = original.helper, self._native_original()
            if (type(history.state) is not str or history.state != 'retired'
                    or history.started is not True or history.finished is not True or history.cleanup is not True
                    or history.joined is not True or Thread.is_alive(original.thread)
                    or type(history.ident) is not int or history.ident != original.thread.ident
                    or type(history.native_ident) is not int or history.native_ident != original.thread.native_id
                    or helper._finished is not True or helper._cleanup_confirmed is not True
                    or type(helper._state) is not str or helper._state != 'retired'
                    or helper._issued_timer.finished.is_set() is not True
                    or type(original.buffer) is not bytearray or original.buffer
                    or helper._owner_changed is not False or original.source._state != 'closed'
                    or original.acquisition._closed is not True or original.review._state != 'closed'
                    or original.recipient._terminal is not True or original.recipient._state != 'closed'
                    or original.source._wire._buffer is not original.buffer
                    or original.source._wire._issued_buffer is not original.buffer
                    or type(original.source._wire._state) is not str or original.source._wire._state != 'closed'
                    or type(original.source._wire._step) is not int or original.source._wire._step != 4
                    or type(original.source._wire._key) is not bytes or original.source._wire._key
                    or type(original.review._exchange._state) is not str or original.review._exchange._state != 'closed'
                    or type(original.review._exchange._key) is not bytes or original.review._exchange._key
                    or original.review._timer.finished.is_set() is not True):
                raise ResumableWitnessError('witness_cleanup_uncertain')
            if native is not None:
                native.child._retired()
                self._native_retired_shape(native)
                if (native.wire._state != 'closed' or type(native.wire._key) is not bytes or native.wire._key
                        or type(native.wire._step) is not int or native.wire._step != 4
                        or native.wire._binding is not None or native.wire._binding_snapshot is not None
                        or native.wire._binding_digest is not None):
                    raise ResumableWitnessError('witness_codec_cleanup_uncertain')
            proof = self._proof_original()
            if proof is not None:
                helper._proof_current()
                phase = native.wire._phase_snapshot
                if (type(phase) is not tuple or tuple((type(value), value) for value in phase) !=
                        ((int, 4), (str, proof.previous), (str, 'closed'))):
                    raise ResumableWitnessError('witness_transcript_cleanup_uncertain')
            self._identity(original, active=False)
            if native is not None: self._native_retired_shape(native)
            if (original.buffer or original.helper._finished is not True
                    or original.helper._cleanup_confirmed is not True
                    or original.helper._state != 'retired' or self._status() is not history):
                raise ResumableWitnessError('witness_cleanup_uncertain')
            return dict(state='retired', worker_joined=True, cleanup_confirmed=True, released_bytes=0)
