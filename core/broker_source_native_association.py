"""Inactive original-source/native-recipient association; discard only.

The original dry commit's channel is preserved. A separately launched fixed
metadata peer is observed and associated, never substituted into that source.
No payload, resource acquisition or active host integration exists. Native I/O
and join reject callers holding any captured source/authority lock.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import os
import secrets
from threading import Event, RLock
from time import monotonic, sleep

from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_dispatch_model_protocol import PublicationDispatchExchange
from .broker_live_dispatch_reservation import LiveDispatchReservationDryRun
from .broker_process import BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .broker_recipient_process import ProcessChannelObservation, _OwnershipApi
from .broker_source_association_peer import _SourceAssociationPeer
from .broker_source_association_protocol import SourceRecipientAssociationExchange, SourceRecipientAssociationEvidence, _MEANING as _WIRE_MEANING
from .json_input import loads

_MEANING = 'Retired inactive original-source/native association; not authority or delivery permission.'
_LOCK_TYPE = type(RLock())
_Origin = namedtuple('_Origin', 'gate source lock cancel deadline grant fingerprint peer peer_lock model_lock')
_History = namedtuple('_History', 'state started finished consumed cleanup result snapshot')


class SourceNativeAssociationError(RuntimeError):
    pass


def _facts(value):
    return tuple((type(x), x) for x in (value.canonical_binding, value.binding_digest,
                                      value.outcome, value.released_bytes, value.meaning))


@dataclass(frozen=True)
class SourceNativeAssociationEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    outcome: str = field(default='associated_discarded', init=False)
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('An association fact is not permission')


class SourceNativeAssociationDryRun:
    """One original ready commit, two separate original live native channels.

    Trusted bootstrap supplies the original commit graph. Association declares
    a fixed test recipient for that original authenticated application; it is
    not independent installed-application identity or general app onboarding.
    The original witness worker alone closes its own child. This worker alone
    closes the new child, outside source/authority locks. Uncertain cleanup must
    poison admission in a future host; this prototype supplies no active host.
    """
    def __init__(self, commit_draft, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 5 or not math.isfinite(timeout):
            raise SourceNativeAssociationError('invalid_association_lifetime')
        key, session = secrets.token_bytes(32), secrets.token_bytes(32)
        gate = LiveDispatchReservationDryRun(commit_draft, key=key, session=session, timeout=timeout)
        source = gate._original()
        # Retain a disposal owner before any later bootstrap check can fail.
        # Empty grant/fingerprint/peer fields are cleanup-only, never authority.
        origin = _Origin(gate, source, RLock(), Event(), source.deadline,
                         None, None, None, None, source.model_ledger._issued_lock)
        try:
            peer = PublicationDispatchExchange(role='broker', key=key, session=session)
            origin = origin._replace(peer=peer, peer_lock=peer._lock)
            fingerprint = source.review._app_snapshot
            if type(fingerprint) is not bytes or len(fingerprint) != 32:
                raise SourceNativeAssociationError('invalid_association_source')
            origin = origin._replace(grant=source.review._ticket.grant_id, fingerprint=fingerprint.hex())
            self._origin = self._issued_origin = self._recovery_origin = origin
            self._reservation = self._issued_reservation = gate
            self._lock, self._cancel = origin.lock, origin.cancel
            self._deadline = origin.deadline
            self._child = self._issued_child = self._native_observation = None
            self._result = self._issued_result = None
            self._save('new', False, False, False, False)
            self._source_current('new')
        except BaseException:
            cleaned = self._dispose_source(origin)
            raise SourceNativeAssociationError('association_bootstrap_failed' if cleaned
                else 'association_bootstrap_cleanup_failed') from None

    @staticmethod
    def _recover(values, kind):
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise SourceNativeAssociationError('uncertain_association_owner')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _History)

    def _save(self, state, started, finished, consumed, cleanup, *, result=None, snapshot=None):
        history = _History(state, started, finished, consumed, cleanup, result, snapshot)
        self._history = self._issued_history = self._recovery_history = history
        self._state, self._started, self._finished = state, started, finished
        self._source_consumed, self._cleanup_confirmed = consumed, cleanup
        self._result = self._issued_result = result
        return history

    def _structural_identity(self, original):
        history = self._status()
        if (any(getattr(self, name, None) is not original for name in
                ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in
                ('_history', '_issued_history', '_recovery_history'))
                or self._reservation is not original.gate or self._issued_reservation is not original.gate
                or self._lock is not original.lock or self._cancel is not original.cancel
                or type(self._deadline) is not float or self._deadline != original.deadline
                or tuple((type(x), x) for x in (self._state, self._started, self._finished,
                    self._source_consumed, self._cleanup_confirmed)) !=
                    ((str, history.state), (bool, history.started), (bool, history.finished),
                     (bool, history.consumed), (bool, history.cleanup))
                or self._result is not history.result or self._issued_result is not history.result
                or (history.result is not None and (type(history.result) is not SourceNativeAssociationEvidence
                    or _facts(history.result) != history.snapshot))
                or original.peer._lock is not original.peer_lock
                or original.source.model_ledger._lock is not original.model_lock
                or original.source.model_ledger._issued_lock is not original.model_lock):
            raise SourceNativeAssociationError('changed_association_owner')
        return history

    def _identity(self, original):
        history = self._structural_identity(original)
        if original.cancel.is_set() or monotonic() >= original.deadline:
            raise SourceNativeAssociationError('expired_or_cancelled_association')
        return history

    @staticmethod
    def _source_locks(original):
        o = original.source
        return o.owner_locks+(o.reviews_lock, o.registry_lock, o.review_ledger_lock, o.native_lock)+tuple(
            lock for _, lock in o.codec_locks)+(original.model_lock,)+(
                () if original.peer is None else (original.peer_lock,))

    def _assert_io_unlocked(self, original):
        # A lock can be reentrant: successful acquire would not reveal that the
        # old host already holds authority across its final callback.
        if any(lock._is_owned() for lock in self._source_locks(original)+(original.lock,)):
            raise SourceNativeAssociationError('authority_held_across_native_io')

    @contextmanager
    def _locked_source(self, original):
        with ExitStack() as stack:
            for lock in self._source_locks(original)+(original.lock,):
                if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                    raise SourceNativeAssociationError('busy_association_source')
                stack.callback(lock.release)
            yield

    def _source_current(self, model_state, *, consumed=False):
        original = self._original()
        with self._locked_source(original):
            self._identity(original)
            o = original.source
            with original.gate._authority(o):
                original.gate._current('retired' if consumed else model_state,
                    consumed=consumed, model_state=model_state)
                if (o.review._ticket.grant_id != original.grant
                        or type(o.review._app_snapshot) is not bytes
                        or o.review._app_snapshot.hex() != original.fingerprint):
                    raise SourceNativeAssociationError('changed_association_grant')
                self._identity(original)

    def _source_retired_current(self, original):
        with self._locked_source(original):
            self._identity(original)
            o = original.source
            original.gate._identity(o, active=False)
            with o.lease(), o.review_ledger_lock, o.native_lock:
                o.draft._current('consumed', 3)
                original.gate._identity(o, active=False)
                if (original.gate._state != 'closed' or original.gate._attempted is not True
                        or original.gate._terminal is not True or original.gate._cancelled is not True
                        or not o.cancel.is_set() or not o.timer.finished.is_set()
                        or o.model_ledger._closed is not True or o.buffer
                        or not self._codec_retired(original.peer, original.peer_lock)
                        or o.review._ticket.grant_id != original.grant
                        or type(o.review._app_snapshot) is not bytes
                        or o.review._app_snapshot.hex() != original.fingerprint):
                    raise SourceNativeAssociationError('changed_association_retired_source')
                self._identity(original)

    def inspect(self):
        original = self._original()
        with original.lock:
            history = self._structural_identity(original)
            # Terminal facts are historical, never renewed freshness.
            if not history.finished: self._identity(original)
            return dict(state=history.state, cleanup_confirmed=history.cleanup, source_consumed=history.consumed)

    def close(self):
        original = self._original()
        with original.lock:
            history = self._status()
            if history.finished: return
            original.cancel.set()
            if not history.started:
                cleaned = self._dispose_source(original)
                self._save('failed', True, True, False, cleaned)
                if not cleaned: raise SourceNativeAssociationError('association_cleanup_failed')

    cancel = close

    @staticmethod
    def _codec_retired(codec, lock):
        return (codec._lock is lock and type(codec._key) is bytes and codec._key == b''
            and type(codec._state) is str and codec._state == 'closed'
            and type(codec._step) is int and codec._step == 4
            and codec._binding is None and codec._binding_snapshot is None and codec._binding_digest is None)

    def _dispose_peer(self, original):
        if original.peer is None: return True  # Failed before private peer construction.
        cleaned = original.peer._lock is original.peer_lock
        # Restore only the captured disposal target. Changed ownership remains
        # a failure even when its original private key can still be retired.
        original.peer._lock = original.peer_lock
        if not original.peer_lock.acquire(blocking=False): return False
        try:
            original.peer.close()
            return cleaned and self._codec_retired(original.peer, original.peer_lock)
        except BaseException: return False
        finally: original.peer_lock.release()

    def _dispose_source(self, original):
        o, cleaned = original.source, True
        # Signal captured originals before any lock attempt. Never synchronously
        # join the original worker or select a mutable foreign native field.
        o.helper_cancel.set(); o.draft_cancel.set(); o.cancel.set()
        # Failure only removes usability. These terminal markers never create
        # or restore authority, even if a busy original owner delays disposal.
        o.draft._attempted, o.source._publication_attempted = True, True
        try:
            with self._locked_source(original): original.gate.close()
        except BaseException: cleaned = False
        try:
            o.buffer[:] = b'\0'*len(o.buffer); o.buffer.clear()
            if type(o.buffer) is not bytearray or o.buffer: cleaned = False
        except BaseException: cleaned = False
        return self._dispose_peer(original) and cleaned

    def run(self, app, credential, proposal, descriptor):
        original = self._original()
        with original.lock:
            history = self._status()
            if history.started:
                if not history.finished: original.cancel.set()
                raise SourceNativeAssociationError('association_attempt_spent')
            try: self._identity(original)
            except BaseException:
                original.cancel.set()
                cleaned = self._dispose_source(original)
                self._save('failed', True, True, False, cleaned)
                raise SourceNativeAssociationError('association_rejected') from None
            self._save('running', True, False, False, False)
        child = wire = wire_lock = native_lock = native_api = observation = None
        observation_snapshot = child_owned = child_anchors = child_seals = None
        model_state, consumed, candidate, expected, proof, ack = 'new', False, None, None, None, None
        cleanup_ok, failure, sealed = True, None, False
        o = original.source

        def dispose_wire():
            if wire is None: return True
            unchanged = wire._lock is wire_lock and wire._issued_lock is wire_lock
            wire._lock = wire_lock  # Captured original disposal only.
            if not wire_lock.acquire(blocking=False): return False
            try:
                wire.close()
                return unchanged and wire._issued_lock is wire_lock and self._codec_retired(wire, wire_lock)
            except BaseException: return False
            finally: wire_lock.release()

        try:
            self._assert_io_unlocked(original)
            self._source_current(model_state)
            with self._locked_source(original), original.gate._authority(o):
                o.source._authenticate(app, credential, proposal)
                if descriptor is not o.descriptor: raise SourceNativeAssociationError('wrong_association_recipient')
                self._identity(original)
            with self._locked_source(original):
                request = original.gate.prepare(); model_state = 'prepared'
                original.peer.accept_prepare(request)
                original.gate.accept_ready(original.peer.ready()); model_state = 'ready'
            self._source_current(model_state)
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            wire = SourceRecipientAssociationExchange(role='coordinator', key=key, session=session)
            wire_lock = wire._lock
            self._assert_io_unlocked(original)
            child = self._child = self._issued_child = _SourceAssociationPeer()
            native_lock, native_api = child._ownership_lock, child._ownership
            child_owned, child_anchors, child_seals = child._issued_owned, child._anchor_snapshot, child._seal_snapshot
            observation = self._native_observation = child._issued_observation
            if (type(native_lock) is not _LOCK_TYPE or type(native_api) is not _OwnershipApi
                    or type(observation) is not ProcessChannelObservation):
                raise SourceNativeAssociationError('invalid_association_channel')
            observation_snapshot = (type(observation.pid), observation.pid, type(observation.creation_time), observation.creation_time)
            if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
            try:
                if child._observe() is not observation: raise SourceNativeAssociationError('changed_association_channel')
            finally: native_lock.release()
            binding = dict(revision=1, mode='source_native_association_discard_only', association_id=secrets.token_hex(32),
                source_commit_json=o.envelope.decode('ascii'), grant_id=original.grant, grant_fingerprint=original.fingerprint,
                recipient_channel=dict(pid=observation.pid, creation_time=observation.creation_time, witness_session=session.hex()))
            envelope = _canonical(binding)
            expected = ((bytes, envelope), (str, hashlib.sha256(envelope).hexdigest()),
                        (str, 'associated_discarded'), (int, 0), (str, _MEANING))

            def channel_identity():
                if (self._child is not child or self._issued_child is not child
                            or type(child) is not _SourceAssociationPeer or child._ownership_lock is not native_lock
                            or child._ownership is not native_api or type(native_api) is not _OwnershipApi
                            or self._native_observation is not observation or child._issued_observation is not observation
                            or type(observation) is not ProcessChannelObservation
                            or (type(observation.pid), observation.pid, type(observation.creation_time), observation.creation_time) != observation_snapshot
                            or child._owned is not child_owned or child._issued_owned is not child_owned
                            or child._anchor_snapshot is not child_anchors or child._issued_anchors is not child_anchors
                            or child._seal_snapshot is not child_seals or child._issued_seals is not child_seals
                            or wire._lock is not wire_lock):
                    raise SourceNativeAssociationError('changed_association_channel')

            def check(*, retiring=False):
                self._source_current(model_state, consumed=consumed)
                with original.lock:
                    self._identity(original); channel_identity()
                    if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
                    try: child._validate(retiring=retiring)
                    finally: native_lock.release()
                    self._identity(original); channel_identity()
                self._source_current(model_state, consumed=consumed)
                with original.lock: self._identity(original); channel_identity()

            def retired_channel_identity():
                channel_identity()
                if (not self._codec_retired(wire, wire_lock) or wire._issued_lock is not wire_lock
                        or not self._codec_retired(original.peer, original.peer_lock)
                        or child._closed is not True or child._cleanup_failed is not False
                        or child._input_closed is not True or type(child._exit) is not int or child._exit != 0
                        or child._process is not None or child._job is not None
                        or type(child._fds) is not set or child._fds
                        or type(child._anchors) is not dict or child._anchors
                        or type(child._seals) is not dict or child._seals
                        or type(child.stdin_fd) is not int or child.stdin_fd != child_owned[0]
                        or type(child.stdout_fd) is not int or child.stdout_fd != child_owned[1]
                        or type(child.pid) is not int or child.pid != observation_snapshot[1]
                        or type(child._retired_snapshot) is not tuple or len(child._retired_snapshot) != 2
                        or type(child._retired_snapshot[0]) is not int or type(child._retired_snapshot[1]) is not bool
                        or child._retired_snapshot != (0, True)):
                    raise SourceNativeAssociationError('changed_association_retirement')

            def wire_call(operation, *args):
                channel_identity()
                if not wire_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_codec')
                try:
                    channel_identity(); value = operation(*args); channel_identity()
                    return value
                finally: wire_lock.release()

            def write(data):
                offset = 0
                while offset < len(data):
                    check(); self._assert_io_unlocked(original)
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if type(count) is not int or not 0 < count <= len(data)-offset:
                            raise SourceNativeAssociationError('association_pipe_failed')
                        offset += count
                    except BlockingIOError: sleep(.002)
                    check()

            def read(size, *, retiring=False):
                value = bytearray()
                while len(value) < size:
                    check(retiring=retiring); self._assert_io_unlocked(original)
                    try:
                        chunk = os.read(child.stdout_fd, size-len(value))
                        if type(chunk) is not bytes or not chunk or len(chunk) > size-len(value):
                            raise SourceNativeAssociationError('truncated_association_output')
                        value.extend(chunk)
                    except BlockingIOError: sleep(.002)
                    check(retiring=retiring)
                return bytes(value)

            def frame(*, retiring=False):
                prefix = read(4, retiring=retiring); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32: raise SourceNativeAssociationError('association_output_limit')
                return prefix+read(size, retiring=retiring)

            def poll():
                check(retiring=True)
                if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
                try:
                    channel_identity(); value = child.poll(); channel_identity()
                finally: native_lock.release()
                check(retiring=True)
                return value

            check(); write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, observation.pid)):
                raise SourceNativeAssociationError('association_startup_failed')
            write(wire_call(wire.request, binding)); proof = wire_call(wire.accept_proof, frame()); check()
            if (type(proof) is not SourceRecipientAssociationEvidence or proof.canonical_binding != envelope
                    or _facts(proof) != (expected[:2]+((str, 'associated_ready'), (int, 0), (str, _WIRE_MEANING)))):
                raise SourceNativeAssociationError('association_proof_mismatch')
            # Local-only consume/discard with both original guarded native
            # channels live. No pipe wait or write occurs inside this section.
            with self._locked_source(original):
                check()
                if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
                try:
                    original.gate.reserve_and_discard(app, credential, proposal, descriptor)
                    consumed, model_state = True, 'outcome_unknown'
                    self._save('running', True, False, True, False)
                    check()
                finally: native_lock.release()
            write(wire_call(wire.retire)); check(); self._assert_io_unlocked(original)
            if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
            try: channel_identity(); child.close_input(); channel_identity()
            finally: native_lock.release()
            receipt_frame = frame(retiring=True)
            while True:
                check(retiring=True); self._assert_io_unlocked(original)
                try:
                    tail = os.read(child.stdout_fd, 1)
                    if type(tail) is not bytes or tail: raise SourceNativeAssociationError('trailing_association_output')
                    break
                except BlockingIOError: sleep(.002)
            while poll() is None: sleep(.002)
            check(retiring=True)
            if poll() != 0: raise SourceNativeAssociationError('association_peer_failed')
            ack = wire_call(wire.accept_ack, receipt_frame)
            if type(ack) is not SourceRecipientAssociationEvidence or _facts(ack) != expected[:2]+((str, 'associated_retired'), (int, 0), (str, _WIRE_MEANING)):
                raise SourceNativeAssociationError('association_receipt_mismatch')
            check(retiring=True)
            candidate = SourceNativeAssociationEvidence(envelope, hashlib.sha256(envelope).hexdigest())
            if type(candidate) is not SourceNativeAssociationEvidence or _facts(candidate) != expected:
                raise SourceNativeAssociationError('changed_association_result')
        except BaseException as error:
            failure = error
            if isinstance(error, BrokerProcessError) and str(error) == 'process_cleanup_failed': cleanup_ok = False
        finally:
            try:
                if child is not None:
                    self._assert_io_unlocked(original)
                    if child._ownership_lock is not native_lock or child._ownership is not native_api:
                        failure = SourceNativeAssociationError('changed_association_channel')
                    child._ownership_lock, child._ownership = native_lock, native_api
                    if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('association_cleanup_failed')
                    try:
                        child.close()
                        if child._ownership_lock is not native_lock or child._ownership is not native_api:
                            failure = SourceNativeAssociationError('changed_association_channel')
                            child._ownership_lock, child._ownership = native_lock, native_api
                        child._retired()
                    finally: native_lock.release()
            except BaseException: cleanup_ok = False
            try:
                if not dispose_wire(): raise SourceNativeAssociationError('association_cleanup_failed')
                if not self._dispose_peer(original): raise SourceNativeAssociationError('association_cleanup_failed')
            except BaseException: cleanup_ok = False
            try:
                if failure is None and candidate is not None:
                    self._source_current(model_state, consumed=True)
                    with self._locked_source(original):
                        self._identity(original)
                        if (type(candidate) is not SourceNativeAssociationEvidence or _facts(candidate) != expected
                                or type(proof) is not SourceRecipientAssociationEvidence
                                or _facts(proof) != expected[:2]+((str, 'associated_ready'), (int, 0), (str, _WIRE_MEANING))
                                or type(ack) is not SourceRecipientAssociationEvidence
                                or _facts(ack) != expected[:2]+((str, 'associated_retired'), (int, 0), (str, _WIRE_MEANING))
                                or self._child is not child or self._issued_child is not child
                                or child._ownership_lock is not native_lock or child._ownership is not native_api):
                            raise SourceNativeAssociationError('changed_association_result')
                        if not native_lock.acquire(blocking=False): raise SourceNativeAssociationError('busy_association_channel')
                        try: child._retired()
                        finally: native_lock.release()
                        self._source_current(model_state, consumed=True)
                        self._identity(original)
                        if (type(candidate) is not SourceNativeAssociationEvidence or _facts(candidate) != expected
                                or child._closed is not True or child._cleanup_failed is not False
                                or child._owned is not child_owned or child._issued_owned is not child_owned
                                or child._anchor_snapshot is not child_anchors or child._issued_anchors is not child_anchors
                                or child._seal_snapshot is not child_seals or child._issued_seals is not child_seals
                                or child._input_closed is not True or type(child._exit) is not int or child._exit != 0
                                or child._process is not None or child._job is not None
                                or type(child._fds) is not set or child._fds
                                or self._native_observation is not observation or child._issued_observation is not observation
                                or (type(observation.pid), observation.pid, type(observation.creation_time), observation.creation_time) != observation_snapshot
                                or o.buffer):
                            raise SourceNativeAssociationError('changed_association_retirement')
            except BaseException as error:
                if failure is None: failure = error
            if failure is not None or not cleanup_ok or candidate is None:
                original.cancel.set()
                cleanup_ok = self._dispose_source(original) and cleanup_ok
                candidate = None
            else:
                # Only local model/key/timer disposal; preserve original worker
                # ownership so it can subsequently reject the spent source.
                try:
                    with self._locked_source(original): original.gate.close()
                except BaseException: cleanup_ok = False; candidate = None
                if candidate is not None:
                    try:
                        with self._locked_source(original):
                            self._source_retired_current(original)
                            self._identity(original)
                            if (type(candidate) is not SourceNativeAssociationEvidence or _facts(candidate) != expected
                                    or type(proof) is not SourceRecipientAssociationEvidence
                                    or _facts(proof) != expected[:2]+((str, 'associated_ready'), (int, 0), (str, _WIRE_MEANING))
                                    or type(ack) is not SourceRecipientAssociationEvidence
                                    or _facts(ack) != expected[:2]+((str, 'associated_retired'), (int, 0), (str, _WIRE_MEANING))
                                    or self._child is not child or self._issued_child is not child
                                    or child._ownership_lock is not native_lock or child._ownership is not native_api
                                    or self._native_observation is not observation or child._issued_observation is not observation
                                    or (type(observation.pid), observation.pid, type(observation.creation_time), observation.creation_time) != observation_snapshot
                                    or child._closed is not True or child._cleanup_failed is not False
                                    or type(child._exit) is not int or child._exit != 0
                                    or o.buffer):
                                raise SourceNativeAssociationError('changed_association_result')
                            retired_channel_identity()
                            self._save('associated_discarded', True, True, True, True, result=candidate, snapshot=expected)
                            # A reentrant disposal/history hook can change the
                            # registry even while its RLock is held. Recheck
                            # after sealing; no provisional fact may escape.
                            self._source_retired_current(original)
                            history = self._identity(original)
                            retired_channel_identity()
                            if (history.state != 'associated_discarded' or history.started is not True
                                    or history.finished is not True or history.consumed is not True
                                    or history.cleanup is not True or history.result is not candidate
                                    or history.snapshot != expected or type(candidate) is not SourceNativeAssociationEvidence
                                    or _facts(candidate) != expected
                                    or type(proof) is not SourceRecipientAssociationEvidence
                                    or _facts(proof) != expected[:2]+((str, 'associated_ready'), (int, 0), (str, _WIRE_MEANING))
                                    or type(ack) is not SourceRecipientAssociationEvidence
                                    or _facts(ack) != expected[:2]+((str, 'associated_retired'), (int, 0), (str, _WIRE_MEANING))):
                                raise SourceNativeAssociationError('changed_association_result')
                            sealed = True  # Historical fact serialized with current authority.
                    except BaseException:
                        candidate = None
                        original.cancel.set()
                        cleanup_ok = self._dispose_source(original) and cleanup_ok
            if not sealed: cleanup_ok = dispose_wire() and cleanup_ok
            with original.lock:
                source_spent = consumed or o.source._publication_attempted is True
                if not sealed: self._save('failed', True, True, source_spent, cleanup_ok)
        if candidate is None or not cleanup_ok:
            raise SourceNativeAssociationError('association_cleanup_failed' if not cleanup_ok else 'association_rejected') from None
        with original.lock:
            history = self._structural_identity(original)
            if _facts(candidate) != history.snapshot: raise SourceNativeAssociationError('changed_association_result')
            return candidate
