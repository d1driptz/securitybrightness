"""Inactive one-attempt private transport to a fixed synthetic discard child.

This accepts bounded test bytes, never an acquisition/review/authority object.
It is not wired to any protected reader or application. The original worker
alone closes/joins its native child. Cancellation signals; it does not join.
After the payload-write barrier every failure is outcome_unknown, never a
claim that no bytes reached the child, and this instance cannot be retried.
"""
from collections import namedtuple
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import os
import secrets
from threading import Event, RLock
from time import monotonic, sleep

from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_protocol import MAX_BODY_BYTES, MAX_DATA_BYTES, _canonical
from .broker_process import BrokerProcessError
from .broker_recipient_process import ProcessChannelObservation, _OwnershipApi
from .broker_synthetic_payload_peer import _SyntheticPayloadPeer
from .broker_synthetic_payload_protocol import SyntheticPayloadExchange, SyntheticPayloadEvidence, _MEANING as _CODEC_MEANING
from .json_input import loads

_MEANING = 'Fixed synthetic peer discard only; not authority or protected delivery.'
_Origin = namedtuple('_Origin', 'lock event buffer deadline count digest')
_History = namedtuple('_History', 'state visible written cleanup')


class SyntheticPayloadTransportError(RuntimeError):
    """Fixed diagnostic, with no test bytes, credentials or requester labels."""


@dataclass(frozen=True)
class NativeSyntheticPayloadEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    byte_count: int
    digest: str
    outcome: str = field(default='peer_discarded', init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('Synthetic transport is not permission')


class SyntheticPayloadTransport:
    """Trusted bootstrap only; no endpoint, executable or resource selector.

    Three immutable aliases corroborate original cleanup references after one
    damaged alias. They do not defend against hostile code rewriting the trusted
    runtime. Python copies and pipe/kernel buffers are not secure memory erasure.
    A new instance is a new synthetic test, not global delivery/replay authority.
    """
    def __init__(self, payload, *, timeout=5):
        if type(payload) is not bytes or len(payload) > MAX_DATA_BYTES:
            raise SyntheticPayloadTransportError('invalid_synthetic_payload')
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 5):
            raise SyntheticPayloadTransportError('invalid_synthetic_timeout')
        origin = _Origin(RLock(), Event(), bytearray(payload), monotonic()+timeout,
                         len(payload), hashlib.sha256(payload).hexdigest())
        self._origin = self._issued_origin = self._recovery_origin = origin
        self._history = self._issued_history = self._recovery_history = _History('not_started', False, 0, False)
        self._child = self._issued_child = self._native_observation = None
        self._result = self._issued_result = self._result_snapshot = None

    @staticmethod
    def _recover(values, expected):
        for value in values:
            if type(value) is expected and sum(other is value for other in values) >= 2:
                return value
        raise SyntheticPayloadTransportError('synthetic_owner_unrecoverable')

    def _owners(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _History)

    def _identity(self, original, history):
        if (any(getattr(self, name, None) is not original for name in
                ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in
                ('_history', '_issued_history', '_recovery_history'))):
            raise SyntheticPayloadTransportError('changed_synthetic_owner')

    def _record(self, *, state=None, visible=None, written=None, cleanup=None):
        value = self._status()
        value = _History(value.state if state is None else state,
                         value.visible if visible is None else visible,
                         value.written if written is None else written,
                         value.cleanup if cleanup is None else cleanup)
        self._history = self._issued_history = self._recovery_history = value
        return value

    @staticmethod
    def _wipe(original):
        if type(original.buffer) is not bytearray:
            raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
        original.buffer[:] = b'\0'*len(original.buffer)
        original.buffer.clear()
        if original.buffer: raise SyntheticPayloadTransportError('synthetic_cleanup_failed')

    def cancel(self):
        original = self._owners()
        with original.lock:
            status = self._status()
            # A completed fact is historical, never a capability. Cancellation
            # is serialized with the final publication of that fact.
            if status.state == 'peer_discarded':
                self._identity(original, status)
                self._result_current()
                return
            original.event.set()
            if status.state == 'not_started':
                self._dispose_unstarted(original, 'cancelled_before_payload')

    close = cancel

    def _dispose_unstarted(self, original, state):
        cleaned = False
        try:
            self._wipe(original)
            cleaned = type(original.buffer) is bytearray and not original.buffer
        except BaseException: cleaned = False
        finally: self._record(state=state, cleanup=cleaned)
        if not cleaned: raise SyntheticPayloadTransportError('synthetic_cleanup_failed')

    def inspect(self):
        original = self._owners()
        with original.lock:
            value = self._status()
            self._identity(original, value)
            if value.state == 'peer_discarded': self._result_current()
            return dict(state=value.state, payload_may_have_been_visible=value.visible,
                        payload_frame_bytes_written=value.written, cleanup_confirmed=value.cleanup)

    def _result_current(self):
        value = self._result
        if (type(value) is not NativeSyntheticPayloadEvidence or value is not self._issued_result
                or tuple((type(x), x) for x in (value.canonical_binding, value.binding_digest,
                    value.byte_count, value.digest, value.outcome, value.meaning)) != self._result_snapshot):
            raise SyntheticPayloadTransportError('changed_synthetic_result')

    def run(self):
        original = self._owners()
        with original.lock:
            status = self._status()
            try:
                self._identity(original, status)
                if status.state != 'not_started':
                    # No second worker; duplicate admission cancels an active
                    # attempt instead of obtaining another payload or result.
                    if status.state == 'running': original.event.set()
                    raise SyntheticPayloadTransportError('synthetic_attempt_spent')
                status = self._record(state='running')
            except BaseException:
                if status.state == 'not_started':
                    original.event.set(); self._dispose_unstarted(original, 'failed_before_payload')
                raise

        child = wire = wire_lock = None
        child_lock = child_api = observation = None
        child_owned = child_anchors = child_seals = None
        observation_snapshot = None
        candidate = expected_result = receipt = None
        cleanup_ok, failure = True, None
        # Captured locals are used for every I/O and disposal; mutable fields are
        # checked only for identity and never selected as cleanup targets.
        try:
            def current(*, retiring=False):
                with original.lock:
                    value = self._status(); self._identity(original, value)
                    if (value.state != 'running' or original.event.is_set()
                            or monotonic() >= original.deadline
                            or type(original.buffer) is not bytearray
                            or len(original.buffer) != original.count
                            or hashlib.sha256(original.buffer).hexdigest() != original.digest):
                        raise SyntheticPayloadTransportError('stale_synthetic_attempt')
                    if wire is not None and (type(wire) is not SyntheticPayloadExchange or wire._lock is not wire_lock):
                        raise SyntheticPayloadTransportError('changed_synthetic_codec')
                    if child is not None:
                        if (type(child) is not _SyntheticPayloadPeer or self._child is not child
                                or self._issued_child is not child or child._ownership_lock is not child_lock
                                or child._ownership is not child_api or type(child_api) is not _OwnershipApi
                                or type(observation) is not ProcessChannelObservation
                                or self._native_observation is not observation
                                or child._issued_observation is not observation
                                or (type(observation.pid), observation.pid, type(observation.creation_time),
                                    observation.creation_time) != observation_snapshot):
                            raise SyntheticPayloadTransportError('changed_synthetic_channel')
                        if not child_lock.acquire(blocking=False):
                            raise SyntheticPayloadTransportError('busy_synthetic_channel')
                        try: child._validate(retiring=retiring)
                        finally: child_lock.release()
                        # Original native calls are a trust boundary. Repeat
                        # local freshness after them, before progressing.
                        self._identity(original, value)
                        if (original.event.is_set() or monotonic() >= original.deadline
                                or child._ownership_lock is not child_lock or child._ownership is not child_api
                                or self._child is not child or self._issued_child is not child
                                or self._native_observation is not observation
                                or child._issued_observation is not observation
                                or (type(observation.pid), observation.pid, type(observation.creation_time),
                                    observation.creation_time) != observation_snapshot
                                or len(original.buffer) != original.count
                                or hashlib.sha256(original.buffer).hexdigest() != original.digest):
                            raise SyntheticPayloadTransportError('changed_synthetic_attempt')

            def write(data, *, payload=False):
                offset = 0
                while offset < len(data):
                    current()
                    if payload and offset == 0:
                        with original.lock:
                            value = self._status(); self._identity(original, value)
                            if original.event.is_set() or monotonic() >= original.deadline:
                                raise SyntheticPayloadTransportError('stale_synthetic_attempt')
                            # Irreversible before attempting the first OS write,
                            # including a blocked/zero/failed first write.
                            self._record(visible=True)
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if type(count) is not int or not 0 < count <= len(data)-offset:
                            raise SyntheticPayloadTransportError('synthetic_pipe_failed')
                        offset += count
                        if payload:
                            with original.lock:
                                value = self._status(); self._identity(original, value)
                                self._record(written=value.written+count)
                    except BlockingIOError: sleep(.002)
                    current()

            def read(size, *, retiring=False):
                output = bytearray()
                while len(output) < size:
                    current(retiring=retiring)
                    try:
                        chunk = os.read(child.stdout_fd, size-len(output))
                        if type(chunk) is not bytes or not chunk or len(chunk) > size-len(output):
                            raise SyntheticPayloadTransportError('truncated_synthetic_output')
                        output.extend(chunk)
                    except BlockingIOError: sleep(.002)
                    current(retiring=retiring)
                return bytes(output)

            def frame(*, retiring=False):
                prefix = read(4, retiring=retiring); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32:
                    raise SyntheticPayloadTransportError('synthetic_output_limit')
                return prefix+read(size, retiring=retiring)

            current()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            wire = SyntheticPayloadExchange(role='coordinator', key=key, session=session)
            wire_lock = wire._lock
            child = self._child = self._issued_child = _SyntheticPayloadPeer()
            child_lock, child_api = child._ownership_lock, child._ownership
            child_owned, child_anchors, child_seals = child._issued_owned, child._anchor_snapshot, child._seal_snapshot
            observation = self._native_observation = child._observe()
            observation_snapshot = (type(observation.pid), observation.pid,
                                    type(observation.creation_time), observation.creation_time)
            current()
            envelope = dict(revision=1, mode='synthetic_transport_discard_only',
                transport_id=secrets.token_hex(32), fixture_id=secrets.token_hex(32),
                byte_count=original.count, digest=original.digest,
                channel=dict(pid=observation.pid, creation_time=observation.creation_time,
                             witness_session=session.hex()))
            expected = _canonical(envelope)
            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, observation.pid)):
                raise SyntheticPayloadTransportError('synthetic_startup_failed')
            write(wire.prepare(envelope)); wire.accept_ready(frame()); current()
            payload_frame = wire.payload(bytes(original.buffer)); current()
            write(payload_frame, payload=True)
            current(); child.close_input()
            receipt_frame = frame(retiring=True)
            # A valid receipt alone is insufficient: no trailing output, zero
            # original process exit and joined original cleanup are required.
            while True:
                current(retiring=True)
                try:
                    tail = os.read(child.stdout_fd, 1)
                    if type(tail) is not bytes or tail:
                        raise SyntheticPayloadTransportError('trailing_synthetic_output')
                    break
                except BlockingIOError: sleep(.002)
            while child.poll() is None: current(retiring=True); sleep(.002)
            current(retiring=True)
            if child.poll() != 0: raise SyntheticPayloadTransportError('synthetic_peer_failed')
            receipt = wire.accept_receipt(receipt_frame)
            if (type(receipt) is not SyntheticPayloadEvidence or receipt.canonical_binding != expected
                    or type(receipt.canonical_binding) is not bytes
                    or type(receipt.binding_digest) is not str
                    or receipt.binding_digest != hashlib.sha256(expected).hexdigest()
                    or type(receipt.outcome) is not str or receipt.outcome != 'peer_discarded'
                    or type(receipt.byte_count) is not int or receipt.byte_count != original.count
                    or type(receipt.digest) is not str or receipt.digest != original.digest
                    or type(receipt.meaning) is not str or receipt.meaning != _CODEC_MEANING):
                raise SyntheticPayloadTransportError('synthetic_receipt_mismatch')
            current(retiring=True)
            candidate = NativeSyntheticPayloadEvidence(expected, hashlib.sha256(expected).hexdigest(),
                                                       original.count, original.digest)
            expected_result = ((bytes, expected), (str, hashlib.sha256(expected).hexdigest()), (int, original.count),
                               (str, original.digest), (str, 'peer_discarded'), (str, _MEANING))
            if (type(candidate) is not NativeSyntheticPayloadEvidence
                    or tuple((type(x), x) for x in (candidate.canonical_binding, candidate.binding_digest,
                        candidate.byte_count, candidate.digest, candidate.outcome, candidate.meaning)) !=
                    expected_result):
                raise SyntheticPayloadTransportError('changed_synthetic_result')
        except BaseException as error:
            failure = error
            if isinstance(error, BrokerProcessError) and str(error) == 'process_cleanup_failed':
                cleanup_ok = False
        finally:
            # Native close can itself expose mutation/uncertain cleanup. Never
            # upgrade a buffered candidate to a result until this succeeds.
            try:
                if child is not None:
                    if child._ownership_lock is not child_lock or child._ownership is not child_api:
                        failure = SyntheticPayloadTransportError('changed_synthetic_channel')
                    child._ownership_lock, child._ownership = child_lock, child_api
                    if not child_lock.acquire(blocking=False):
                        raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
                    try:
                        child.close(); child._retired()
                        if candidate is not None and (type(child._exit) is not int or child._exit != 0):
                            raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
                    finally: child_lock.release()
            except BaseException: cleanup_ok = False
            try:
                if wire is not None:
                    if wire._lock is not wire_lock:
                        failure = SyntheticPayloadTransportError('changed_synthetic_codec')
                    wire._lock = wire_lock  # Original disposal only, never retry.
                    wire.close()
                    if type(wire._key) is not bytes or wire._key != b'' or wire._state != 'closed':
                        raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
            except BaseException: cleanup_ok = False
            with original.lock:
                try:
                    value = self._status(); self._identity(original, value)
                    if (original.event.is_set() or monotonic() >= original.deadline
                            or len(original.buffer) != original.count
                            or hashlib.sha256(original.buffer).hexdigest() != original.digest):
                        raise SyntheticPayloadTransportError('stale_synthetic_attempt')
                    if child is not None and (self._child is not child or self._issued_child is not child
                            or self._native_observation is not observation
                            or child._issued_observation is not observation
                            or (type(observation.pid), observation.pid, type(observation.creation_time),
                                observation.creation_time) != observation_snapshot):
                        raise SyntheticPayloadTransportError('changed_synthetic_channel')
                    if candidate is not None and (type(candidate) is not NativeSyntheticPayloadEvidence
                            or tuple((type(x), x) for x in (candidate.canonical_binding,
                                candidate.binding_digest, candidate.byte_count, candidate.digest,
                                candidate.outcome, candidate.meaning)) != expected_result):
                        raise SyntheticPayloadTransportError('changed_synthetic_result')
                    if receipt is not None and (type(receipt) is not SyntheticPayloadEvidence
                            or tuple((type(x), x) for x in (receipt.canonical_binding,
                                receipt.binding_digest, receipt.byte_count, receipt.digest,
                                receipt.outcome, receipt.meaning)) != expected_result[:-1]+((str, _CODEC_MEANING),)):
                        raise SyntheticPayloadTransportError('changed_synthetic_receipt')
                except BaseException as error:
                    if failure is None: failure = error
                try:
                    self._wipe(original)
                    if type(original.buffer) is not bytearray or original.buffer:
                        raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
                except BaseException: cleanup_ok = False
                try:
                    # Wiping and codec/native disposal are callback fault
                    # boundaries too. Do not snapshot a changed candidate.
                    self._identity(original, self._status())
                    if original.event.is_set() or monotonic() >= original.deadline:
                        raise SyntheticPayloadTransportError('stale_synthetic_attempt')
                    if candidate is not None:
                        if (type(candidate) is not NativeSyntheticPayloadEvidence
                                or tuple((type(x), x) for x in (candidate.canonical_binding,
                                    candidate.binding_digest, candidate.byte_count, candidate.digest,
                                    candidate.outcome, candidate.meaning)) != expected_result
                                or type(receipt) is not SyntheticPayloadEvidence
                                or tuple((type(x), x) for x in (receipt.canonical_binding,
                                    receipt.binding_digest, receipt.byte_count, receipt.digest,
                                    receipt.outcome, receipt.meaning)) != expected_result[:-1]+((str, _CODEC_MEANING),)
                                or self._child is not child or self._issued_child is not child
                                or self._native_observation is not observation
                                or child._ownership_lock is not child_lock or child._ownership is not child_api):
                            raise SyntheticPayloadTransportError('changed_synthetic_result')
                        if not child_lock.acquire(blocking=False):
                            raise SyntheticPayloadTransportError('busy_synthetic_channel')
                        try: child._retired()
                        finally: child_lock.release()
                        if type(child._exit) is not int or child._exit != 0:
                            raise SyntheticPayloadTransportError('synthetic_cleanup_failed')
                    # This is the final pure fence, after ALL disposal/native
                    # callbacks. A late cancellation/mutation must not be
                    # overwritten by a newly sealed success history.
                    self._identity(original, self._status())
                    if (original.event.is_set() or monotonic() >= original.deadline
                            or type(original.buffer) is not bytearray or original.buffer):
                        raise SyntheticPayloadTransportError('stale_synthetic_attempt')
                    if candidate is not None and (type(candidate) is not NativeSyntheticPayloadEvidence
                            or tuple((type(x), x) for x in (candidate.canonical_binding,
                                candidate.binding_digest, candidate.byte_count, candidate.digest,
                                candidate.outcome, candidate.meaning)) != expected_result
                            or type(receipt) is not SyntheticPayloadEvidence
                            or tuple((type(x), x) for x in (receipt.canonical_binding,
                                receipt.binding_digest, receipt.byte_count, receipt.digest,
                                receipt.outcome, receipt.meaning)) != expected_result[:-1]+((str, _CODEC_MEANING),)
                            or self._child is not child or self._issued_child is not child
                            or self._native_observation is not observation
                            or child._issued_observation is not observation
                            or (type(observation.pid), observation.pid, type(observation.creation_time),
                                observation.creation_time) != observation_snapshot
                            or child._ownership_lock is not child_lock or child._ownership is not child_api
                            or child._closed is not True or child._cleanup_failed is not False
                            or child._owned is not child_owned or child._issued_owned is not child_owned
                            or child._issued_anchors is not child_anchors or child._anchor_snapshot is not child_anchors
                            or child._issued_seals is not child_seals or child._seal_snapshot is not child_seals
                            or child._input_closed is not True
                            or type(child.stdin_fd) is not int or child.stdin_fd != child_owned[0]
                            or type(child.stdout_fd) is not int or child.stdout_fd != child_owned[1]
                            or type(child.pid) is not int or child.pid != observation_snapshot[1]
                            or type(child._retired_snapshot) is not tuple or len(child._retired_snapshot) != 2
                            or type(child._retired_snapshot[0]) is not int
                            or type(child._retired_snapshot[1]) is not bool
                            or child._retired_snapshot != (0, True)
                            or child._process is not None or child._job is not None
                            or type(child._fds) is not set or child._fds
                            or type(child._anchors) is not dict or child._anchors
                            or type(child._seals) is not dict or child._seals
                            or type(child._exit) is not int or child._exit != 0):
                        raise SyntheticPayloadTransportError('changed_synthetic_result')
                except BaseException as error:
                    if failure is None: failure = error
                value = self._status()
                if failure is None and cleanup_ok and candidate is not None:
                    self._result = self._issued_result = candidate
                    self._result_snapshot = expected_result
                    self._record(state='peer_discarded', cleanup=True)
                else:
                    state = ('outcome_unknown' if value.visible else
                             'cancelled_before_payload' if original.event.is_set() else 'failed_before_payload')
                    self._record(state=state, cleanup=cleanup_ok)
                    candidate = None
        if not cleanup_ok: raise SyntheticPayloadTransportError('synthetic_cleanup_failed') from None
        if candidate is None: raise SyntheticPayloadTransportError('synthetic_transport_failed') from None
        with original.lock:
            self._identity(original, self._status()); self._result_current()
            return candidate
