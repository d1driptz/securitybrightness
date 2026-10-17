"""Inactive fixed generated-fixture acquisition stage; no application delivery.

Trusted bootstrap supplies one exact custody/source graph. This stage owns the
original guarded child, not an arbitrary reader or caller-selected file. Review
and authenticated transcripts remain evidence, never permission. The launcher,
fixed entry and containing trusted process remain trusted; MAC possession does
not attest code, and Python/transport copies do not have secure-erasure claims.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import os
import re
from threading import Event, RLock, current_thread
from time import monotonic, sleep
from uuid import UUID

from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_live_protocol import LiveMetadataExchange
from .broker_live_review import LiveBrokerReview
from .broker_observation import _observation, proposal_from_text
from .broker_pending_review import PendingDisplay
from .broker_process import _WinApi
from .broker_protocol import MAX_BODY_BYTES, _binding, _canonical
from .broker_publication_lifecycle import LivePublicationDraft
from .broker_publication_protocol import RetiredForCheckReceipt
from .broker_quarantine import QuarantineSummary
from .broker_recipient_process import _OwnershipApi, ProcessChannelObservation
from .broker_source_fixture_process import _SourceFixtureChild

_RLOCK = type(RLock())
_Origin = namedtuple('_Origin', 'stage custody custody_owner source thread ident deadline cancel lock '
    'key_digest session opening fields locks launch_seen native_seen display_seen wire_seen staged_seen retired_seen closed_seen uncertain failed')
_Native = namedtuple('_Native', 'child lock api process_api owned anchors seals observation values fds')
_Display = namedtuple('_Display', 'value snapshot observation observation_digest first_digest frame_digest')
_Wire = namedtuple('_Wire', 'wire lock buffer token binding recipient_snapshot')
_Staging = namedtuple('_Staging', 'value values')
_Retirement = namedtuple('_Retirement', 'value values acknowledgment native_exit')
_Status = namedtuple('_Status', 'state opened staged retired closed cleanup')


class SourceFixtureStageError(RuntimeError):
    pass


def _values(value):
    if type(value) is QuarantineSummary:
        names = ('binding_digest', 'staged_digest', 'staged_bytes', 'outcome')
    elif type(value) is RetiredForCheckReceipt:
        names = ('binding_digest', 'staged_digest', 'staged_bytes', 'outcome', 'released_bytes', 'meaning')
    else: raise SourceFixtureStageError('invalid_fixture_metadata_type')
    return tuple((type(getattr(value, name)), getattr(value, name)) for name in names)


def _display_snapshot(value):
    """Bound original flat display scalars before canonicalization, no deepcopy."""
    if type(value) is not PendingDisplay: raise SourceFixtureStageError('invalid_fixture_display_type')
    names = ('request_id', 'application_id', 'proposal_id', 'draft_id', 'draft_revision', 'grant_id',
        'registry_session', 'owner_session', 'resource_token', 'volume_serial', 'file_id', 'size_bytes',
        'max_bytes', 'display_path', 'proposal_json')
    numbers = {'draft_revision', 'volume_serial', 'size_bytes', 'max_bytes'}
    values = {name: getattr(value, name) for name in names}
    if any(type(item) is not (int if name in numbers else str) for name, item in values.items()):
        raise SourceFixtureStageError('invalid_fixture_display_scalar')
    _binding(dict(application_id=values['application_id'], proposal_id=values['proposal_id'],
        resource_token=values['resource_token'], decision_id=values['request_id'], max_bytes=values['max_bytes']))
    _observation({name: values[name] for name in ('owner_session', 'resource_token', 'volume_serial',
        'file_id', 'size_bytes', 'display_path')})
    if (re.fullmatch('[0-9a-f]{64}', values['registry_session']) is None
            or not 1 <= values['draft_revision'] <= 2**31-1):
        raise SourceFixtureStageError('invalid_fixture_display_identity')
    for name in ('draft_id', 'grant_id'):
        if len(values[name]) != 36 or str(UUID(values[name])) != values[name]:
            raise SourceFixtureStageError('invalid_fixture_display_identity')
    proposal_from_text(values['proposal_json'])
    return _canonical(values)


class _SourceFixtureStage:
    """One original worker, bounded private protocol, independently retired child.

    No I/O or native join is permitted while a source/custody guard is held.
    Native disposal runs once on the original worker. Constructor uncertainty,
    missing archives and cleanup uncertainty cannot certify admission release.
    """
    def __init__(self, custody):
        from .broker_source_admission import _SourceAdmissionCustody, _Source
        if type(self) is not _SourceFixtureStage or type(custody) is not _SourceAdmissionCustody:
            raise TypeError('expected exact private source custody')
        custody._identity(thread=True)
        source, owner = custody._source, custody._original()
        if type(source) is not _Source or custody._status().begun or not custody._status().bound:
            raise SourceFixtureStageError('invalid_fixture_bootstrap')
        opening = source.review._exchange
        if (type(opening) is not LiveMetadataExchange or type(opening._key) is not bytes
                or len(opening._key) != 32 or type(opening._session) is not str or len(opening._session) != 64
                or opening._role != 'coordinator' or opening._state != 'new'
                or type(opening._step) is not int or opening._step != 0 or opening._previous != '0'*64):
            raise SourceFixtureStageError('invalid_fixture_bootstrap')
        try:
            if bytes.fromhex(opening._session).hex() != opening._session: raise ValueError()
        except ValueError: raise SourceFixtureStageError('invalid_fixture_bootstrap') from None
        fields = source.fields+tuple((obj, name, getattr(obj, name)) for obj, names in (
            (source.source, ('coordinator', 'adapter')), (source.review, ('coordinator', 'operator')),
            (source.source.coordinator, ('_owner',)), (source.source.adapter, ('_owner',)),
            (source.review.coordinator, ('_owner',)), (source.review.operator, ('_owner',))) for name in names)
        origin = _Origin(self, custody, owner, source, owner.thread, owner.ident,
            min(owner.deadline, source.recipient_deadline), owner.cancel, RLock(),
            hashlib.sha256(opening._key).digest(), opening._session, opening, fields, source.locks,
            *(Event() for _ in range(9)))
        self._origin = self._issued_origin = self._recovery_origin = origin
        self._lock, self._cancel, self._deadline = origin.lock, origin.cancel, origin.deadline
        self._child = self._issued_child = self._recovery_child = None
        for name in ('native', 'display', 'wire', 'staging', 'retirement'):
            for prefix in ('_', '_issued_', '_recovery_'): setattr(self, prefix+name, None)
        self._save('new', False, False, False, False, False)
        custody._attach_fixture_stage(self)
        self._identity(active=False)

    @staticmethod
    def _recover(values, kind, *, optional=False):
        if optional and all(value is None for value in values): return None
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise SourceFixtureStageError('uncertain_fixture_archive')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _archive(self, name, kind):
        values = tuple(getattr(self, prefix+name, None) for prefix in ('_', '_issued_', '_recovery_'))
        value = self._recover(values, kind, optional=True)
        if any(item is not value for item in values): raise SourceFixtureStageError('changed_fixture_archive')
        return value

    def _native_original(self): return self._archive('native', _Native)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_history', '_issued_history', '_recovery_history')), _Status)

    def _save(self, state, opened, staged, retired, closed, cleanup):
        history = _Status(state, opened, staged, retired, closed, cleanup)
        self._history = self._issued_history = self._recovery_history = history
        self._state = state
        return history

    def _identity(self, *, active=False):
        origin, history = self._original(), self._status()
        native, display = self._native_original(), self._archive('display', _Display)
        wire, staging, retirement = self._archive('wire', _Wire), self._archive('staging', _Staging), self._archive('retirement', _Retirement)
        if (origin.stage is not self
                or any(getattr(self, name, None) is not origin for name in ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not history for name in ('_history', '_issued_history', '_recovery_history'))
                or self._lock is not origin.lock or self._cancel is not origin.cancel
                or type(self._deadline) is not float or self._deadline != origin.deadline
                or type(history.state) is not str or self._state != history.state
                or any(type(flag) is not bool for flag in history[1:])
                or origin.custody._original() is not origin.custody_owner
                or origin.custody_owner.custody is not origin.custody
                or any(getattr(origin.custody, prefix+'source', None) is not origin.source
                    for prefix in ('_', '_issued_', '_recovery_'))
                or any(getattr(origin.custody, name, None) is not self for name in
                    ('_fixture_stage', '_issued_fixture_stage', '_recovery_fixture_stage'))
                or any(getattr(obj, name, None) is not value for obj, name, value in origin.fields)
                or origin.opening is not origin.source.review._exchange
                or type(origin.opening._role) is not str or origin.opening._role != 'coordinator'
                or type(origin.opening._session) is not str or origin.opening._session != origin.session
                or type(origin.opening._key) is not bytes
                or (origin.source.review._state == 'closed' and (origin.opening._key != b''
                    or origin.opening._state != 'closed' or type(origin.opening._step) is not int or origin.opening._step != 4))
                or (origin.source.review._state != 'closed' and hashlib.sha256(origin.opening._key).digest() != origin.key_digest)
                or origin.native_seen.is_set() is not (native is not None)
                or origin.display_seen.is_set() is not (display is not None)
                or origin.wire_seen.is_set() is not (wire is not None)
                or origin.staged_seen.is_set() is not (staging is not None)
                or origin.retired_seen.is_set() is not (retirement is not None)
                or history.opened is not origin.display_seen.is_set()
                or history.staged is not origin.staged_seen.is_set()
                or history.retired is not origin.retired_seen.is_set()
                or history.closed is not origin.closed_seen.is_set()
                or origin.launch_seen.is_set() is not (self._child is not None)
                or self._child is not self._issued_child or self._child is not self._recovery_child
                or (self._child is not None and type(self._child) is not _SourceFixtureChild)
                or (native is not None and native.child is not self._child)):
            raise SourceFixtureStageError('changed_fixture_owner')
        if display is not None:
            review = origin.source.review
            if (type(display.value) is not PendingDisplay or review._shown is not display.value
                    or review._facts is not display.value or _display_snapshot(display.value) != display.snapshot
                    or review._facts_snapshot != display.snapshot or review._observation_snapshot != display.observation
                    or review._digest != display.observation_digest
                    or (review._state != 'closed' and (type(origin.opening._step) is not int
                        or origin.opening._step != 2 or origin.opening._previous != display.frame_digest))):
                raise SourceFixtureStageError('changed_fixture_display')
        if wire is not None and (origin.source.source._wire is not wire.wire
                or origin.source.source._owned_buffer is not wire.buffer or wire.wire._buffer is not wire.buffer
                or wire.wire._issued_buffer is not wire.buffer or wire.wire._lock is not wire.lock
                or type(wire.buffer) is not bytearray or origin.source.source._token is not wire.token
                or origin.source.source._issued_token is not wire.token
                or origin.source.source._publication_binding_snapshot != wire.binding
                or origin.source.source._recipient_snapshot != wire.recipient_snapshot):
            raise SourceFixtureStageError('changed_fixture_quarantine')
        if staging is not None and (type(staging.value) is not QuarantineSummary
                or origin.source.source._summary is not staging.value
                or origin.source.source._issued_summary is not staging.value or _values(staging.value) != staging.values):
            raise SourceFixtureStageError('changed_fixture_staging')
        if retirement is not None and (type(retirement.value) is not RetiredForCheckReceipt
                or origin.source.source._retirement is not retirement.value
                or origin.source.source._issued_retirement is not retirement.value
                or _values(retirement.value) != retirement.values or wire is None or native is None
                or type(wire.wire._step) is not int or wire.wire._step != 4
                or type(wire.wire._previous) is not str or wire.wire._previous != retirement.acknowledgment
                or type(retirement.native_exit) is not tuple or len(retirement.native_exit) != 2
                or type(retirement.native_exit[0]) is not int or type(retirement.native_exit[1]) is not bool
                or retirement.native_exit != (0, True) or type(native.child._exit) is not int
                or native.child._exit != 0 or native.child._input_closed is not True
                or type(native.child._retired_snapshot) is not tuple
                or native.child._retired_snapshot != retirement.native_exit):
            raise SourceFixtureStageError('changed_fixture_retirement')
        if active and (origin.cancel.is_set() or origin.failed.is_set() or origin.uncertain.is_set()
                or monotonic() >= origin.deadline):
            raise SourceFixtureStageError('expired_or_cancelled_fixture')
        return history

    def _worker(self):
        origin = self._original()
        if origin.stage is not self or current_thread() is not origin.thread or current_thread().ident != origin.ident:
            raise SourceFixtureStageError('wrong_fixture_worker')
        return origin

    @contextmanager
    def _control(self):
        origin = self._worker()
        if not origin.lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_control')
        try: yield origin
        finally: origin.lock.release()

    @contextmanager
    def _guards(self):
        origin = self._original()
        wire = self._archive('wire', _Wire)
        with ExitStack() as stack:
            for lock in origin.locks+(() if wire is None else (wire.lock,)):
                if type(lock) is not _RLOCK or not lock.acquire(blocking=False):
                    raise SourceFixtureStageError('busy_fixture_source')
                stack.callback(lock.release)
            yield

    def _io_unlocked(self, *, disposal=False):
        origin = self._original()
        if disposal:
            native = self._recover(tuple(getattr(self, prefix+'native', None) for prefix in
                ('_', '_issued_', '_recovery_')), _Native, optional=True)
            wire = self._recover(tuple(getattr(self, prefix+'wire', None) for prefix in
                ('_', '_issued_', '_recovery_')), _Wire, optional=True)
        else:
            native, wire = self._native_original(), self._archive('wire', _Wire)
        locks = origin.locks+(origin.custody_owner.lock, origin.lock)
        if native is not None: locks += (native.lock,)
        if wire is not None: locks += (wire.lock,)
        if any(type(lock) is not _RLOCK or lock._is_owned() for lock in locks):
            raise SourceFixtureStageError('authority_held_across_fixture_io')

    def _live(self):
        from .broker_source_admission import _SourceAdmissionCustody
        self._worker()
        with self._guards():
            self._identity(active=True)
            origin = self._original()
            _SourceAdmissionCustody._identity(origin.custody, thread=True)
            expected = {'opening': 'await_observation', 'observed': 'shown'}.get(self._state, 'acquisition_inflight')
            LiveBrokerReview._current(origin.source.review, expected)
            self._identity(active=True)

    def _native_fields(self, native, *, terminal=False):
        child, value = native.child, native.observation
        if (type(child) is not _SourceFixtureChild or child._ownership_lock is not native.lock
                or type(native.lock) is not _RLOCK or child._ownership is not native.api
                or type(native.api) is not _OwnershipApi or child._api is not native.process_api
                or type(native.process_api) is not _WinApi or child._owned is not native.owned
                or child._issued_owned is not native.owned or type(native.owned) is not tuple
                or len(native.owned) != 7 or any(type(item) is not int or item <= 0 for item in native.owned)
                or child._issued_anchors is not native.anchors or child._anchor_snapshot is not native.anchors
                or child._issued_seals is not native.seals or child._seal_snapshot is not native.seals
                or child._issued_observation is not value or child._original_observation is not value
                or type(value) is not ProcessChannelObservation or (type(value.pid), value.pid,
                    type(value.creation_time), value.creation_time) != native.values
                or child._observation_snapshot != (value.pid, value.creation_time) or child._initializing is not False
                or child._fds is not native.fds or type(native.fds) is not set
                or type(child.stdin_fd) is not int or child.stdin_fd != native.owned[0]
                or type(child.stdout_fd) is not int or child.stdout_fd != native.owned[1]
                or type(child.pid) is not int or child.pid != native.owned[6]
                or type(child._input_closed) is not bool):
            raise SourceFixtureStageError('changed_fixture_native_owner')
        if terminal:
            if (child._closed is not True or child._cleanup_failed is not False
                    or child._process is not None or child._job is not None or native.fds
                    or type(child._anchors) is not dict or child._anchors
                    or type(child._seals) is not dict or child._seals or type(child._exit) is not int
                    or type(child._retired_snapshot) is not tuple or len(child._retired_snapshot) != 2
                    or type(child._retired_snapshot[0]) is not int or type(child._retired_snapshot[1]) is not bool
                    or child._retired_snapshot != (child._exit, child._input_closed)):
                raise SourceFixtureStageError('unretired_fixture_native')
        elif child._closed is not False or child._cleanup_failed is not False:
            raise SourceFixtureStageError('unavailable_fixture_native')

    def _capture_native(self, child):
        lock = child._ownership_lock
        if type(lock) is not _RLOCK or not lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_native')
        try:
            value = child._issued_observation
            native = _Native(child, lock, child._ownership, child._api, child._issued_owned,
                child._anchor_snapshot, child._seal_snapshot, value,
                (type(value.pid), value.pid, type(value.creation_time), value.creation_time), child._fds)
            self._native = self._issued_native = self._recovery_native = native
            self._original().native_seen.set()
            self._native_fields(native)
            if _SourceFixtureChild._observe(child) is not value: raise SourceFixtureStageError('wrong_fixture_observation')
            self._native_fields(native)
            self._identity(active=False)
        finally: lock.release()

    def _native_current(self, *, retiring=False):
        self._io_unlocked(); self._live()
        native = self._native_original()
        if native is None or not native.lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_native')
        try:
            self._identity(active=True); self._native_fields(native)
            _SourceFixtureChild._validate(native.child, retiring=retiring)
            self._native_fields(native); self._identity(active=True)
        finally: native.lock.release()

    def _write(self, data):
        if type(data) is not bytes or not 1 <= len(data) <= MAX_BODY_BYTES+36:
            raise SourceFixtureStageError('invalid_fixture_input_bound')
        offset = 0
        while offset < len(data):
            self._native_current()
            try:
                count = os.write(self._native_original().owned[0], data[offset:])
                if type(count) is not int or not 0 < count <= len(data)-offset:
                    raise SourceFixtureStageError('fixture_input_failed')
                offset += count
            except BlockingIOError: sleep(.002)
            self._native_current()

    def _read(self, count, *, retiring=False):
        if type(count) is not int or not 0 < count <= MAX_BODY_BYTES+32:
            raise SourceFixtureStageError('invalid_fixture_output_bound')
        result = bytearray()
        while len(result) < count:
            self._native_current(retiring=retiring)
            try:
                value = os.read(self._native_original().owned[1], count-len(result))
                if type(value) is not bytes or not 0 < len(value) <= count-len(result):
                    raise SourceFixtureStageError('fixture_output_eof')
                result.extend(value)
            except BlockingIOError: sleep(.002)
            self._native_current(retiring=retiring)
        return bytes(result)

    def _frame(self, *, retiring=False):
        prefix = self._read(4, retiring=retiring)
        count = int.from_bytes(prefix, 'big')
        if not 32 <= count <= MAX_BODY_BYTES+32: raise SourceFixtureStageError('invalid_fixture_frame_bound')
        return prefix+self._read(count, retiring=retiring)

    def _reject(self, reason):
        origin = self._original()
        origin.failed.set(); origin.cancel.set()
        try:
            wire = self._archive('wire', _Wire)
            if wire is not None: wire.buffer[:] = b'\0'*len(wire.buffer); wire.buffer.clear()
        except BaseException: origin.uncertain.set()
        try: self.close()
        except BaseException: origin.uncertain.set()
        raise SourceFixtureStageError(reason) from None

    def open(self, first):
        origin = self._worker()
        try:
            with self._control(), self._guards():
                history = self._identity(active=True)
                if history.state != 'new' or origin.launch_seen.is_set(): raise SourceFixtureStageError('fixture_attempt_spent')
                if (type(first) is not bytes or not 36 <= len(first) <= MAX_BODY_BYTES+36
                        or type(origin.opening._step) is not int or origin.opening._step != 1
                        or hashlib.sha256(first).hexdigest() != origin.opening._previous):
                    raise SourceFixtureStageError('wrong_fixture_first_frame')
                origin.launch_seen.set()
                child = object.__new__(_SourceFixtureChild)
                self._child = self._issued_child = self._recovery_child = child
                self._save('opening', False, False, False, False, False)
            self._io_unlocked()
            try: _SourceFixtureChild.__init__(child)
            except BaseException:
                origin.uncertain.set()
                raise
            self._capture_native(child)  # Capture disposal ownership before active cancellation rejection.
            self._native_current()
            self._write(MAGIC+origin.opening._key+bytes.fromhex(origin.session))
            actual = self._read(READY_SIZE)
            if not hmac.compare_digest(actual, ready(origin.opening._key, bytes.fromhex(origin.session),
                    self._native_original().observation.pid)):
                raise SourceFixtureStageError('fixture_startup_rejected')
            self._write(first); frame = self._frame()
            with self._control(), self._guards():
                self._identity(active=True)
                origin.source.review.coordinator.observe(frame)
                value = origin.source.review.operator.display()
                if (type(value) is not PendingDisplay or origin.opening._step != 2
                        or origin.opening._previous != hashlib.sha256(frame).hexdigest()):
                    raise SourceFixtureStageError('wrong_fixture_observation_frame')
                display = _Display(value, _display_snapshot(value), origin.source.review._observation_snapshot,
                    origin.source.review._digest, hashlib.sha256(first).hexdigest(), hashlib.sha256(frame).hexdigest())
                self._display = self._issued_display = self._recovery_display = display
                origin.display_seen.set(); self._save('observed', True, False, False, False, False)
                self._identity(active=True)
                return value
        except BaseException: self._reject('fixture_open_rejected')

    def stage(self, app, credential, proposal):
        origin = self._worker()
        try:
            with self._control(), self._guards():
                history = self._identity(active=True)
                if history.state != 'observed' or history.closed: raise SourceFixtureStageError('fixture_stage_spent')
                self._save('acquiring', True, False, False, False, False)
                token = origin.source.source.coordinator.reserve()
                frame = origin.custody.begin_acquisition(token, app, credential, proposal)
                source = origin.source.source
                wire = _Wire(source._wire, source._wire._lock, source._owned_buffer, token,
                    source._publication_binding_snapshot, source._recipient_snapshot)
                self._wire = self._issued_wire = self._recovery_wire = wire
                origin.wire_seen.set(); self._identity(active=True)
            self._write(frame); reply = self._frame()
            with self._control(), self._guards():
                self._identity(active=True)
                summary = origin.source.source.adapter.stage(reply)
                if type(summary) is not QuarantineSummary: raise SourceFixtureStageError('wrong_fixture_summary')
                self._staging = self._issued_staging = self._recovery_staging = _Staging(summary, _values(summary))
                origin.staged_seen.set(); self._save('staged', True, True, False, False, False)
                self._identity(active=True)
                return summary
        except BaseException: self._reject('fixture_stage_rejected')

    def retire(self):
        origin = self._worker()
        try:
            with self._control(), self._guards():
                history = self._identity(active=True)
                if history.state != 'staged' or history.closed: raise SourceFixtureStageError('fixture_retirement_spent')
                frame = origin.source.source.adapter.retire()
                self._save('retiring', True, True, False, False, False)
            self._write(frame)
            self._native_current()
            native = self._native_original()
            if not native.lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_native')
            try: _SourceFixtureChild.close_input(native.child)
            finally: native.lock.release()
            acknowledgment = self._frame(retiring=True)
            while True:
                self._native_current(retiring=True)
                try:
                    trailing = os.read(native.owned[1], 1)
                    if trailing: raise SourceFixtureStageError('trailing_fixture_output')
                    break
                except BlockingIOError: sleep(.002)
            while True:
                self._native_current(retiring=True)
                if not native.lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_native')
                try: code = _SourceFixtureChild.poll(native.child)
                finally: native.lock.release()
                self._identity(active=True)
                if code is not None:
                    if type(code) is not int or code != 0: raise SourceFixtureStageError('fixture_failed_exit')
                    break
                sleep(.002)
            self.close(); self.verify_cleanup()
            with self._control(), self._guards():
                self._identity(active=True)
                receipt = origin.source.source.adapter.confirm_retirement(acknowledgment)
                if type(receipt) is not RetiredForCheckReceipt: raise SourceFixtureStageError('wrong_fixture_receipt')
                digest, wire = hashlib.sha256(acknowledgment).hexdigest(), self._archive('wire', _Wire)
                if (wire is None or type(wire.wire._step) is not int or wire.wire._step != 4
                        or type(wire.wire._previous) is not str or wire.wire._previous != digest):
                    raise SourceFixtureStageError('wrong_fixture_retirement_transcript')
                retirement = _Retirement(receipt, _values(receipt), digest,
                    native.child._retired_snapshot)
                self._retirement = self._issued_retirement = self._recovery_retirement = retirement
                origin.retired_seen.set(); self._save('retired', True, True, True, True, True)
                self._identity(active=True)
            self.verify_handoff()
            return receipt
        except BaseException: self._reject('fixture_retirement_rejected')

    def verify_cleanup(self):
        history, origin = self._identity(active=False), self._original()
        if not history.closed or not history.cleanup or origin.uncertain.is_set():
            raise SourceFixtureStageError('uncertain_fixture_cleanup')
        native = self._native_original()
        if native is None:
            if origin.launch_seen.is_set(): raise SourceFixtureStageError('missing_fixture_cleanup_owner')
            return
        if not native.lock.acquire(blocking=False): raise SourceFixtureStageError('busy_fixture_cleanup')
        try:
            self._native_fields(native, terminal=True)
            _SourceFixtureChild._retired(native.child)
            self._native_fields(native, terminal=True); self._identity(active=False)
            retirement = self._archive('retirement', _Retirement)
            if retirement is not None and (type(retirement.native_exit) is not tuple
                    or len(retirement.native_exit) != 2 or type(retirement.native_exit[0]) is not int
                    or type(retirement.native_exit[1]) is not bool or retirement.native_exit != (0, True)
                    or native.child._retired_snapshot != retirement.native_exit
                    or native.child._exit != 0 or native.child._input_closed is not True):
                raise SourceFixtureStageError('changed_successful_fixture_retirement')
        finally: native.lock.release()

    def verify_handoff(self):
        self.verify_cleanup()
        history, origin = self._identity(active=False), self._original()
        native, retirement = self._native_original(), self._archive('retirement', _Retirement)
        wire, staging, display = self._archive('wire', _Wire), self._archive('staging', _Staging), self._archive('display', _Display)
        if (not history.retired or retirement is None or native is None or wire is None or staging is None or display is None
                or origin.failed.is_set() or native.child._input_closed is not True or native.child._exit != 0
                or retirement.native_exit != (0, True) or origin.source.source._state != 'cleaned'
                or origin.source.source._retirement_snapshot != retirement.values
                or retirement.value.released_bytes != 0
                or retirement.value.staged_bytes != min(display.value.size_bytes, display.value.max_bytes)
                or staging.value.staged_bytes != min(display.value.size_bytes, display.value.max_bytes)
                or hashlib.sha256(wire.buffer).hexdigest() != staging.value.staged_digest
                or len(wire.buffer) != staging.value.staged_bytes
                or hashlib.sha256(wire.binding).hexdigest() != staging.value.binding_digest
                or retirement.value.binding_digest != staging.value.binding_digest
                or retirement.value.staged_digest != staging.value.staged_digest):
            raise SourceFixtureStageError('invalid_fixture_handoff')
        self._identity(active=False)

    def close(self):
        origin = self._worker()
        self._io_unlocked(disposal=True)
        native = self._recover(tuple(getattr(self, prefix+'native', None) for prefix in
            ('_', '_issued_', '_recovery_')), _Native, optional=True)
        with self._control():
            history = self._status()
            if history.closed:
                self.verify_cleanup()
                return
            try: self._identity(active=False)
            except BaseException: origin.uncertain.set()
            origin.closed_seen.set()
            self._save('closed', history.opened, history.staged, history.retired, True, False)
        if native is None:
            if origin.launch_seen.is_set():
                origin.uncertain.set()
                child = self._recover((self._child, self._issued_child, self._recovery_child), _SourceFixtureChild)
                lock = getattr(child, '_ownership_lock', None)
                if (type(lock) is _RLOCK and type(getattr(child, '_ownership', None)) is _OwnershipApi
                        and type(getattr(child, '_api', None)) is _WinApi
                        and lock.acquire(blocking=False)):
                    try: _SourceFixtureChild.close(child)
                    finally: lock.release()
                raise SourceFixtureStageError('uncertain_fixture_constructor')
        else:
            if not native.lock.acquire(blocking=False):
                origin.uncertain.set(); raise SourceFixtureStageError('busy_fixture_cleanup')
            try:
                try: self._native_fields(native)
                except BaseException: origin.uncertain.set()
                child = native.child
                # The guarded child's fixed close recovers original handles
                # when public PID/fd/process fields were changed. Never select
                # a substituted API, lock or private ownership anchor to do so.
                if (type(child) is not _SourceFixtureChild or child._ownership_lock is not native.lock
                        or child._ownership is not native.api or type(native.api) is not _OwnershipApi
                        or child._issued_owned is not native.owned
                        or child._anchor_snapshot is not native.anchors
                        or child._seal_snapshot is not native.seals):
                    raise SourceFixtureStageError('uncertain_fixture_disposal_owner')
                if child._initializing is not False:
                    origin.uncertain.set()
                    # A full original native archive proves construction had
                    # completed. Restore only that known disposal prerequisite;
                    # uncertainty remains irreversible and grants no authority.
                    child._initializing = False
                _SourceFixtureChild.close(native.child)
                self._native_fields(native, terminal=True)
                _SourceFixtureChild._retired(native.child)
                self._native_fields(native, terminal=True)
            except BaseException:
                origin.uncertain.set(); raise SourceFixtureStageError('fixture_cleanup_failed') from None
            finally: native.lock.release()
        with self._control():
            self._save('closed', history.opened, history.staged, history.retired, True, not origin.uncertain.is_set())
            self._identity(active=False)
        self.verify_cleanup()
