"""Inactive fixed fixture wait/acquisition actor; no authority or delivery API.

The retained Windows object is created by this trusted adapter, never selected
by a requester pathname. A distinct opening can wait at most thirty seconds;
one separately timed acquisition/retirement has at most five seconds within the
original thirty-five-second total. The coordinator still owes fresh independent
human review, registry/lifecycle checks and exact downstream-operation binding.
Possession of this private codec key is never permission.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import math
import re
from threading import Event, RLock, Timer, current_thread, get_ident
from time import monotonic

from .broker_native_acquisition import _NativeReadFixture, NativeAcquisitionError
from .broker_observation import proposal_from_text
from .broker_protocol import _canonical, FixtureBrokerExchange
from .broker_live_protocol import LiveMetadataExchange
from .broker_publication_protocol import _publication_binding
from .broker_wait_phase import _WaitAcquisitionPhases
from .broker_wait_protocol import _WaitOpeningExchange, _WaitAcquisitionExchange
from .file_read_schema import inspect_file_read_proposal
from .json_input import loads
from .structured_proposal import StructuredActionProposal
from .windows_identity import _Native


_RLOCK, _EVENT = type(RLock()), type(Event())


def _quorum(instance, names, kind):
    values = [getattr(instance, name, None) for name in names]
    for value in values:
        if type(value) is kind and sum(other is value for other in values) >= 2:
            return value
    raise NativeAcquisitionError('original_ownership_unavailable')


@dataclass(frozen=True)
class _OwnerOrigin:
    owner: object
    thread: object
    ident: int
    deadline: float
    allocated: object
    closed: object
    attempted: object
    failed: object


@dataclass(frozen=True)
class _Resource:
    native: object
    kernel: object
    nt: object
    fd: int
    handle: int
    metadata: tuple
    description: object
    description_snapshot: bytes


class _WaitNativeReadFixture(_NativeReadFixture):
    """Separate fixed 35-second owner; never lengthens a five-second owner."""
    _ORIGINS = ('_origin', '_issued_origin', '_recovery_origin')
    _RESOURCES = ('_resource', '_issued_resource', '_recovery_resource')

    def __init__(self):
        if type(self) is not _WaitNativeReadFixture:
            raise NativeAcquisitionError('unsupported_wait_owner')
        deadline = monotonic()+35
        origin = _OwnerOrigin(self, current_thread(), get_ident(), deadline,
                              Event(), Event(), Event(), Event())
        for name in self._ORIGINS: setattr(self, name, origin)
        for name in self._RESOURCES: setattr(self, name, None)
        _NativeReadFixture._initialize_fixed_fixture(self, deadline)
        resource = _Resource(self._native, self._native.k, self._native.n,
            self._issued_fd, self._issued_handle, self._metadata_snapshot,
            self._issued_description, self._description_snapshot)
        for name in self._RESOURCES: setattr(self, name, resource)
        origin.allocated.set()
        try: self.validate()
        except BaseException:
            self.close()
            raise

    def _original(self):
        origin = _quorum(self, self._ORIGINS, _OwnerOrigin)
        if (origin.owner is not self or any(getattr(self, name, None) is not origin for name in self._ORIGINS)
                or any(type(value) is not _EVENT for value in
                    (origin.allocated, origin.closed, origin.attempted, origin.failed))):
            if origin.owner is self and type(origin.failed) is _EVENT: Event.set(origin.failed)
            raise NativeAcquisitionError('changed_wait_owner')
        return origin

    def _resource_original(self):
        origin = self._original()
        if not origin.allocated.is_set():
            if any(getattr(self, name, None) is not None for name in self._RESOURCES):
                raise NativeAcquisitionError('changed_wait_allocation')
            return None
        resource = _quorum(self, self._RESOURCES, _Resource)
        if any(getattr(self, name, None) is not resource for name in self._RESOURCES):
            origin.failed.set()
            raise NativeAcquisitionError('changed_wait_resource')
        return resource

    def _identity(self, *, active=True):
        origin = self._original()
        now = monotonic()
        if (type(self._deadline) is not float or self._deadline != origin.deadline
                or type(self._closed) is not bool or self._closed != origin.closed.is_set()
                or type(self._attempted) is not bool or self._attempted != origin.attempted.is_set()
                or type(self._cleanup_failed) is not bool or origin.failed.is_set()
                or self._cleanup_failed):
            raise NativeAcquisitionError('changed_wait_owner')
        if active and (current_thread() is not origin.thread or get_ident() != origin.ident
                       or origin.closed.is_set() or type(now) is not float or not math.isfinite(now)
                       or not origin.deadline-35 <= now < origin.deadline):
            raise NativeAcquisitionError('wait_resource_unavailable')
        resource = self._resource_original()
        if resource is not None:
            if (type(resource.native) is not _Native or self._native is not resource.native
                    or resource.native.k is not resource.kernel or resource.native.n is not resource.nt
                    or self._handle != resource.handle or self._issued_handle != resource.handle
                    or type(self._handle) is not int or type(self._issued_handle) is not int
                    or self._metadata_snapshot != resource.metadata or self._metadata != resource.metadata
                    or self.description is not resource.description or self._issued_description is not resource.description
                    or self._description_snapshot != resource.description_snapshot):
                raise NativeAcquisitionError('changed_wait_resource')
            if origin.closed.is_set():
                if self._fd is not None or self._issued_fd is not None:
                    raise NativeAcquisitionError('wait_resource_not_closed')
            elif (type(self._fd) is not int or type(self._issued_fd) is not int
                  or self._fd != resource.fd or self._issued_fd != resource.fd):
                raise NativeAcquisitionError('changed_wait_descriptor')
        return origin

    def validate(self):
        self._identity()
        _NativeReadFixture.validate(self)
        self._identity()

    def acquire_once(self, limit):
        origin = self._identity()
        if origin.attempted.is_set():
            raise NativeAcquisitionError('already_attempted')
        # Burn before even limit validation, without letting the original method
        # mistake the retained monotonic history for a second request.
        origin.attempted.set()
        self._attempted = True
        self.validate()
        size = self.description.size_bytes
        if type(limit) is not int or not size <= limit <= 4096:
            raise NativeAcquisitionError('invalid_read_bound')
        import os
        fd = self._resource_original().fd
        if os.lseek(fd, 0, os.SEEK_SET) != 0:
            raise NativeAcquisitionError('position_failed')
        self.validate()
        data = os.read(fd, size)
        from .broker_native_acquisition import _FIXTURE
        if type(data) is not bytes or data != _FIXTURE or len(data) != size:
            raise NativeAcquisitionError('invalid_fixture_read')
        self.validate()
        return data

    def close(self):
        origin = _quorum(self, self._ORIGINS, _OwnerOrigin)
        if origin.owner is not self or any(type(value) is not _EVENT for value in
                (origin.allocated, origin.closed, origin.attempted, origin.failed)):
            raise NativeAcquisitionError('original_ownership_unavailable')
        try: self._identity(active=False)
        except Exception: origin.failed.set()
        resource = None
        if origin.allocated.is_set():
            resource = _quorum(self, self._RESOURCES, _Resource)
            # Never call through a substituted native API or close a descriptor
            # selected by a mutable public alias. Unknown ownership withholds ACK.
            if (type(resource.native) is not _Native or resource.native.k is not resource.kernel
                    or resource.native.n is not resource.nt):
                origin.failed.set()
                raise NativeAcquisitionError('native_cleanup_uncertain')
            self._native = resource.native
            self._metadata_snapshot = resource.metadata
            self._issued_handle = self._handle = resource.handle
            if not origin.closed.is_set():
                self._issued_fd = self._fd = resource.fd
        origin.closed.set()
        _NativeReadFixture.close(self)
        if origin.failed.is_set():
            raise NativeAcquisitionError('native_cleanup_uncertain')

    def _retired_snapshot_current(self):
        origin = self._identity(active=False)
        if not origin.closed.is_set() or monotonic() >= origin.deadline:
            raise NativeAcquisitionError('wait_resource_not_retired')
        _NativeReadFixture.validate_description(self)


@dataclass(frozen=True)
class _Origin:
    adapter: object
    thread: object
    ident: int
    lock: object
    phases: object
    phase_origin: object
    deadline: float
    key_digest: str
    session: bytes
    opening: object
    opening_lock: object
    cancel: object
    opened: object
    native_seen: object
    owner_done: object
    acquiring: object
    wire_seen: object
    staged: object
    retired: object
    closed: object
    failed: object
    wait_timer: object
    wait_finished: object


@dataclass(frozen=True)
class _Owned:
    value: object
    origin: object
    deadline: float


@dataclass(frozen=True)
class _Allocation:
    value: object


@dataclass(frozen=True)
class _Wire:
    value: object
    lock: object
    buffer: object
    timer: object
    acquisition_timer: object
    timer_finished: object
    acquisition_finished: object
    deadline: float


@dataclass(frozen=True)
class _State:
    name: str
    request: object
    proposal: object
    binding: object
    recipient: object
    acknowledgment: object
    previous: object


class WaitNativeFixtureAdapter:
    """Private fixture-only transport actor, inactive and explicitly unauthorizing.

    Native observation and one read are performed only on this newly generated
    object. The authenticated sender is still trusted to enforce current review,
    authority and recipient ownership. No read/release/publish/execute API exists.
    """
    _ORIGINS = ('_origin', '_issued_origin', '_recovery_origin')
    _OWNERS = ('_owned', '_issued_owned', '_recovery_owned')
    _ALLOCATIONS = ('_allocation', '_issued_allocation', '_recovery_allocation')
    _WIRES = ('_wire_origin', '_issued_wire_origin', '_recovery_wire_origin')
    _STATES = ('_snapshot', '_issued_snapshot', '_recovery_snapshot')

    def __init__(self, *, key, session):
        if (type(self) is not WaitNativeFixtureAdapter or type(key) is not bytes or len(key) != 32
                or type(session) is not bytes or len(session) != 32 or key == session):
            raise NativeAcquisitionError('invalid_wait_bootstrap')
        phases = _WaitAcquisitionPhases()
        phase_origin = phases._original()
        lock = RLock()
        opening = _WaitOpeningExchange(role='broker', key=key, session=session)
        self._lock, self._phases, self._opening = lock, phases, opening
        self._key, self._session = key, session
        self._deadline = phase_origin.deadline_total
        self._cancelled = False
        self._owner = self._issued_owner = self._wire = self._issued_wire = None
        self._owner_changed = self._wire_changed = False
        self._owner_deadline_snapshot = None
        self._binding_snapshot = self._recipient_snapshot = None
        self._state = 'new'
        self._proposal = self._request = self._request_snapshot = None
        for name in self._OWNERS+self._WIRES+self._ALLOCATIONS: setattr(self, name, None)
        self._save('new')
        timer = Timer(max(0, phase_origin.deadline_wait-monotonic()), self._wait_expired)
        timer.daemon = True
        origin = _Origin(self, current_thread(), get_ident(), lock, phases, phase_origin,
            phase_origin.deadline_total, hashlib.sha256(key).hexdigest(), session,
            opening, opening._lock, Event(), Event(), Event(), Event(), Event(), Event(),
            Event(), Event(), Event(), Event(), timer, timer.finished)
        for name in self._ORIGINS: setattr(self, name, origin)
        self._retained_origin = origin
        self._timer = self._issued_timer = timer
        try: timer.start()
        except BaseException:
            self.close()
            raise NativeAcquisitionError('wait_adapter_unavailable') from None

    def _save(self, name, *, request=None, proposal=None, binding=None, recipient=None,
              acknowledgment=None, previous=None):
        value = _State(name, request, proposal, binding, recipient, acknowledgment, previous)
        for item in self._STATES: setattr(self, item, value)
        self._state = name

    def _original(self):
        origin = _quorum(self, self._ORIGINS, _Origin)
        if origin.adapter is not self or any(getattr(self, name, None) is not origin for name in self._ORIGINS):
            if origin.adapter is self and type(origin.failed) is _EVENT:
                Event.set(origin.failed)
            raise NativeAcquisitionError('changed_wait_adapter')
        return origin

    def _state_original(self):
        origin = self._original()
        value = _quorum(self, self._STATES, _State)
        if (any(getattr(self, name, None) is not value for name in self._STATES)
                or type(self._state) is not str or self._state != value.name):
            origin.failed.set()
            raise NativeAcquisitionError('changed_wait_state')
        return value

    def _optional(self, names, kind, seen):
        values = [getattr(self, name, None) for name in names]
        if not seen:
            if any(value is not None for value in values):
                raise NativeAcquisitionError('unexpected_wait_owner')
            return None
        value = _quorum(self, names, kind)
        if any(other is not value for other in values):
            raise NativeAcquisitionError('changed_wait_owner')
        return value

    def _identity(self, *, active=True):
        origin = self._original()
        if self._disposal_origin() is not origin:
            raise NativeAcquisitionError('changed_wait_owner')
        state = self._state_original()
        now = monotonic()
        if (self._retained_origin is not origin or self._lock is not origin.lock or self._phases is not origin.phases
                or self._opening is not origin.opening or origin.opening._lock is not origin.opening_lock
                or type(origin.opening) is not _WaitOpeningExchange
                or type(self._deadline) is not float or self._deadline != origin.deadline
                or self._timer is not origin.wait_timer or self._issued_timer is not origin.wait_timer
                or origin.wait_timer.finished is not origin.wait_finished
                or type(origin.wait_finished) is not type(Event())
                or type(self._cancelled) is not bool or self._cancelled != origin.cancel.is_set()
                or self._owner_changed is not False or self._wire_changed is not False
                or origin.failed.is_set() or type(self._session) is not bytes
                or self._session != (b'' if origin.closed.is_set() else origin.session)
                or type(self._key) is not bytes
                or (bool(self._key) if origin.closed.is_set() else hashlib.sha256(self._key).hexdigest() != origin.key_digest)):
            raise NativeAcquisitionError('changed_wait_adapter')
        if active and (current_thread() is not origin.thread or get_ident() != origin.ident
                or origin.cancel.is_set() or origin.closed.is_set() or type(now) is not float
                or not math.isfinite(now) or not origin.phase_origin.created <= now < origin.deadline):
            raise NativeAcquisitionError('wait_adapter_unavailable')
        if ((state.name == 'new' and origin.opened.is_set())
                or (state.name == 'observed' and (not origin.owner_done.is_set() or origin.acquiring.is_set()))
                or (state.name == 'acquiring' and (not origin.acquiring.is_set() or origin.staged.is_set()))
                or (state.name in ('staged', 'retiring') and not origin.staged.is_set())
                or (state.name != 'closed' and origin.closed.is_set())
                or (origin.retired.is_set() and (state.name != 'closed' or state.acknowledgment is None))):
            raise NativeAcquisitionError('rolled_back_wait_history')
        if origin.phases._original() is not origin.phase_origin:
            raise NativeAcquisitionError('changed_wait_clock')
        if state.name != 'new' and (origin.opening._state != 'closed'
                or type(origin.opening._key) is not bytes or origin.opening._key
                or type(origin.opening._step) is not int or origin.opening._step != 4):
            raise NativeAcquisitionError('changed_wait_opening')
        allocation = self._optional(self._ALLOCATIONS, _Allocation, origin.native_seen.is_set())
        if allocation is not None and (type(allocation.value) is not _WaitNativeReadFixture
                or self._owner is not allocation.value or self._issued_owner is not allocation.value):
            raise NativeAcquisitionError('changed_wait_allocation')
        owned = self._optional(self._OWNERS, _Owned, origin.owner_done.is_set())
        if owned is not None:
            if (type(owned.value) is not _WaitNativeReadFixture or self._owner is not owned.value
                    or self._issued_owner is not owned.value or owned.value._original() is not owned.origin
                    or owned.value._deadline != owned.deadline or self._owner_deadline_snapshot != owned.deadline):
                raise NativeAcquisitionError('changed_wait_native_owner')
            owned.value._identity(active=active and state.name not in ('retiring', 'closed'))
        elif allocation is None and (self._owner is not None or self._issued_owner is not None):
            raise NativeAcquisitionError('unexpected_wait_owner')
        wire = self._optional(self._WIRES, _Wire, origin.wire_seen.is_set())
        if wire is not None:
            if (type(wire.value) is not _WaitAcquisitionExchange or self._wire is not wire.value
                    or self._issued_wire is not wire.value or wire.value._lock is not wire.lock
                    or wire.value._buffer is not wire.buffer or wire.value._issued_buffer is not wire.buffer
                    or wire.value._timer is not wire.timer or wire.value._timer_snapshot is not wire.timer
                    or wire.timer.finished is not wire.timer_finished
                    or wire.acquisition_timer.finished is not wire.acquisition_finished
                    or type(wire.timer_finished) is not type(Event())
                    or type(wire.acquisition_finished) is not type(Event())
                    or type(wire.value._deadline) is not float or wire.value._deadline != wire.deadline
                    or wire.value._deadline_snapshot != wire.deadline or wire.deadline > origin.deadline):
                raise NativeAcquisitionError('changed_wait_wire')
        elif self._wire is not None or self._issued_wire is not None:
            raise NativeAcquisitionError('unexpected_wait_wire')
        if state.name in ('observed', 'acquiring', 'staged', 'retiring', 'closed') and state.request is not None:
            self._validate_opening(state)
        return origin, state

    @contextmanager
    def _guard(self):
        origin = self._original()
        if self._disposal_origin() is not origin:
            raise NativeAcquisitionError('changed_wait_owner')
        if type(origin.lock) is not _RLOCK or self._lock is not origin.lock:
            if type(origin.cancel) is _EVENT: Event.set(origin.cancel)
            if type(origin.failed) is _EVENT: Event.set(origin.failed)
            raise NativeAcquisitionError('changed_wait_lock')
        if current_thread() is not origin.thread or get_ident() != origin.ident:
            Event.set(origin.cancel); _WaitAcquisitionPhases.cancel(origin.phases)
            raise NativeAcquisitionError('wrong_wait_worker')
        if not origin.lock.acquire(blocking=False):
            Event.set(origin.cancel); _WaitAcquisitionPhases.cancel(origin.phases)
            raise NativeAcquisitionError('wait_adapter_busy')
        try: yield origin
        finally: origin.lock.release()

    def _wait_expired(self):
        origin = self._disposal_origin()
        # The original wait callback may race a successful phase transition. It
        # never cancels a subsequently entered acquisition or selects its timer.
        if origin.phase_origin.entered.is_set() or origin.acquiring.is_set() or origin.closed.is_set(): return
        origin.cancel.set()
        origin.phases.cancel()
        self._cancelled = True

    def _acquisition_expired(self):
        origin = self._disposal_origin()
        if origin.closed.is_set(): return
        origin.cancel.set()
        origin.phases.cancel()
        self._cancelled = True

    def _input_current(self):
        """Original worker pump fence; timers only signal, never perform I/O."""
        try:
            with self._guard():
                origin, state = self._identity(active=False)
                if origin.retired.is_set():
                    self._retired_snapshot_current()
                    return
                self._check(state.name)
                if state.name in ('observed', 'staged'):
                    self._owner.validate()
                self._check(state.name)
        except Exception: self._abort('wait_input_unavailable')

    def _check(self, state):
        origin, snapshot = self._identity()
        if snapshot.name != state:
            raise NativeAcquisitionError('wrong_wait_state')
        if origin.acquiring.is_set(): origin.phases.check_acquisition()
        else: origin.phases.check_wait()
        return origin, snapshot

    def _validate_opening(self, state=None):
        state = state or self._state_original()
        if (type(self._request) is not bytes or self._request != state.request
                or self._request_snapshot != state.request or self._proposal is not state.proposal
                or type(self._proposal) is not StructuredActionProposal
                or self._proposal.canonical_bytes().decode('ascii') != loads(state.request)['proposal_json']):
            raise NativeAcquisitionError('changed_wait_opening')

    def open(self, frame):
        try:
            with self._guard() as origin:
                self._check('new')
                if origin.opened.is_set(): raise NativeAcquisitionError('already_opened')
                origin.opened.set()
                request = origin.opening.receive(frame)
                private_ids = {self._key.hex(), origin.session.hex()}
                if request['decision_id'] in private_ids:
                    raise NativeAcquisitionError('bootstrap_identifier_collision')
                proposal = proposal_from_text(request['proposal_json'])
                request_bytes = _canonical(request)
                owner = object.__new__(_WaitNativeReadFixture)
                allocation = _Allocation(owner)
                for name in self._ALLOCATIONS: setattr(self, name, allocation)
                origin.native_seen.set()
                self._owner = self._issued_owner = owner
                _WaitNativeReadFixture.__init__(owner)
                owned = _Owned(owner, owner._original(), owner._deadline)
                for name in self._OWNERS: setattr(self, name, owned)
                origin.owner_done.set()
                self._owner_deadline_snapshot = owned.deadline
                self._proposal, self._request, self._request_snapshot = proposal, request_bytes, request_bytes
                description = owner.description
                observed_ids = {description.registry_session, description.owner_session, description.resource_token}
                if request['decision_id'] in observed_ids or observed_ids & private_ids:
                    raise NativeAcquisitionError('identifier_collision')
                if not description.size_bytes <= inspect_file_read_proposal(proposal).max_bytes <= 4096:
                    raise NativeAcquisitionError('unsupported_wait_bound')
                result = origin.opening.send(dict(registry_session=description.registry_session, observation=dict(
                    owner_session=description.owner_session, resource_token=description.resource_token,
                    volume_serial=description.volume_serial, file_id=description.file_id,
                    size_bytes=description.size_bytes, display_path=description.display_path)))
                origin.opening.close()
                self._save('observed', request=request_bytes, proposal=proposal)
                self._check('observed')
                owner.validate()
                return result
        except Exception: self._abort('wait_opening_rejected')

    def _wire_current(self, step):
        origin, state = self._identity()
        wire = _quorum(self, self._WIRES, _Wire).value
        origin.phases.check_acquisition()
        if (type(wire._step) is not int or wire._step != step or type(wire._state) is not str
                or wire._state != ('closed' if step == 4 else 'new')):
            raise NativeAcquisitionError('wait_wire_unavailable')
        if step < 4: wire._integrity()
        elif (type(wire._key) is not bytes or wire._key or wire._buffer):
            raise NativeAcquisitionError('wait_wire_not_retired')
        if state.binding is not None:
            if (type(wire._context_snapshot) is not bytes or wire._context_snapshot != state.binding
                    or _publication_binding(loads(wire._context_snapshot)) != state.binding
                    or self._binding_snapshot != state.binding or self._recipient_snapshot != state.recipient
                    or _canonical(loads(state.binding)['recipient']) != state.recipient):
                raise NativeAcquisitionError('changed_wait_binding')
        return wire

    def stage(self, frame):
        try:
            with self._guard() as origin:
                _, old = self._check('observed')
                if origin.acquiring.is_set(): raise NativeAcquisitionError('already_attempted')
                deadline = origin.phases.enter_acquisition()
                origin.acquiring.set()  # Invalid first frames permanently spend the phase.
                self._stop_timer(origin, origin.wait_timer, origin.wait_finished)
                self._save('acquiring', request=old.request, proposal=old.proposal)
                wire = _WaitAcquisitionExchange(role='broker', key=self._key, session=origin.session,
                                                timeout=min(5, deadline-monotonic()))
                wire._deadline = wire._deadline_snapshot = min(wire._deadline, deadline)
                timer = Timer(max(0, deadline-monotonic()), self._acquisition_expired)
                timer.daemon = True
                capsule = _Wire(wire, wire._lock, wire._issued_buffer, wire._timer, timer,
                    wire._timer.finished, timer.finished, wire._deadline)
                self._wire = self._issued_wire = wire
                for name in self._WIRES: setattr(self, name, capsule)
                origin.wire_seen.set()
                timer.start()
                binding = wire.accept_request(frame).inspect()
                public_ids = {binding['context'][name] for name in
                              ('review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token')}
                public_ids.update(binding['recipient'][name] for name in ('recipient_session', 'recipient_id'))
                if public_ids & {self._key.hex(), origin.session.hex()}:
                    raise NativeAcquisitionError('bootstrap_identifier_collision')
                binding_bytes, recipient_bytes = _publication_binding(binding), _canonical(binding['recipient'])
                self._binding_snapshot, self._recipient_snapshot = binding_bytes, recipient_bytes
                self._save('acquiring', request=old.request, proposal=old.proposal,
                           binding=binding_bytes, recipient=recipient_bytes)
                self._wire_current(1)
                self._owner.validate(); self._validate_opening()
                d, request = self._owner.description, loads(old.request)
                intent = inspect_file_read_proposal(old.proposal)
                expected = dict(application_id=request['application_id'], proposal_id=intent.proposal_id,
                    decision_id=request['decision_id'], registry_session=d.registry_session,
                    owner_session=d.owner_session, resource_token=d.resource_token,
                    volume_serial=d.volume_serial, file_id=d.file_id, size_bytes=d.size_bytes,
                    max_bytes=intent.max_bytes, operation='files.read', recipient='requesting_application')
                if (any(binding['context'][name] != value for name, value in expected.items())
                        or binding['recipient']['application_id'] != request['application_id']
                        or binding['recipient']['recipient_revision'] != 1):
                    raise NativeAcquisitionError('wait_binding_mismatch')
                self._check('acquiring')
                data = self._owner.acquire_once(binding['context']['max_bytes'])
                self._check('acquiring')
                result = wire.reply(outcome='staged', data=data)
                self._wire_current(2)
                self._owner.validate(); self._validate_opening(); self._check('acquiring')
                origin.staged.set()
                self._save('staged', request=old.request, proposal=old.proposal,
                           binding=binding_bytes, recipient=recipient_bytes)
                return result
        except Exception: self._abort('wait_native_staging_rejected')

    def retire(self, frame):
        try:
            with self._guard() as origin:
                _, old = self._check('staged')
                self._save('retiring', request=old.request, proposal=old.proposal,
                           binding=old.binding, recipient=old.recipient)
                wire = self._wire_current(2)
                wire.accept_retirement(frame)
                self._wire_current(3)
                self._owner.validate(); self._validate_opening()
                self._owner.close()  # No authenticated cleanup claim on uncertainty.
                # Native closure is expected here, but phase/key/graph checks remain.
                self._wire_current(3)
                result = wire.acknowledge_retirement()
                self._wire_current(4)
                origin.phases.check_acquisition()
                previous = wire._previous
                origin.retired.set()
                self._save('closed', request=old.request, proposal=old.proposal,
                    binding=old.binding, recipient=old.recipient,
                    acknowledgment=hashlib.sha256(result).hexdigest(), previous=previous)
                self._shutdown(origin)
                self._retired_snapshot_current()
                return result
        except Exception: self._abort('wait_native_retirement_rejected')

    def _retired_snapshot_current(self):
        origin, state = self._identity(active=False)
        if (origin.cancel.is_set() or not origin.retired.is_set() or not origin.closed.is_set()
                or state.name != 'closed' or not origin.staged.is_set()
                or monotonic() >= origin.deadline):
            raise NativeAcquisitionError('wait_retirement_unavailable')
        origin.phases.check_acquisition()
        owned = _quorum(self, self._OWNERS, _Owned)
        owned.value._retired_snapshot_current()
        wire = _quorum(self, self._WIRES, _Wire).value
        phase = wire._phase_snapshot
        if (type(wire._step) is not int or wire._step != 4
                or type(wire._state) is not str or wire._state != 'closed'
                or type(wire._key) is not bytes or wire._key or wire._buffer
                or type(state.acknowledgment) is not str
                or re.fullmatch('[0-9a-f]{64}', state.acknowledgment) is None
                or type(state.previous) is not str or type(wire._previous) is not str
                or state.previous != state.acknowledgment
                or wire._previous != state.previous or type(phase) is not tuple or len(phase) != 3
                or type(phase[0]) is not int or type(phase[1]) is not str or type(phase[2]) is not str
                or phase != (4, state.previous, 'closed')
                or type(wire._context_snapshot) is not bytes or wire._context_snapshot != state.binding):
            raise NativeAcquisitionError('changed_wait_retirement')
        self._validate_opening(state)

    def _abort(self, reason):
        try:
            origin = self._disposal_origin()
            origin.failed.set()
            self.close()
        finally: raise NativeAcquisitionError(reason) from None

    def close(self):
        origin = self._disposal_origin()
        if origin.adapter is not self:
            raise NativeAcquisitionError('original_ownership_unavailable')
        try: self._identity(active=False)
        except Exception: origin.failed.set()
        if not origin.retired.is_set():
            origin.cancel.set()
            origin.phases.cancel()
        self._cancelled = origin.cancel.is_set()
        if current_thread() is not origin.thread or get_ident() != origin.ident:
            return  # A foreign caller signals only; the original worker disposes.
        if not origin.lock.acquire(blocking=False):
            return  # Original worker sees cancellation and performs known cleanup.
        try: self._shutdown(origin)
        finally: origin.lock.release()

    def _disposal_origin(self):
        origin = getattr(self, '_retained_origin', None)
        if type(origin) is not _Origin or origin.adapter is not self:
            origin = _quorum(self, self._ORIGINS, _Origin)
        if (origin.adapter is not self or type(origin.lock) is not _RLOCK
                or type(origin.phases) is not _WaitAcquisitionPhases
                or type(origin.opening) is not _WaitOpeningExchange
                or type(origin.opening_lock) is not _RLOCK
                or type(origin.wait_timer) is not Timer
                or any(type(value) is not _EVENT for value in (origin.wait_finished,
                    origin.cancel, origin.opened, origin.native_seen, origin.owner_done,
                    origin.acquiring, origin.wire_seen, origin.staged, origin.retired,
                    origin.closed, origin.failed))):
            # A rejected provenance check must remain rejected after a caller
            # restores a damaged field. Signal only independently typed events
            # belonging to this original instance; never dispatch through the
            # invalid lock, timer, opening or phase object.
            if origin.adapter is self:
                for value in (origin.cancel, origin.failed):
                    if type(value) is _EVENT:
                        Event.set(value)
            raise NativeAcquisitionError('original_ownership_unavailable')
        return origin

    def _shutdown(self, origin):
        self._stop_timer(origin, origin.wait_timer, origin.wait_finished)
        failures = []
        try:
            if origin.wire_seen.is_set():
                try:
                    wire = _quorum(self, self._WIRES, _Wire)
                    self._stop_timer(origin, wire.acquisition_timer, wire.acquisition_finished)
                    self._stop_timer(origin, wire.timer, wire.timer_finished)
                    if self._wire is not wire.value or self._issued_wire is not wire.value:
                        self._wire_changed = True; origin.failed.set()
                    if (wire.value._lock is not wire.lock or wire.value._timer is not wire.timer
                            or wire.value._timer_snapshot is not wire.timer
                            or wire.value._buffer is not wire.buffer or wire.value._issued_buffer is not wire.buffer):
                        origin.failed.set()
                    # Restore this private graph solely for disposal. Select no
                    # lock, timer, buffer or callback from the changed aliases.
                    wire.value._lock = wire.lock
                    wire.value._timer = wire.value._timer_snapshot = wire.timer
                    wire.value._buffer = wire.value._issued_buffer = wire.buffer
                    if not wire.lock.acquire(blocking=False):
                        raise NativeAcquisitionError('wait_wire_busy')
                    try:
                        wire.buffer[:] = b'\0'*len(wire.buffer)
                        bytearray.clear(wire.buffer)
                        wire.value._step = 4
                        FixtureBrokerExchange._failed(wire.value)
                        wire.value._phase_snapshot = (4, wire.value._previous, 'closed')
                    finally: wire.lock.release()
                except Exception as exc: failures.append(exc)
            try:
                if origin.opening._lock is not origin.opening_lock:
                    origin.failed.set()
                    origin.opening._lock = origin.opening_lock
                if not origin.opening_lock.acquire(blocking=False):
                    raise NativeAcquisitionError('wait_opening_busy')
                try: LiveMetadataExchange._failed(origin.opening)
                finally: origin.opening_lock.release()
            except Exception as exc: failures.append(exc)
            try:
                values = [getattr(self, name, None) for name in self._OWNERS]
                if any(value is not None for value in values):
                    owned = _quorum(self, self._OWNERS, _Owned)
                    if self._owner is not owned.value or self._issued_owner is not owned.value:
                        self._owner_changed = True; origin.failed.set()
                    _WaitNativeReadFixture.close(owned.value)
                elif origin.native_seen.is_set():
                    # Allocation may have failed after an original owner was
                    # retained but before its completed capsule was published.
                    allocation = _quorum(self, self._ALLOCATIONS, _Allocation)
                    if type(allocation.value) is not _WaitNativeReadFixture:
                        raise NativeAcquisitionError('unknown_wait_allocation')
                    _WaitNativeReadFixture.close(allocation.value)
            except Exception as exc: failures.append(exc)
        finally:
            self._key = self._session = b''
            origin.closed.set()
            old = _quorum(self, self._STATES, _State)
            if origin.retired.is_set():
                # Preserve the successful transcript; close never reconstructs it.
                if self._state != old.name: origin.failed.set()
            else:
                self._save('closed', request=old.request, proposal=old.proposal,
                           binding=old.binding, recipient=old.recipient)
        if failures:
            origin.failed.set()
            raise NativeAcquisitionError('wait_cleanup_uncertain') from None

    @staticmethod
    def _stop_timer(origin, timer, finished):
        if type(timer) is not Timer or type(finished) is not type(Event()):
            origin.failed.set()
            raise NativeAcquisitionError('unknown_wait_timer')
        if timer.finished is not finished:
            origin.failed.set()
            # Timer.run reads .finished again after its original wait returns.
            # Repair this private disposal link before waking that original wait.
            timer.finished = finished
        Event.set(finished)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
