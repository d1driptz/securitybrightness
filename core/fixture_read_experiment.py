"""Opt-in, fixture-only read enforcement experiment; never imported by /check.

The bootstrap owns one newly created synthetic file. Application and operator
ports are distributed separately by a trusted host. This is not isolation from
hostile Python in the host process, an arbitrary file API or a Windows sandbox.
"""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass, field
import json
from pathlib import Path
import tempfile
from threading import RLock
from time import monotonic
from uuid import uuid4

from .file_read_constraint import FileReadConstraint
from .file_read_review import FileReadReviewLedger
from .file_read_schema import inspect_file_read_proposal
from .registry import ApplicationRegistry, AuthorityInactiveError
from .registry_bound_review import RegistryBoundFileReadReviews
from .resource_review import ResourceReviewEnvelopes
from .windows_identity import WindowsIdentityCollector, ResourceIdentityError

FIXTURE_REFERENCE = 'controlled-fixture'
MAX_FIXTURE_BYTES = 4096
REVIEW_SECONDS = 60


@dataclass(frozen=True)
class FixtureRequest:
    request_id: str

    def __bool__(self):
        raise TypeError('A request is not permission')


@dataclass(frozen=True)
class HumanReviewDisplay:
    request_id: str
    application_id: str
    proposal_id: str
    requester_reference: str
    observed_display_path: str
    volume_serial: int
    file_id: str
    observation_id: str
    max_bytes: int
    grant_id: str
    draft_revision: int
    envelope_id: str
    draft_id: str
    proposal_json: str
    meaning: str = 'This file object, one bounded read; not immutable bytes.'

    def __bool__(self):
        raise TypeError('Displaying a review is not approval')


@dataclass(frozen=True)
class ProtectedReadResult:
    released: bool
    reason: str
    data: bytes = field(default=b'', repr=False)

    def __bool__(self):
        raise TypeError('Inspect the explicit protected read result')


class _Reader:
    """Private same-object read adapter; accepts no pathname or user handle."""
    def __init__(self, collector, observation):
        self.collector, self.observation = collector, observation
        self.k = collector._native.k
        self.k.ReOpenFile.argtypes = [w.HANDLE, w.DWORD, w.DWORD, w.DWORD]
        self.k.ReOpenFile.restype = w.HANDLE
        self.k.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        self.k.ReadFile.restype = w.BOOL

    def read_staged(self, limit):
        # Only called after authority, approval and one-use retirement checks.
        if not self.collector.revalidate(self.observation):
            raise ResourceIdentityError('resource_unavailable')
        entry = self.collector._held[self.observation.observation_id]
        original, expected = entry[1][-1], entry[3]
        size = expected[2]
        if type(limit) is not int or not 1 <= limit <= MAX_FIXTURE_BYTES or size > limit:
            raise ResourceIdentityError('read_bound_exceeded')
        # ReOpenFile refers to the retained object, never an application pathname.
        # Read-data access + share-read excludes ordinary write/delete handles.
        handle = self.k.ReOpenFile(original, 0x100081, 1, 0x00200000)
        if handle in (None, c.c_void_p(-1).value):
            raise ResourceIdentityError('read_handle_unavailable')
        try:
            native = self.collector._native
            if native.metadata(handle, False) != expected:
                raise ResourceIdentityError('resource_changed')
            buffer, count = c.create_string_buffer(max(1, size)), w.DWORD()
            if not self.k.ReadFile(handle, buffer, size, c.byref(count), None) or count.value != size:
                raise ResourceIdentityError('read_failed')
            if native.metadata(handle, False) != expected or not self.collector.revalidate(self.observation):
                raise ResourceIdentityError('resource_changed')
            staged = buffer.raw[:size]
        finally:
            # A close error prevents this function returning staged bytes.
            self.collector._native.close(handle)
        return staged


class ApplicationFixturePort:
    """Application-facing methods: no approval, path or caller-supplied identity."""
    def __init__(self, controller):
        self._controller = controller

    def propose(self, application_id, credential, proposal):
        return self._controller.propose(application_id, credential, proposal)

    def read_once(self, request, application_id, credential, proposal):
        return self._controller.read_once(request, application_id, credential, proposal)


class OperatorFixturePort:
    """Trusted operator channel, never handed to application code or HTTP."""
    def __init__(self, controller):
        self._controller = controller

    def review(self, request):
        return self._controller.review(request)

    def approve(self, displayed_review):
        return self._controller.approve(displayed_review)

    def deny(self, request):
        return self._controller.deny(request)

    def revoke_review(self, request):
        return self._controller.deny(request)


class FixtureReadExperiment:
    """Trusted bootstrap/controller; application receives only application_port.

    One fixture, at most 32 proposals, 60-second nonrenewable review lifetime.
    Registry lifecycle changes serialize with read staging and publication. All
    experiment-owned review/approval/resource lifecycle changes use this lock.
    The registry is the only shared external authority; there are no callbacks.
    """
    def __init__(self, registry, *, fixture_data=b'SecurityBrightness synthetic fixture\n'):
        if type(registry) is not ApplicationRegistry:
            raise TypeError('expected trusted application registry')
        if type(fixture_data) is not bytes or len(fixture_data) > MAX_FIXTURE_BYTES:
            raise ValueError('fixture must be at most 4096 synthetic bytes')
        import msvcrt
        self._registry = registry
        self._lock = RLock()
        self._closed = False
        self._faulted = False
        self._requests = {}
        self._collector = WindowsIdentityCollector(capacity=1)
        self._folder = tempfile.TemporaryDirectory(prefix='sb-controlled-read-')
        self._path = Path(self._folder.name) / 'synthetic-fixture.txt'
        try:
            # Exclusive creation; pin the created object until observation is held.
            # This bootstrap write is fixture setup, never a proposed operation.
            with self._path.open('xb') as fixture:
                fixture.write(fixture_data)
                fixture.flush()
                identity = self._collector._native.metadata(msvcrt.get_osfhandle(fixture.fileno()), False)[:2]
                self._observation = self._collector.collect(str(self._path))
                if identity != (self._observation.volume_serial, self._observation.file_id):
                    raise ResourceIdentityError('fixture_identity_changed')
            # Closing the writer can update timestamps; capture final metadata on
            # the same already-retained handle, never reacquire through a pathname.
            entry = self._collector._held[self._observation.observation_id]
            if self._collector._native.metadata(entry[1][-1], False) != entry[3]:
                raise ResourceIdentityError('fixture_metadata_changed')
            self._reader = _Reader(self._collector, self._observation)
            self._ledger = FileReadReviewLedger(capacity=32)
            self._reviews = RegistryBoundFileReadReviews(registry, self._ledger)
            self._envelopes = ResourceReviewEnvelopes(self._reviews, self._collector, capacity=32)
            self.application_port = ApplicationFixturePort(self)
            self.operator_port = OperatorFixturePort(self)
        except Exception:
            self._collector.close()
            self._folder.cleanup()
            raise

    def _state(self, request):
        if self._closed or self._faulted or type(request) is not FixtureRequest or type(request.request_id) is not str:
            raise ValueError('unknown request')
        state = self._requests.get(request.request_id)
        if state is None or state['request'] is not request or state['retired']:
            raise ValueError('unknown or retired request')
        return state

    def _unexpired(self, state):
        if monotonic() >= state['deadline']:
            state['retired'] = True
            raise ValueError('review expired')

    def _current(self, state):
        if self._closed or self._faulted:
            raise ValueError('experiment unavailable')
        self._unexpired(state)
        if not self._envelopes.inspect(state['envelope'], state['app'].application_id, state['proposal']).current:
            raise ValueError('evidence stale')
        # This experimental policy always requires human approval even for trusted
        # applications. Only existing authority supplies scopes, never the proposal.
        if not ({'files.read', '*'} & state['app'].scopes):
            raise AuthorityInactiveError('read scope required')
        self._unexpired(state)

    def propose(self, application_id, credential, proposal):
        if type(credential) is not str or not 1 <= len(credential) <= 512:
            raise AuthorityInactiveError('invalid credential')
        intent = inspect_file_read_proposal(proposal)
        if intent.reference != FIXTURE_REFERENCE or intent.max_bytes > MAX_FIXTURE_BYTES:
            raise ValueError('only the controlled fixture is supported')
        with self._lock:
            if self._closed or self._faulted or len(self._requests) >= 32:
                raise ValueError('experiment unavailable')
            app = self._registry.authenticate(application_id, credential)
            if app is None or not ({'files.read', '*'} & app.scopes):
                raise AuthorityInactiveError('current read authority required')
            lease = self._registry.authorization_lease(app)
            with lease():
                identity = str(uuid4())
                if identity in self._requests:
                    raise ValueError('duplicate request identity')
                draft = self._ledger.create(FileReadConstraint(app.application_id, FIXTURE_REFERENCE,
                                                               max_bytes=MAX_FIXTURE_BYTES))
                ticket = self._reviews.begin_review(app.application_id, credential, proposal, draft.draft_id, 1)
                envelope = self._envelopes.capture(ticket, app.application_id, proposal, self._observation)
                request = FixtureRequest(identity)
                self._requests[identity] = dict(request=request, app=app, lease=lease, proposal=proposal,
                    envelope=envelope, deadline=monotonic() + REVIEW_SECONDS, display=None,
                    approved=False, retired=False, max_bytes=intent.max_bytes)
                return request

    def review(self, request):
        with self._lock:
            state = self._state(request)
            try:
                with state['lease']():
                    self._current(state)
                    envelope = state['envelope']
                    observation = envelope.observation
                    display = HumanReviewDisplay(request.request_id, state['app'].application_id,
                        envelope.proposal_id, FIXTURE_REFERENCE, observation.display_path, observation.volume_serial,
                        observation.file_id.hex(), observation.observation_id, state['max_bytes'],
                        envelope.review.grant_id, envelope.review.review.revision,
                        envelope.envelope_id, envelope.review.review.draft_id,
                        json.dumps(state["proposal"].to_payload(), ensure_ascii=True, sort_keys=True))
                    # Redisplay invalidates any previous approval/display record.
                    self._unexpired(state)
                    state['display'], state['approved'] = display, False
                    return display
            except Exception:
                state['retired'] = True
                raise ValueError('review unavailable') from None

    def approve(self, display):
        with self._lock:
            if self._closed or type(display) is not HumanReviewDisplay or type(display.request_id) is not str:
                return False
            state = self._requests.get(display.request_id)
            if state is None or state['retired'] or state['display'] is not display or state['approved']:
                return False
            try:
                with state['lease']():
                    self._current(state)
                    state['approved'] = True
                    return True
            except Exception:
                state['retired'] = True
                return False

    def deny(self, request):
        with self._lock:
            try:
                state = self._state(request)
            except ValueError:
                return False
            state['retired'], state['approved'] = True, False
            self._envelopes.discard(state['envelope'])
            return True

    def read_once(self, request, application_id, credential, proposal):
        with self._lock:
            try:
                state = self._state(request)
                # Burn on the first attempt, including denial, mismatch and failure.
                state['retired'] = True
                if type(credential) is not str or not 1 <= len(credential) <= 512:
                    raise AuthorityInactiveError('invalid credential')
                intent = inspect_file_read_proposal(proposal)
                app = self._registry.authenticate(application_id, credential)
                if (app is not state['app'] or intent.proposal_id != state['envelope'].proposal_id
                        or not state['approved']):
                    raise AuthorityInactiveError('approval or binding unavailable')
                with state['lease']():
                    self._current(state)
                    try:
                        data = self._reader.read_staged(state['max_bytes'])
                    except Exception:
                        self._faulted = True
                        raise
                    # Catch reentrant failure injection as well as final freshness.
                    # Other threads cannot mutate registry authority during this lease.
                    with state['lease']():
                        self._current(state)
                        if type(data) is not bytes or len(data) != self._observation.size_bytes or len(data) > state['max_bytes']:
                            raise ResourceIdentityError('invalid_read_result')
                        self._envelopes.discard(state['envelope'])
                        result = ProtectedReadResult(True, 'controlled_read_released', data)
                        # Publication decision: no blocking work after this deadline check.
                        self._unexpired(state)
                        return result
            except Exception:
                return ProtectedReadResult(False, 'controlled_read_denied')

    def close(self):
        with self._lock:
            self._closed = True
            for state in self._requests.values():
                state['retired'], state['approved'] = True, False
            self._envelopes.close()
            self._collector.close()
            self._folder.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
