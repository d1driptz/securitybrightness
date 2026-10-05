"""Inactive fixed generated-fixture adapter; stages data only for discard.

Trusted bootstrap owns this adapter and its private transport key. No caller path,
handle, contents or executable is accepted. Only the separate inactive discard
diagnostic selects it; no existing protected-reader, desktop or product route does.
Staging frames are private adapter transport, never application byte delivery.
"""
from dataclasses import dataclass
import ctypes
import math
import os
import re
import secrets
import tempfile
from threading import RLock, Timer
from time import monotonic
from .broker_live_protocol import LiveMetadataExchange
from .broker_quarantine import QuarantinedReadExchange
from .broker_observation import proposal_from_text, _observation
from .broker_protocol import _canonical
from .file_read_schema import inspect_file_read_proposal
from .structured_proposal import StructuredActionProposal
from .windows_identity import _Native

_FIXTURE = b'SecurityBrightness synthetic fixture\n'


class NativeAcquisitionError(ValueError):
    pass


@dataclass(frozen=True)
class _Description:
    registry_session: str
    owner_session: str
    resource_token: str
    volume_serial: int
    file_id: str
    size_bytes: int
    display_path: str


class _NativeReadFixture:
    """Own only the fixed fixture's original exclusive read/write handle."""
    def __init__(self):
        self._fd = self._issued_fd = self._issued_handle = None
        self._closed = self._attempted = self._cleanup_failed = False
        self._deadline = monotonic()+5
        try:
            self._native = _Native()
            registry, owner, token = (secrets.token_hex(32) for _ in range(3))
            if (any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
                    for value in (registry, owner, token)) or len({registry, owner, token}) != 3):
                raise ValueError('identifier_collision')
            path = os.path.join(tempfile.gettempdir(), 'sb-native-acquisition-'+token+'.txt')
            # Atomic CREATE_NEW, DELETE_ON_CLOSE, OPEN_REPARSE_POINT; no pathname
            # reopen or fallback. Sharing zero keeps ordinary writers/deleters out.
            handle = self._native.k.CreateFileW(path, 0xC0010080, 0, None, 1, 0x04200100, None)
            if handle in (None, ctypes.c_void_p(-1).value): raise ValueError('creation_failed')
            try:
                import msvcrt
                self._fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except BaseException:
                self._native.close(handle)
                raise
            self._issued_fd = self._fd
            self._handle = self._issued_handle = handle
            if os.get_inheritable(self._fd): raise ValueError('inherited_resource')
            offset = 0
            while offset < len(_FIXTURE):
                count = os.write(self._fd, _FIXTURE[offset:])
                if count <= 0: raise ValueError('write_failed')
                offset += count
            os.fsync(self._fd)
            self._validate_descriptor()
            self._native.local_ntfs(self._handle)
            self._metadata = self._native.metadata(self._handle, False)
            self._validate_metadata_types(self._metadata)
            self._metadata_snapshot = self._metadata
            if self._metadata[2] != len(_FIXTURE): raise ValueError('size_mismatch')
            self.description = _Description(registry, owner, token, self._metadata[0],
                self._metadata[1].hex(), self._metadata[2], self._native.display(self._handle))
            self._description_snapshot = _canonical(self.description.__dict__)
            self._issued_description = self.description
            _observation(dict(owner_session=owner, resource_token=token,
                volume_serial=self.description.volume_serial, file_id=self.description.file_id,
                size_bytes=self.description.size_bytes, display_path=self.description.display_path))
            self.validate()
        except BaseException:
            self.close()
            raise NativeAcquisitionError('fixture_creation_failed') from None

    def validate(self):
        if self._closed or monotonic() >= self._deadline:
            raise NativeAcquisitionError('native_resource_unavailable')
        self.validate_description()
        self._validate_descriptor()
        metadata = self._native.metadata(self._issued_handle, False)
        self._validate_metadata_types(metadata)
        self._validate_descriptor()
        self.validate_description()
        if (self._closed or self._fd is None or metadata != self._metadata_snapshot
                or monotonic() >= self._deadline):
            raise NativeAcquisitionError('native_resource_changed')

    def _validate_descriptor(self):
        import msvcrt
        if (type(self._fd) is not int or self._fd != self._issued_fd
                or type(self._handle) is not int or self._handle != self._issued_handle
                or msvcrt.get_osfhandle(self._fd) != self._issued_handle):
            raise NativeAcquisitionError('native_descriptor_changed')

    def validate_description(self):
        if type(self.description) is not _Description or self.description is not self._issued_description:
            raise NativeAcquisitionError('native_resource_changed')
        value = self.description
        if (type(value.registry_session) is not str or type(value.owner_session) is not str
                or type(value.resource_token) is not str or type(value.volume_serial) is not int
                or type(value.file_id) is not str or type(value.size_bytes) is not int
                or type(value.display_path) is not str):
            raise NativeAcquisitionError('native_resource_changed')
        self._validate_metadata_types(self._metadata)
        if (_canonical(self.description.__dict__) != self._description_snapshot
                or self._metadata != self._metadata_snapshot):
            raise NativeAcquisitionError('native_resource_changed')

    @staticmethod
    def _validate_metadata_types(value):
        if (type(value) is not tuple or len(value) != 8
                or type(value[1]) is not bytes or len(value[1]) != 16
                or any(type(value[index]) is not int for index in (0, 2, 3, 4, 5, 6, 7))):
            raise NativeAcquisitionError('invalid_native_metadata')

    def acquire_once(self, limit):
        if self._attempted: raise NativeAcquisitionError('already_attempted')
        self._attempted = True
        self.validate()
        size = self.description.size_bytes
        if type(limit) is not int or not size <= limit <= 4096:
            raise NativeAcquisitionError('invalid_read_bound')
        fd = self._issued_fd
        if os.lseek(fd, 0, os.SEEK_SET) != 0:
            raise NativeAcquisitionError('position_failed')
        self.validate()
        data = os.read(fd, size)  # Same retained object, at most approved size.
        if type(data) is not bytes or data != _FIXTURE or len(data) != size:
            raise NativeAcquisitionError('invalid_fixture_read')
        self.validate()
        return data

    def close(self):
        self._closed = True
        if self._issued_fd is not None:
            fd, self._issued_fd, self._fd = self._issued_fd, None, None
            try:
                import msvcrt
                # Never close a substituted/reused descriptor belonging elsewhere.
                if msvcrt.get_osfhandle(fd) != self._issued_handle:
                    raise NativeAcquisitionError('native_descriptor_changed')
                if hasattr(self, '_metadata_snapshot'):
                    current = self._native.metadata(self._issued_handle, False)
                    self._validate_metadata_types(current)
                    # Numeric CRT descriptors and Windows handles can both be
                    # reused. Verify original object identity before cleanup.
                    if any(current[index] != self._metadata_snapshot[index] for index in (0, 1, 5)):
                        raise NativeAcquisitionError('native_cleanup_identity_changed')
                os.close(fd)
            except BaseException: self._cleanup_failed = True
        self._fd = None
        if self._cleanup_failed: raise NativeAcquisitionError('native_cleanup_uncertain')


class NativeFixtureAcquisitionAdapter:
    """One opening, one native acquisition, one discard. No byte release API.

    A signed reservation proves coordinator key possession, not current authority
    or human permission. The coordinator must keep/recheck that evidence separately.
    The adapter and Python process remain trusted; hostile code in that process
    can bypass API separation. This is not an OS access sandbox.
    """
    def __init__(self, *, key, session, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_adapter_lifetime')
        self._lock = RLock()
        self._state = 'new'
        self._cancelled = self._closing = False
        self._owner = self._wire = None
        self._opening = LiveMetadataExchange(role='broker', key=key, session=session)
        self._key, self._session = key, session
        self._deadline = monotonic()+timeout
        self._timer = Timer(timeout, self.close)
        self._timer.daemon = True
        try: self._timer.start()
        except Exception:
            self.close()
            raise NativeAcquisitionError('adapter_unavailable') from None

    def _check(self, state):
        if self._cancelled or self._state != state or monotonic() >= self._deadline:
            raise NativeAcquisitionError('adapter_unavailable')

    def _wire_current(self, step):
        if (self._wire is None or self._wire._step != step
                or (self._wire._state == 'closed') != (step == 4)
                or monotonic() >= self._wire._deadline):
            raise NativeAcquisitionError('quarantine_unavailable')

    def open(self, frame):
        with self._lock:
            try:
                self._check('new')
                request = self._opening.receive(frame)
                self._proposal = proposal_from_text(request['proposal_json'])
                self._request = _canonical(request)
                self._request_snapshot = self._request
                self._owner = _NativeReadFixture()
                self._owner._deadline = min(self._owner._deadline, self._deadline)
                d = self._owner.description
                if request['decision_id'] in {d.registry_session, d.owner_session, d.resource_token}:
                    raise NativeAcquisitionError('identifier_collision')
                if not d.size_bytes <= inspect_file_read_proposal(self._proposal).max_bytes <= 4096:
                    raise NativeAcquisitionError('unsupported_bound')
                self._wire = QuarantinedReadExchange(role='broker', key=self._key,
                    session=self._session, timeout=min(5, self._deadline-monotonic()))
                observed = dict(registry_session=d.registry_session, observation=dict(
                    owner_session=d.owner_session, resource_token=d.resource_token,
                    volume_serial=d.volume_serial, file_id=d.file_id, size_bytes=d.size_bytes,
                    display_path=d.display_path))
                result = self._opening.send(observed)
                self._opening.close()
                self._check('new')
                self._state = 'observed'
                return result
            except Exception:
                self.close()
                raise NativeAcquisitionError('opening_rejected') from None

    def stage(self, frame):
        with self._lock:
            try:
                self._check('observed')
                self._state = 'acquiring'  # Burn before decoding/validation/native work.
                context = self._wire.accept_request(frame).inspect()
                self._wire_current(1)
                self._owner.validate()
                d, request = self._owner.description, self._request_values()
                self._validate_opening()
                intent = inspect_file_read_proposal(self._proposal)
                expected = dict(application_id=request['application_id'], proposal_id=intent.proposal_id,
                    decision_id=request['decision_id'], registry_session=d.registry_session,
                    owner_session=d.owner_session, resource_token=d.resource_token,
                    volume_serial=d.volume_serial, file_id=d.file_id, size_bytes=d.size_bytes,
                    max_bytes=intent.max_bytes, operation='files.read', recipient='requesting_application')
                if any(context[name] != value for name, value in expected.items()):
                    raise NativeAcquisitionError('binding_mismatch')
                data = self._owner.acquire_once(context['max_bytes'])
                self._check('acquiring')
                result = self._wire.reply(outcome='staged', data=data)
                self._wire_current(2)
                self._owner.validate()
                self._validate_opening()
                self._check('acquiring')
                self._state = 'staged'
                return result
            except Exception:
                self.close()
                raise NativeAcquisitionError('native_staging_rejected') from None

    def _request_values(self):
        from .json_input import loads
        if type(self._request) is not bytes or self._request != self._request_snapshot:
            raise NativeAcquisitionError('changed_opening')
        return loads(self._request)

    def _validate_opening(self):
        if (type(self._proposal) is not StructuredActionProposal
                or self._proposal.canonical_bytes().decode('ascii') != self._request_values()['proposal_json']):
            raise NativeAcquisitionError('changed_proposal')

    def retire(self, frame):
        with self._lock:
            try:
                self._check('staged')
                self._state = 'retiring'
                self._wire.accept_discard(frame)
                self._wire_current(3)
                self._validate_opening()
                self._owner.validate()
                self._owner.close()  # No ack if native cleanup fails.
                self._check('retiring')
                result = self._wire.acknowledge_discard()
                self._wire_current(4)
                self._check('retiring')
                self._shutdown()
                self._wire_current(4)
                self._owner.validate_description()
                self._validate_opening()
                if self._cancelled or monotonic() >= self._deadline:
                    raise NativeAcquisitionError('cancelled_during_cleanup')
                return result
            except Exception:
                self.close()
                raise NativeAcquisitionError('native_retirement_rejected') from None

    def close(self):
        with self._lock:
            self._cancelled = True
            self._shutdown()

    def _shutdown(self):
        self._state = 'closed'
        if self._closing: return
        self._closing = True
        self._timer.cancel()
        try:
            try:
                if self._wire is not None: self._wire.close()
            finally:
                try: self._opening.close()
                finally:
                    self._key = self._session = b''
                    if self._owner is not None: self._owner.close()
        finally:
            self._closing = False

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
