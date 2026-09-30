"""Inactive generated-fixture ownership and one-shot metadata binding.

No content-read or delivery API. Used only by the opt-in observation diagnostic,
never by /check or the protected fixture reader.
A matching receipt is evidence only, never permission to perform an operation.
"""
from dataclasses import dataclass
import os
import ctypes
import secrets
import re
import tempfile
from threading import RLock
from time import monotonic

from .broker_protocol import _binding, MAX_DATA_BYTES
from .file_read_schema import inspect_file_read_proposal
from .structured_proposal import StructuredActionProposal
from .windows_identity import _Native

_FIXTURE = b'SecurityBrightness synthetic fixture\n'
_LIFETIME = 60


class BrokerResourceError(ValueError):
    pass


@dataclass(frozen=True)
class BrokerResourceDescription:
    session: str
    resource_token: str
    volume_serial: int
    file_id: bytes
    size_bytes: int
    display_path: str

    def __bool__(self):
        raise TypeError('A resource description is not authority')


@dataclass(frozen=True)
class BrokerResourceBinding:
    session: str
    canonical_binding: bytes

    def __bool__(self):
        raise TypeError('Resource binding is not permission')


@dataclass(frozen=True)
class BrokerResourceMatch:
    session: str
    canonical_binding: bytes
    meaning: str = 'metadata matched; no read or permission'

    def __bool__(self):
        raise TypeError('Matching metadata is not permission')


def _description(value):
    return (value.session, value.resource_token, value.volume_serial,
            value.file_id, value.size_bytes, value.display_path)


class BrokerFixtureOwner:
    """Own one newly created synthetic file and its original, noninherited handle.

    No caller pathname, file contents, handle, token or lifetime is accepted.
    Trusted test/bootstrap code must close this object (prefer a context manager).
    Python process integrity remains trusted; this is not a hostile-code sandbox.
    """
    def __init__(self):
        self._lock = RLock()
        self._fd = None
        self._state = 'new'
        self._issued = self._issued_snapshot = None
        try:
            self._native = _Native()
            self._session = secrets.token_hex(32)
            self._token = secrets.token_hex(32)
            if (type(self._session) is not str or type(self._token) is not str
                    or re.fullmatch('[0-9a-f]{64}', self._session) is None
                    or re.fullmatch('[0-9a-f]{64}', self._token) is None
                    or self._session == self._token):
                raise BrokerResourceError('invalid_randomness')
            # Atomic CREATE_NEW + DELETE_ON_CLOSE: no Python-finalizer window,
            # directory artifact, path-based cleanup, reopen or overwrite fallback.
            self._path = os.path.join(tempfile.gettempdir(), 'sb-broker-fixture-'+self._token+'.txt')
            handle = self._native.k.CreateFileW(self._path, 0x40010080, 0, None, 1, 0x04200100, None)
            if handle in (None, ctypes.c_void_p(-1).value):
                raise BrokerResourceError('fixture_creation_failed')
            try:
                import msvcrt
                self._fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            except BaseException:
                self._native.close(handle)
                raise
            if os.get_inheritable(self._fd):
                raise BrokerResourceError('inherited_resource')
            offset = 0
            while offset < len(_FIXTURE):
                written = os.write(self._fd, _FIXTURE[offset:])
                if written <= 0:
                    raise BrokerResourceError('fixture_creation_failed')
                offset += written
            os.fsync(self._fd)
            import msvcrt
            self._handle = msvcrt.get_osfhandle(self._fd)
            self._native.local_ntfs(self._handle)
            self._metadata = self._native.metadata(self._handle, False)
            if self._metadata[2] != len(_FIXTURE):
                raise BrokerResourceError('fixture_creation_failed')
            display = self._native.display(self._handle)
            if type(display) is not str or not 1 <= len(display) <= 32767 or any(ord(ch) < 32 for ch in display):
                raise BrokerResourceError('invalid_display')
            self._description = BrokerResourceDescription(self._session, self._token,
                self._metadata[0], self._metadata[1], self._metadata[2], display)
            self._description_snapshot = _description(self._description)
            self._deadline = monotonic() + _LIFETIME
            self._validate()
        except BaseException:
            self.close()
            raise BrokerResourceError('fixture_creation_failed') from None

    def _validate(self):
        if (self._state not in {'new', 'bound'} or monotonic() >= self._deadline
                or _description(self._description) != self._description_snapshot
                or self._native.metadata(self._handle, False) != self._metadata):
            raise BrokerResourceError('resource_unavailable')
        # Native metadata calls must not silently extend the lifetime.
        if monotonic() >= self._deadline:
            raise BrokerResourceError('resource_unavailable')

    def describe(self):
        with self._lock:
            try:
                self._validate()
                return self._description
            except Exception:
                self.close()
                raise BrokerResourceError('resource_unavailable') from None

    def _request(self, application_id, proposal, decision_id):
        if type(proposal) is not StructuredActionProposal:
            raise BrokerResourceError('invalid_proposal')
        intent = inspect_file_read_proposal(proposal)
        if not self._metadata[2] <= intent.max_bytes <= MAX_DATA_BYTES:
            raise BrokerResourceError('unsupported_bound')
        return _binding(dict(application_id=application_id, proposal_id=intent.proposal_id,
            resource_token=self._token, decision_id=decision_id, max_bytes=intent.max_bytes))

    def bind(self, application_id, proposal, decision_id):
        with self._lock:
            try:
                if self._state != 'new':
                    raise BrokerResourceError('already_bound')
                snapshot = self._request(application_id, proposal, decision_id)
                self._validate()
                issued = BrokerResourceBinding(self._session, snapshot)
                self._issued, self._issued_snapshot = issued, (self._session, snapshot)
                self._state = 'bound'
                return issued
            except Exception:
                self.close()
                raise BrokerResourceError('binding_rejected') from None

    def inspect_binding(self, binding, application_id, proposal, decision_id):
        """Non-consuming metadata sample, never an authorization lease."""
        with self._lock:
            try:
                if (self._state != 'bound' or type(binding) is not BrokerResourceBinding
                        or binding is not self._issued
                        or (binding.session,binding.canonical_binding) != self._issued_snapshot
                        or self._request(application_id,proposal,decision_id) != self._issued_snapshot[1]):
                    raise BrokerResourceError('binding_unavailable')
                self._validate()
                return self._description
            except Exception:
                self.close()
                raise BrokerResourceError('binding_rejected') from None

    def verify_once(self, binding, application_id, proposal, decision_id):
        """Consume metadata evidence, close ownership, return no contents.

        This diagnostic is deliberately not a read admission or grant interface.
        Failed attempts retire the owner too; no retry/rebind/restore exists.
        """
        with self._lock:
            try:
                if (self._state != 'bound' or type(binding) is not BrokerResourceBinding
                        or binding is not self._issued
                        or (binding.session, binding.canonical_binding) != self._issued_snapshot):
                    raise BrokerResourceError('binding_unavailable')
                snapshot = self._request(application_id, proposal, decision_id)
                if snapshot != self._issued_snapshot[1]:
                    raise BrokerResourceError('binding_mismatch')
                self._validate()
                result = BrokerResourceMatch(self._session, snapshot)
                self.close()  # No receipt if cleanup fails.
                if monotonic() >= self._deadline:
                    raise BrokerResourceError('expired')
                return result
            except Exception:
                self.close()
                raise BrokerResourceError('binding_rejected') from None

    def close(self):
        with self._lock:
            self._state = 'closed'
            self._issued = self._issued_snapshot = None
            failed = False
            if self._fd is not None:
                fd, self._fd = self._fd, None
                try:
                    os.close(fd)
                except Exception:
                    failed = True
            if failed:
                raise BrokerResourceError('resource_cleanup_failed')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
