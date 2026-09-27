"""Inactive adapter-observation and exact operation-binding contract prototype.

All metadata is supplied by trusted adapter-side Python code; this module performs
no Windows calls and cannot establish that a report is truthful. No authority or
human decision is accepted or issued. Requester dictionaries are never imported.
"""
from dataclasses import dataclass, field
from threading import RLock
from uuid import uuid4

from .file_read_schema import inspect_file_read_proposal
from .proposal_identity import proposal_identity
from .validation import application_id as validate_application_id


def _uint64(value, name):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value


@dataclass(frozen=True)
class WindowsFileObservation:
    session_id: str
    observation_id: str
    volume_serial: int
    file_id: bytes = field(repr=False)
    size_bytes: int
    change_time: int
    display_path: str = field(repr=False)

    def __bool__(self):
        raise TypeError("An observation is not verified authority or permission")


@dataclass(frozen=True)
class FileReadOperationBinding:
    session_id: str
    observation_id: str
    application_id: str
    proposal_id: str
    max_bytes: int

    def __bool__(self):
        raise TypeError("An operation binding is not permission")


@dataclass(frozen=True)
class OperationBindingMatch:
    matches: bool
    reason: str

    def __bool__(self):
        raise TypeError("A matching operation binding is not permission")


class AdapterObservationSession:
    """Bounded in-memory model of adapter-owned observation lifetimes.

    Not an OS adapter or a security boundary against hostile in-process Python.
    Capacity counts all issued observation IDs, including released tombstones.
    Exactly one binding is outstanding per observation; rebinding supersedes it.
    """
    def __init__(self, *, capacity=128):
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError("capacity must be between 1 and 4096")
        self._capacity = capacity
        self._session_id = str(uuid4())
        self._observations = {}
        self._bindings = {}
        self._lock = RLock()
        self._closed = False

    def record_observation(self, *, volume_serial, file_id, size_bytes, change_time,
                           display_path, filesystem, file_kind, reparse_status):
        """Record a supplied adapter report, not a verified OS observation.

        Only a future collector may substantiate the explicit local-NTFS,
        regular-file, no-reparse profile. This routine does not check a path.
        """
        _uint64(volume_serial, "volume_serial")
        _uint64(size_bytes, "size_bytes")
        _uint64(change_time, "change_time")
        if type(file_id) is not bytes or len(file_id) != 16:
            raise ValueError("file_id must be exactly 16 immutable bytes")
        if (type(display_path) is not str or not display_path.strip()
                or len(display_path) > 32767
                or any(ord(char) < 32 or ord(char) == 127 for char in display_path)):
            raise ValueError("invalid display path")
        try:
            display_path.encode("utf-8")
            if len(display_path.encode("utf-16-le")) // 2 > 32767:
                raise ValueError("display path is too long")
        except UnicodeError:
            raise ValueError("invalid display path") from None
        if filesystem != "local_ntfs" or file_kind != "regular" or reparse_status != "excluded":
            raise ValueError("unsupported or incomplete adapter observation profile")
        with self._lock:
            if self._closed:
                raise ValueError("observation session is closed")
            if len(self._observations) >= self._capacity:
                raise ValueError("observation capacity reached")
            observation_id = str(uuid4())
            if observation_id in self._observations:
                raise RuntimeError("duplicate observation identity")
            observation = WindowsFileObservation(self._session_id, observation_id, volume_serial,
                                                 file_id, size_bytes, change_time, display_path)
            self._observations[observation_id] = observation
            return observation

    def _live(self, observation):
        return (not self._closed and type(observation) is WindowsFileObservation
                and type(observation.observation_id) is str
                and observation.session_id == self._session_id
                and self._observations.get(observation.observation_id) is observation)

    def release(self, observation):
        """Invalidate the model's observation; does not close any actual OS handle."""
        with self._lock:
            if self._live(observation):
                self._observations[observation.observation_id] = None
                self._bindings.pop(observation.observation_id, None)

    def replace_observation(self, observation, **report):
        """Retire old evidence first; even a failed replacement cannot restore it."""
        with self._lock:
            if not self._live(observation):
                raise ValueError("observation is not live in this session")
            self.release(observation)
            return self.record_observation(**report)

    def bind(self, application_id, proposal, observation):
        application_id = validate_application_id(application_id)
        intent = inspect_file_read_proposal(proposal)
        with self._lock:
            if not self._live(observation):
                raise ValueError("observation is not live in this session")
            if observation.size_bytes > intent.max_bytes:
                raise ValueError("observed size exceeds proposed byte limit")
            binding = FileReadOperationBinding(self._session_id, observation.observation_id,
                                               application_id, intent.proposal_id, intent.max_bytes)
            self._bindings[observation.observation_id] = binding
            return binding

    def matches(self, binding, application_id, proposal, observation):
        application_id = validate_application_id(application_id)
        # Reject unsupported effects/operations even for a caller-crafted binding.
        inspect_file_read_proposal(proposal)
        with self._lock:
            if not self._live(observation):
                return OperationBindingMatch(False, "observation_unavailable")
            if (not isinstance(binding, FileReadOperationBinding)
                    or self._bindings.get(observation.observation_id) is not binding):
                return OperationBindingMatch(False, "unknown_or_superseded_binding")
            if application_id != binding.application_id:
                return OperationBindingMatch(False, "application_mismatch")
            if proposal_identity(proposal) != binding.proposal_id:
                return OperationBindingMatch(False, "proposal_changed")
            return OperationBindingMatch(True, "exact_operation_binding")

    def close(self):
        """Permanently invalidate all model evidence; no OS handles exist here."""
        with self._lock:
            self._closed = True
            self._bindings.clear()
            self._observations.clear()
