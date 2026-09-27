"""Inactive Windows metadata-only retained-handle identity collector.

Trusted adapter entry point, never called by /check. No content reads or writes.
Native identity is tied to retained handles, not normalization of requester text.
"""
import ctypes as c
from ctypes import wintypes as w
import os
import re
from threading import RLock

from .resource_binding import AdapterObservationSession, OperationBindingMatch, WindowsFileObservation


class ResourceIdentityError(ValueError):
    """Fixed non-sensitive adapter failure; never includes a user path."""


class _UnicodeString(c.Structure):
    _fields_ = [("Length", w.USHORT), ("MaximumLength", w.USHORT), ("Buffer", w.LPWSTR)]


class _ObjectAttributes(c.Structure):
    _fields_ = [("Length", w.ULONG), ("RootDirectory", w.HANDLE),
                ("ObjectName", c.POINTER(_UnicodeString)), ("Attributes", w.ULONG),
                ("SecurityDescriptor", c.c_void_p), ("SecurityQualityOfService", c.c_void_p)]


class _IoStatus(c.Structure):
    _fields_ = [("Status", c.c_void_p), ("Information", c.c_size_t)]


class _FileId(c.Structure):
    _fields_ = [("volume", c.c_ulonglong), ("identifier", c.c_ubyte * 16)]


class _Basic(c.Structure):
    _fields_ = [("creation", c.c_longlong), ("access", c.c_longlong),
                ("write", c.c_longlong), ("change", c.c_longlong), ("attributes", w.DWORD)]


class _Standard(c.Structure):
    _fields_ = [("allocation", c.c_longlong), ("size", c.c_longlong),
                ("links", w.DWORD), ("delete_pending", c.c_ubyte), ("directory", c.c_ubyte)]


class _Device(c.Structure):
    _fields_ = [("device_type", w.ULONG), ("characteristics", w.ULONG)]


def _path_parts(path):
    if type(path) is not str or len(path) > 32760:
        raise ResourceIdentityError("unsupported_path")
    try:
        if len(path.encode("utf-16-le")) // 2 > 32760:
            raise ValueError
    except (UnicodeError, ValueError):
        raise ResourceIdentityError("unsupported_path") from None
    # This selects a narrow syntax. It does NOT establish identity.
    value = path.replace("/", "\\")
    if not re.match(r"^[A-Za-z]:\\", value):
        raise ResourceIdentityError("unsupported_path")
    parts = value[3:].split("\\")
    if not parts or len(parts) > 128:
        raise ResourceIdentityError("unsupported_path")
    for part in parts:
        if (not part or part in {".", ".."} or part[-1] in " ."
                or len(part.encode("utf-16-le")) // 2 > 255
                or any(ord(ch) < 32 or ord(ch) == 127 or ch in ':*?"<>|' for ch in part)
                or re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", part.split(".")[0], re.I)):
            raise ResourceIdentityError("unsupported_path")
    return value[:3], parts


class _Native:
    def __init__(self):
        if os.name != "nt":
            raise ResourceIdentityError("unsupported_platform")
        self.k = c.WinDLL("kernel32", use_last_error=True)
        self.n = c.WinDLL("ntdll")
        self.k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        self.k.CreateFileW.restype = w.HANDLE
        self.k.CloseHandle.argtypes = [w.HANDLE]
        self.k.CloseHandle.restype = w.BOOL
        self.k.GetFileInformationByHandleEx.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        self.k.GetFileInformationByHandleEx.restype = w.BOOL
        self.k.GetFileType.argtypes = [w.HANDLE]
        self.k.GetFileType.restype = w.DWORD
        self.k.GetVolumeInformationByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD,
                                                        c.c_void_p, c.c_void_p, c.c_void_p, w.LPWSTR, w.DWORD]
        self.k.GetVolumeInformationByHandleW.restype = w.BOOL
        self.k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
        self.k.GetFinalPathNameByHandleW.restype = w.DWORD
        self.n.NtCreateFile.argtypes = [c.POINTER(w.HANDLE), w.ULONG, c.POINTER(_ObjectAttributes),
                                      c.POINTER(_IoStatus), c.c_void_p, w.ULONG, w.ULONG, w.ULONG,
                                      w.ULONG, c.c_void_p, w.ULONG]
        self.n.NtCreateFile.restype = w.LONG
        self.n.NtQueryVolumeInformationFile.argtypes = [w.HANDLE, c.POINTER(_IoStatus), c.c_void_p, w.ULONG, c.c_int]
        self.n.NtQueryVolumeInformationFile.restype = w.LONG

    def root(self, root):
        # Attributes only. No FILE_READ_DATA/GENERIC_READ, writes or creation.
        handle = self.k.CreateFileW(root, 0x100080, 7, None, 3, 0x02200000, None)
        if handle in (None, c.c_void_p(-1).value):
            raise ResourceIdentityError("resource_unavailable")
        return handle

    def child(self, parent, name, directory):
        buffer = c.create_unicode_buffer(name)
        length = len(name.encode("utf-16-le"))
        text = _UnicodeString(length, length + 2, c.cast(buffer, w.LPWSTR))
        attributes = _ObjectAttributes(c.sizeof(_ObjectAttributes), parent, c.pointer(text), 0x40, None, None)
        handle, status = w.HANDLE(), _IoStatus()
        options = 0x200000 | 0x20 | (1 if directory else 0x40)
        # Parent traversal is anchored to a handle. Final file requests conservative
        # sharing flags, but attributes-only access does not exclude writers.
        # Neither these flags nor timestamps prove content stability.
        share = 7 if directory else 1
        result = self.n.NtCreateFile(c.byref(handle), 0x100080, c.byref(attributes), c.byref(status),
                                    None, 0, share, 1, options, None, 0)
        if result < 0:
            if handle.value:
                self.close(handle.value)
            raise ResourceIdentityError("resource_unavailable")
        if not handle.value or status.Information != 1:  # FILE_OPENED only
            if handle.value:
                self.close(handle.value)
            raise ResourceIdentityError("resource_unavailable")
        return handle.value

    def query(self, handle, kind, structure):
        value = structure()
        if not self.k.GetFileInformationByHandleEx(handle, kind, c.byref(value), c.sizeof(value)):
            raise ResourceIdentityError("metadata_unavailable")
        return value

    def metadata(self, handle, directory):
        if self.k.GetFileType(handle) != 1:
            raise ResourceIdentityError("unsupported_resource")
        basic = self.query(handle, 0, _Basic)
        standard = self.query(handle, 1, _Standard)
        identity = self.query(handle, 18, _FileId)
        if (basic.attributes & 0x400 or bool(standard.directory) != directory
                or standard.delete_pending or standard.size < 0 or basic.change < 0):
            raise ResourceIdentityError("unsupported_resource")
        if directory:
            sensitive = self.query(handle, 23, w.DWORD)
            if sensitive.value != 0:
                raise ResourceIdentityError("unsupported_case_policy")
        elif standard.links != 1:
            raise ResourceIdentityError("unsupported_hard_links")
        return (identity.volume, bytes(identity.identifier), standard.size,
                basic.change, basic.write, basic.creation, basic.attributes, standard.links)

    def local_ntfs(self, handle):
        filesystem = c.create_unicode_buffer(64)
        if not self.k.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, filesystem, 64):
            raise ResourceIdentityError("metadata_unavailable")
        device, status = _Device(), _IoStatus()
        result = self.n.NtQueryVolumeInformationFile(handle, c.byref(status), c.byref(device), c.sizeof(device), 4)
        if result < 0 or filesystem.value != "NTFS" or device.characteristics & 0x10:
            raise ResourceIdentityError("unsupported_filesystem")

    def display(self, handle):
        buffer = c.create_unicode_buffer(32768)
        count = self.k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not count or count >= len(buffer):
            raise ResourceIdentityError("metadata_unavailable")
        return buffer.value

    def close(self, handle):
        if not self.k.CloseHandle(handle):
            raise ResourceIdentityError("handle_close_failed")


class WindowsIdentityCollector:
    """Explicit metadata acquisition only; retains handles until release/close.

    Use only for trusted adapter selections. Not safe as a requester-controlled
    HTTP endpoint. Unsupported platforms/features/errors fail without fallback.
    """
    def __init__(self, *, capacity=16):
        if type(capacity) is not int or not 1 <= capacity <= 64:
            raise ValueError("collector capacity must be between 1 and 64")
        self._session = AdapterObservationSession(capacity=capacity)
        try:
            self._native = _Native()
        except Exception:
            raise ResourceIdentityError("native_adapter_unavailable") from None
        self._held = {}
        self._lock = RLock()
        self._closed = False

    def collect(self, path):
        root, parts = _path_parts(path)
        with self._lock:
            if self._closed:
                raise ResourceIdentityError("collector_closed")
            handles, parent_ids = [], []
            observation = None
            try:
                handles.append(self._native.root(root))
                self._native.local_ntfs(handles[0])
                for name in parts:
                    parent_ids.append(self._native.metadata(handles[-1], True)[:2])
                    handles.append(self._native.child(handles[-1], name, len(handles) < len(parts)))
                metadata = self._native.metadata(handles[-1], False)
                self._native.local_ntfs(handles[-1])
                for handle, expected in zip(handles[:-1], parent_ids):
                    if self._native.metadata(handle, True)[:2] != expected:
                        raise ResourceIdentityError("resource_changed")
                if self._native.metadata(handles[-1], False) != metadata:
                    raise ResourceIdentityError("resource_changed")
                observation = self._session.record_observation(
                    volume_serial=metadata[0], file_id=metadata[1], size_bytes=metadata[2], change_time=metadata[3],
                    display_path=self._native.display(handles[-1]), filesystem="local_ntfs",
                    file_kind="regular", reparse_status="excluded")
                self._held[observation.observation_id] = (observation, handles, parent_ids, metadata)
                return observation
            except Exception as exc:
                if observation is not None:
                    self._session.release(observation)
                cleanup_failed = False
                for handle in reversed(handles):
                    try:
                        self._native.close(handle)
                    except Exception:
                        cleanup_failed = True
                if cleanup_failed:
                    self._closed = True
                    self._session.close()
                    raise ResourceIdentityError("handle_close_failed") from None
                if isinstance(exc, ResourceIdentityError):
                    raise
                raise ResourceIdentityError("collection_failed") from None

    def revalidate(self, observation):
        with self._lock:
            key = observation.observation_id if type(observation) is WindowsFileObservation else None
            entry = self._held.get(key) if type(key) is str else None
            if entry is None or entry[0] is not observation or self._closed:
                return False
            _, handles, parents, metadata = entry
            try:
                if self._native.metadata(handles[-1], False) != metadata:
                    raise ResourceIdentityError("resource_changed")
                for handle, expected in zip(handles[:-1], parents):
                    if self._native.metadata(handle, True)[:2] != expected:
                        raise ResourceIdentityError("resource_changed")
                return True
            except Exception:
                self.release(observation)
                return False

    def bind(self, application_id, proposal, observation):
        with self._lock:
            if not self.revalidate(observation):
                raise ResourceIdentityError("resource_changed")
            return self._session.bind(application_id, proposal, observation)

    def matches(self, binding, application_id, proposal, observation):
        with self._lock:
            if not self.revalidate(observation):
                return OperationBindingMatch(False, "resource_unavailable")
            return self._session.matches(binding, application_id, proposal, observation)

    def release(self, observation):
        with self._lock:
            key = observation.observation_id if type(observation) is WindowsFileObservation else None
            entry = self._held.get(key) if type(key) is str else None
            if entry is None or entry[0] is not observation:
                return
            self._held.pop(key)
            self._session.release(observation)
            failed = False
            for handle in reversed(entry[1]):
                try:
                    self._native.close(handle)
                except Exception:
                    failed = True
            if failed:
                self._closed = True
                self._session.close()
                raise ResourceIdentityError("handle_close_failed")

    def close(self):
        with self._lock:
            self._closed = True
            self._session.close()
            failed = False
            for observation, *_ in list(self._held.values()):
                try:
                    self.release(observation)
                except Exception:
                    failed = True
            if failed:
                self._closed = True
                self._session.close()
                raise ResourceIdentityError("handle_close_failed")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
