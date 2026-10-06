"""Inactive fixed recipient witness with guarded original Windows ownership.

This is private child/channel provenance, not application or human identity,
permission, an OS sandbox, or a byte-delivery channel. Existing launch profiles
are unchanged. No PID lookup, caller handle, executable or pipe is accepted.
"""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass
import os
from pathlib import Path
from threading import RLock
from .broker_process import _ChildProcess, BrokerProcessError


@dataclass(frozen=True)
class ProcessChannelObservation:
    pid: int
    creation_time: int
    def __bool__(self): raise TypeError('Process provenance is not permission')


class _OwnershipApi:
    def __init__(self):
        if os.name != 'nt': raise BrokerProcessError('unsupported_platform')
        self.k = c.WinDLL('kernel32', use_last_error=True)
        # This Windows 10 API is exported by KernelBase, not kernel32 on every
        # supported system. Keep one typed hook surface for ownership tests.
        self._kernelbase = c.WinDLL('kernelbase', use_last_error=True)
        self.k.CompareObjectHandles = self._kernelbase.CompareObjectHandles
        signatures = {
            'GetCurrentProcess': ([], w.HANDLE),
            'DuplicateHandle': ([w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD], w.BOOL),
            'CompareObjectHandles': ([w.HANDLE, w.HANDLE], w.BOOL),
            'GetProcessId': ([w.HANDLE], w.DWORD),
            'GetProcessTimes': ([w.HANDLE, c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME)], w.BOOL),
            'GetHandleInformation': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            'GetFileType': ([w.HANDLE], w.DWORD),
            'IsProcessInJob': ([w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
            'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
            'GetExitCodeProcess': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            'TerminateJobObject': ([w.HANDLE, w.UINT], w.BOOL),
            'TerminateProcess': ([w.HANDLE, w.UINT], w.BOOL),
            'CloseHandle': ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def check(value):
        if not value: raise BrokerProcessError('native_ownership_failure')
        return value

    def duplicate(self, handle):
        output = w.HANDLE()
        process = self.k.GetCurrentProcess()
        self.check(self.k.DuplicateHandle(process, handle, process, c.byref(output), 0, False, 2))
        return output.value

    def flags(self, handle):
        output = w.DWORD()
        self.check(self.k.GetHandleInformation(handle, c.byref(output)))
        return output.value

    def identity(self, handle):
        pid = self.k.GetProcessId(handle)
        self.check(pid)
        creation, exit_time, kernel, user = (w.FILETIME() for _ in range(4))
        self.check(self.k.GetProcessTimes(handle, c.byref(creation), c.byref(exit_time), c.byref(kernel), c.byref(user)))
        timestamp = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        if type(pid) is not int or not 1 <= pid <= 2**32-1 or not 1 <= timestamp <= 2**64-1:
            raise BrokerProcessError('invalid_process_observation')
        return pid, timestamp

    def membership(self, process, job):
        output = w.BOOL()
        self.check(self.k.IsProcessInJob(process, job, c.byref(output)))
        return bool(output.value)

    def close(self, handle): self.check(self.k.CloseHandle(handle))


class _RecipientWitnessChild(_ChildProcess):
    """One fixed child; original kernel objects remain guarded until cleanup.

    Noninheritable duplicate handles are private comparison anchors. The input
    anchor closes with the input descriptor so it cannot prevent EOF. Job and
    process anchors close only after termination/join. Numeric equality alone
    never establishes pipe or process ownership. The containing process and its
    trusted launcher remain trusted; this does not resist hostile same-account
    code that can steal or alter handles inside that process.
    """
    def __init__(self):
        self._ownership_lock = RLock()
        self._ownership = _OwnershipApi()
        self._initializing = True
        self._owned = self._issued_owned = None
        self._anchors = {}
        self._seals = {}
        self._issued_anchors = self._anchor_snapshot = None
        self._issued_seals = self._seal_snapshot = None
        self._issued_observation = self._original_observation = self._observation_snapshot = None
        self._retired_snapshot = None
        self._input_closed = self._closed = self._cleanup_failed = False
        try:
            super().__init__()
            import msvcrt
            self._owned = (self.stdin_fd, self.stdout_fd, msvcrt.get_osfhandle(self.stdin_fd),
                           msvcrt.get_osfhandle(self.stdout_fd), self._process, self._job, self.pid)
            self._issued_owned = self._owned
            if any(type(value) is not int or value <= 0 for value in self._owned):
                raise BrokerProcessError('invalid_owned_handles')
            for name, handle in zip(('input', 'output', 'process', 'job'), self._owned[2:6]):
                self._anchors[name] = self._ownership.duplicate(handle)
                self._seals[name] = self._ownership.duplicate(handle)
                if self._ownership.flags(self._anchors[name]) & 1:
                    raise BrokerProcessError('inherited_ownership_anchor')
            self._issued_anchors = tuple(self._anchors.items())
            self._anchor_snapshot = self._issued_anchors
            self._issued_seals = tuple(self._seals.items())
            self._seal_snapshot = self._issued_seals
            identity = self._ownership.identity(self._owned[4])
            if identity[0] != self._owned[6]: raise BrokerProcessError('process_identity_mismatch')
            self._issued_observation = ProcessChannelObservation(*identity)
            self._original_observation = self._issued_observation
            self._observation_snapshot = identity
            self._initializing = False
            self._validate()
        except BaseException:
            self.close()
            raise
        finally:
            self._initializing = False

    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_recipient_entry.py')

    def _fields(self):
        if (type(self._closed) is not bool or self._closed or type(self._input_closed) is not bool
                or type(self._cleanup_failed) is not bool or self._cleanup_failed
                or type(self._owned) is not tuple or len(self._owned) != 7
                or self._owned is not self._issued_owned
                or any(type(value) is not int for value in self._owned)
                or type(self._fds) is not set
                or self._fds != ({self._owned[1]} if self._input_closed else {self._owned[0], self._owned[1]})
                or type(self.stdin_fd) is not int or self.stdin_fd != self._owned[0]
                or type(self.stdout_fd) is not int or self.stdout_fd != self._owned[1]
                or type(self._process) is not int or self._process != self._owned[4]
                or type(self._job) is not int or self._job != self._owned[5]
                or type(self.pid) is not int or self.pid != self._owned[6]
                or type(self._anchors) is not dict or type(self._issued_anchors) is not tuple
                or self._issued_anchors is not self._anchor_snapshot
                or type(self._seals) is not dict or self._issued_seals is not self._seal_snapshot
                or tuple(self._seals.items()) != tuple((name, handle) for name, handle in self._issued_seals
                                                      if name != 'input' or not self._input_closed)
                or tuple(self._anchors.items()) != tuple((name, handle) for name, handle in self._issued_anchors
                                                       if name != 'input' or not self._input_closed)
                or any(type(handle) is not int or handle <= 0 for handle in self._anchors.values())
                or type(self._issued_observation) is not ProcessChannelObservation
                or self._issued_observation is not self._original_observation
                or type(self._issued_observation.pid) is not int
                or type(self._issued_observation.creation_time) is not int
                or (self._issued_observation.pid, self._issued_observation.creation_time) != self._observation_snapshot):
            raise BrokerProcessError('changed_owned_channel')

    def _objects(self):
        import msvcrt
        names = ('output', 'process', 'job') if self._input_closed else ('input', 'output', 'process', 'job')
        for name in names:
            index = {'input': 2, 'output': 3, 'process': 4, 'job': 5}[name]
            handle, anchor, seal = self._owned[index], self._anchors[name], self._seals[name]
            if (not self._ownership.k.CompareObjectHandles(handle, anchor)
                    or not self._ownership.k.CompareObjectHandles(anchor, seal)
                    or self._ownership.flags(handle) & 1 or self._ownership.flags(anchor) & 1
                    or self._ownership.flags(seal) & 1):
                raise BrokerProcessError('changed_owned_object')
        for name, index in (('input', 0), ('output', 1)):
            if name == 'input' and self._input_closed: continue
            fd, handle = self._owned[index], self._owned[index+2]
            if (fd not in self._fds or msvcrt.get_osfhandle(fd) != handle
                    or os.get_inheritable(fd) or os.get_blocking(fd)
                    or self._ownership.k.GetFileType(handle) != 3):
                raise BrokerProcessError('changed_owned_pipe')

    def _validate(self, *, retiring=False):
        with self._ownership_lock:
            if type(retiring) is not bool or (retiring and self._input_closed is not True):
                raise BrokerProcessError('invalid_retirement_state')
            self._fields(); self._objects()
            if self._ownership.identity(self._owned[4]) != self._observation_snapshot:
                raise BrokerProcessError('changed_process_identity')
            state = self._ownership.k.WaitForSingleObject(self._owned[4], 0)
            if (not self._ownership.membership(self._owned[4], self._owned[5])
                    or state not in ((0, 258) if retiring else (258,))):
                raise BrokerProcessError('recipient_process_unavailable')
            self._fields(); self._objects()

    def _observe(self):
        with self._ownership_lock:
            self._validate()
            result = self._issued_observation
            self._validate()
            return result

    def poll(self):
        with self._ownership_lock:
            self._fields(); self._objects()
            if self._ownership.identity(self._owned[4]) != self._observation_snapshot:
                raise BrokerProcessError('changed_process_identity')
            status = self._ownership.k.WaitForSingleObject(self._owned[4], 0)
            if status == 258: result = None
            elif status == 0:
                code = w.DWORD()
                self._ownership.check(self._ownership.k.GetExitCodeProcess(self._owned[4], c.byref(code)))
                result = code.value
            else: raise BrokerProcessError('process_query_failed')
            self._fields(); self._objects()
            return result

    def close_input(self):
        with self._ownership_lock:
            try:
                if self._input_closed: raise BrokerProcessError('input_already_closed')
                self._validate()
                fd, handle, seal = self._owned[0], self._anchors['input'], self._seals['input']
                # Closing both owned write handles is essential for child EOF.
                os.close(fd); self._fds.remove(fd)
                failed = False
                for guard in (handle, seal):
                    try: self._ownership.close(guard)
                    except BaseException: failed = True
                del self._anchors['input']
                del self._seals['input']
                self._input_closed = True
                if failed: raise BrokerProcessError('process_cleanup_failed')
                self._fields(); self._objects()
            except BaseException:
                self._cleanup_failed = True
                raise BrokerProcessError('process_cleanup_failed') from None

    def close(self):
        with self._ownership_lock:
            if self._closed:
                if self._cleanup_failed: raise BrokerProcessError('process_cleanup_failed')
                return
            changed = False
            if not self._initializing:
                try: self._fields(); self._objects()
                except BaseException: changed = True
            self._closed = True
            if self._initializing and self._observation_snapshot is None:
                # Before publication, original launch fields cannot have escaped.
                failed = False
                for handle in (*self._anchors.values(), *self._seals.values()):
                    try: self._ownership.close(handle)
                    except BaseException: failed = True
                self._anchors = {}
                self._seals = {}
                try: _ChildProcess.close(self)
                except BaseException: failed = True
                self._cleanup_failed |= failed
                if failed: raise BrokerProcessError('process_cleanup_failed') from None
                return
            failed = self._cleanup_failed or changed
            original = self._issued_owned
            anchors = dict(self._anchor_snapshot)
            seals = dict(self._seal_snapshot)
            if self._input_closed:
                anchors.pop('input', None); seals.pop('input', None)
            def safe_handles(name, index):
                handles = (original[index], anchors[name], seals[name])
                owned = set()
                for first, second in ((0, 1), (0, 2), (1, 2)):
                    try:
                        if self._ownership.k.CompareObjectHandles(handles[first], handles[second]):
                            owned.update((handles[first], handles[second]))
                    except BaseException: pass
                return owned
            safe = {name: safe_handles(name, index) for name, index in
                    (('input', 2), ('output', 3), ('process', 4), ('job', 5)) if name in anchors}
            if any(len(value) != 3 for value in safe.values()): failed = True
            try:
                # A process identity query is against owned original handles,
                # never OpenProcess(PID). It permits safe termination even when
                # a mutable public field points at a foreign process or Job.
                process = None
                for candidate in safe['process']:
                    try:
                        if self._ownership.identity(candidate) == self._observation_snapshot:
                            process = candidate; break
                    except BaseException: pass
                if process is None: raise BrokerProcessError('owned_process_unavailable')
                safe['job'] = safe_handles('job', 5)
                if len(safe['job']) != 3: failed = True
                job = next(iter(safe['job']), None)
                if job is not None and self._ownership.membership(process, job):
                    self._ownership.check(self._ownership.k.TerminateJobObject(job, 1))
                else:
                    failed = True
                    self._ownership.check(self._ownership.k.TerminateProcess(process, 1))
                if self._ownership.k.WaitForSingleObject(process, 1000) != 0:
                    raise BrokerProcessError('process_cleanup_failed')
                code = w.DWORD()
                self._ownership.check(self._ownership.k.GetExitCodeProcess(process, c.byref(code)))
                self._exit = code.value
            except BaseException: failed = True
            import msvcrt
            for name, index in (('input', 0), ('output', 1)):
                if name not in anchors: continue
                fd, handle = original[index], original[index+2]
                # Native termination/identity hooks may have changed ownership
                # after the initial guard query. Re-observe before closing.
                safe[name] = safe_handles(name, index+2)
                if len(safe[name]) != 3: failed = True
                try:
                    if msvcrt.get_osfhandle(fd) != handle or handle not in safe[name]:
                        raise BrokerProcessError('foreign_pipe_substitution')
                    os.close(fd)
                    if type(self._fds) is set: self._fds.discard(fd)
                    else: failed = True
                except BaseException: failed = True
                for guard in (anchors[name], seals[name]):
                    if guard in safe[name]:
                        try: self._ownership.close(guard)
                        except BaseException: failed = True
            for name, index in (('job', 5), ('process', 4)):
                safe[name] = safe_handles(name, index)
                if len(safe[name]) != 3: failed = True
                for handle in (original[index], anchors[name], seals[name]):
                    if handle in safe[name]:
                        try: self._ownership.close(handle)
                        except BaseException: failed = True
            # Check callback-time field mutations before retiring our own maps.
            if (self._owned is not self._issued_owned
                    or self._issued_anchors is not self._anchor_snapshot
                    or type(self._anchors) is not dict or self._anchors != anchors
                    or self._issued_seals is not self._seal_snapshot
                    or type(self._seals) is not dict or self._seals != seals
                    or type(self.stdin_fd) is not int or self.stdin_fd != original[0]
                    or type(self.stdout_fd) is not int or self.stdout_fd != original[1]
                    or type(self.pid) is not int or self.pid != original[6]
                    or self._process != original[4] or self._job != original[5]
                    or self._issued_observation is not self._original_observation
                    or type(self._issued_observation) is not ProcessChannelObservation
                    or type(self._issued_observation.pid) is not int
                    or type(self._issued_observation.creation_time) is not int
                    or (self._issued_observation.pid, self._issued_observation.creation_time) != self._observation_snapshot):
                failed = True
            # Foreign values are left untouched; retired fields never reopen.
            self._process = self._job = None
            self._anchors = {}
            self._seals = {}
            self._cleanup_failed = bool(failed)
            if failed: raise BrokerProcessError('process_cleanup_failed') from None
            self._retired_snapshot = (self._exit, self._input_closed)

    def _retired(self):
        """Recheck terminal metadata only; never reestablish a live channel."""
        with self._ownership_lock:
            original = self._issued_owned
            value = self._issued_observation
            if (self._closed is not True or self._cleanup_failed is not False
                    or self._process is not None or self._job is not None
                    or type(self._anchors) is not dict or self._anchors
                    or type(self._seals) is not dict or self._seals
                    or type(self._fds) is not set or self._fds
                    or self._owned is not original or type(original) is not tuple
                    or self._issued_anchors is not self._anchor_snapshot
                    or self._issued_seals is not self._seal_snapshot
                    or type(self._input_closed) is not bool
                    or value is not self._original_observation or type(value) is not ProcessChannelObservation
                    or type(value.pid) is not int or type(value.creation_time) is not int
                    or (value.pid, value.creation_time) != self._observation_snapshot
                    or type(self.stdin_fd) is not int or self.stdin_fd != original[0]
                    or type(self.stdout_fd) is not int or self.stdout_fd != original[1]
                    or type(self.pid) is not int or self.pid != original[6]
                    or type(self._exit) is not int or type(self._retired_snapshot) is not tuple
                    or len(self._retired_snapshot) != 2
                    or type(self._retired_snapshot[0]) is not int
                    or type(self._retired_snapshot[1]) is not bool
                    or (self._exit, self._input_closed) != self._retired_snapshot):
                raise BrokerProcessError('process_cleanup_failed')
