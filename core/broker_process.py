"""Private Windows launcher for the inactive fixed broker entry; not a sandbox.

Atomic job assignment prevents an unassigned-child window on coordinator death.
The child retains the account's access rights; no arbitrary launch API is exposed.
"""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
import sys


class BrokerProcessError(RuntimeError):
    pass


class _BasicLimits(c.Structure):
    _fields_ = [('process_time', c.c_longlong), ('job_time', c.c_longlong), ('flags', w.DWORD),
                ('minimum_ws', c.c_size_t), ('maximum_ws', c.c_size_t), ('active_processes', w.DWORD),
                ('affinity', c.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]


class _IoCounters(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]


class _ExtendedLimits(c.Structure):
    _fields_ = [('basic', _BasicLimits), ('io', _IoCounters), ('process_memory', c.c_size_t),
                ('job_memory', c.c_size_t), ('peak_process', c.c_size_t), ('peak_job', c.c_size_t)]


class _Startup(c.Structure):
    _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR), ('title', w.LPWSTR),
                ('x', w.DWORD), ('y', w.DWORD), ('xsize', w.DWORD), ('ysize', w.DWORD),
                ('xchars', w.DWORD), ('ychars', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                ('show', w.WORD), ('reserved2_size', w.WORD), ('reserved2', c.c_void_p),
                ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]


class _StartupEx(c.Structure):
    _fields_ = [('startup', _Startup), ('attributes', c.c_void_p)]


class _ProcessInfo(c.Structure):
    _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]


def _entry():
    return Path(__file__).resolve().with_name('broker_child_entry.py')


class _WinApi:
    def __init__(self):
        if os.name != 'nt':
            raise BrokerProcessError('unsupported_platform')
        self.k = c.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([c.c_void_p, w.LPCWSTR], w.HANDLE),
            'SetInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            'InitializeProcThreadAttributeList': ([c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
            'UpdateProcThreadAttribute': ([c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
            'DeleteProcThreadAttributeList': ([c.c_void_p], None),
            'CreateProcessW': ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                c.c_void_p, w.LPCWSTR, c.c_void_p, c.POINTER(_ProcessInfo)], w.BOOL),
            'IsProcessInJob': ([w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
            'GetExitCodeProcess': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
            'TerminateJobObject': ([w.HANDLE, w.UINT], w.BOOL),
            'CloseHandle': ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result

    def check(self, result):
        if not result:
            raise BrokerProcessError('native_process_failure')
        return result

    def close(self, handle):
        self.check(self.k.CloseHandle(handle))


class _ChildProcess:
    """Owns only the fixed child's process, job and anonymous-pipe handles."""
    def __init__(self):
        self._api = _WinApi()
        self._job = self._process = None
        self._fds = set()
        self.stdin_fd = self.stdout_fd = None
        self._exit = None
        self.pid = None
        attributes = None
        thread = None
        try:
            self._job = self._api.check(self._api.k.CreateJobObjectW(None, None))
            limits = _ExtendedLimits()
            limits.basic.flags = 0x2000 | 0x8 | 0x100 | 0x2  # kill-on-close, one process, memory, CPU
            limits.basic.active_processes = 1
            limits.process_memory = 256 * 1024 * 1024
            limits.basic.process_time = 10 * 10_000_000  # Ten CPU seconds; wall deadline is separate.
            self._api.check(self._api.k.SetInformationJobObject(self._job, 9, c.byref(limits), c.sizeof(limits)))
            child_in, self.stdin_fd = os.pipe()
            self._fds.update((child_in, self.stdin_fd))
            self.stdout_fd, child_out = os.pipe()
            self._fds.update((self.stdout_fd, child_out))
            child_error = os.open(os.devnull, os.O_WRONLY)
            self._fds.add(child_error)
            import msvcrt
            for descriptor in (child_in, child_out, child_error):
                os.set_inheritable(descriptor, True)
            handles = (w.HANDLE * 3)(*(msvcrt.get_osfhandle(fd) for fd in (child_in, child_out, child_error)))
            jobs = (w.HANDLE * 1)(self._job)
            size = c.c_size_t()
            self._api.k.InitializeProcThreadAttributeList(None, 2, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                raise BrokerProcessError('attribute_list_unavailable')
            buffer = c.create_string_buffer(size.value)
            self._api.check(self._api.k.InitializeProcThreadAttributeList(buffer, 2, 0, c.byref(size)))
            attributes = buffer
            self._api.check(self._api.k.UpdateProcThreadAttribute(buffer, 0, 0x20002, handles, c.sizeof(handles), None, None))
            # Windows 10+ atomic job assignment. Never fall back to post-spawn assignment.
            self._api.check(self._api.k.UpdateProcThreadAttribute(buffer, 0, 0x2000D, jobs, c.sizeof(jobs), None, None))
            startup = _StartupEx()
            startup.startup.cb = c.sizeof(startup)
            startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = handles
            startup.attributes = c.cast(buffer, c.c_void_p)
            entry = self._entry_path()
            command = c.create_unicode_buffer(subprocess.list2cmdline([sys.executable, '-I', '-S', str(entry)]))
            environment = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR') if key in os.environ}
            env = c.create_unicode_buffer('\0'.join(key + '=' + value for key, value in sorted(environment.items())) + '\0\0')
            process = _ProcessInfo()
            self._api.check(self._api.k.CreateProcessW(sys.executable, command, None, None, True,
                0x08000000 | 0x00080000 | 0x00000400, env, str(entry.parent), c.byref(startup), c.byref(process)))
            self._process, thread, self.pid = process.process, process.thread, process.pid
            in_job = w.BOOL()
            self._api.check(self._api.k.IsProcessInJob(self._process, self._job, c.byref(in_job)))
            if not in_job.value:
                raise BrokerProcessError('job_assignment_failed')
            for descriptor in (child_in, child_out, child_error):
                self._close_fd(descriptor)
            os.set_blocking(self.stdin_fd, False)
            os.set_blocking(self.stdout_fd, False)
        except BaseException:
            self.close()
            raise
        finally:
            if attributes is not None:
                self._api.k.DeleteProcThreadAttributeList(attributes)
            if thread:
                try:
                    self._api.close(thread)
                except Exception:
                    self.close()
                    raise

    def _entry_path(self):
        return _entry()

    def _close_fd(self, descriptor):
        if descriptor in self._fds:
            self._fds.remove(descriptor)
            os.close(descriptor)

    def close_input(self):
        self._close_fd(self.stdin_fd)

    def poll(self):
        if self._exit is not None:
            return self._exit
        if self._process is None:
            raise BrokerProcessError('process_unavailable')
        status = self._api.k.WaitForSingleObject(self._process, 0)
        if status == 258:
            return None
        if status != 0:
            raise BrokerProcessError('process_query_failed')
        code = w.DWORD()
        self._api.check(self._api.k.GetExitCodeProcess(self._process, c.byref(code)))
        self._exit = code.value
        return self._exit

    def close(self):
        failed = False
        # Closing the sole noninherited job handle kills a live child, including
        # on parent process death. Wait for process exit before accepting output.
        if self._job is not None:
            handle, self._job = self._job, None
            try:
                self._api.close(handle)
            except Exception:
                failed = True
                if self._process is not None:
                    # Best effort only; failed closure must poison admission.
                    self._api.k.TerminateJobObject(handle, 1)
        if self._process is not None:
            handle, self._process = self._process, None
            try:
                if self._api.k.WaitForSingleObject(handle, 1000) != 0:
                    raise BrokerProcessError('process_cleanup_failed')
                code = w.DWORD()
                self._api.check(self._api.k.GetExitCodeProcess(handle, c.byref(code)))
                self._exit = code.value
            except Exception:
                failed = True
            finally:
                try:
                    self._api.close(handle)
                except Exception:
                    failed = True
        for descriptor in list(self._fds):
            try:
                self._close_fd(descriptor)
            except Exception:
                failed = True
        if failed:
            raise BrokerProcessError('process_cleanup_failed')


class _ObservationChild(_ChildProcess):
    """Second fixed internal profile; no caller-selected executable or entry."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name("broker_observation_entry.py")

class _LiveMetadataChild(_ChildProcess):
    """Fixed inactive metadata-session diagnostic profile."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_live_entry.py')


class _ReviewWaitChild(_ChildProcess):
    """Fixed inactive metadata-only human-wait profile; same native restrictions."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_review_entry.py')


class _BindingMetadataChild(_ChildProcess):
    """Fixed inactive binding/retirement profile; no acquisition command."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_binding_entry.py')
