"""One-shot fixed analyzer process with bounded nonblocking pipe transport.

Availability boundary only: not an OS sandbox or a general execution API.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from .result_validation import MAX_RESULT_BYTES, InvalidAnalysisResult, validate_result
from .text_analysis import MAX_BYTES, analyze_bytes

_slot = threading.BoundedSemaphore(1)


class AnalysisUnavailable(RuntimeError):
    """No analysis conclusion is available; the reason contains no sample text."""


def analyze_in_worker(content: bytes, *, timeout: float = 5.0, cancel: threading.Event | None = None):
    """Run only the packaged analyzer. Busy/failure/timeout never means safe.

    No executable, path, command, environment or callback is caller-selectable.
    This is synchronous: UI adapters must run it outside the UI/approval thread.
    """
    if type(content) is not bytes:
        raise TypeError("content must be immutable bytes")
    if type(timeout) not in (float, int) or not 0 < timeout <= 60:
        raise ValueError("timeout must be finite and between zero and 60 seconds")
    if cancel is not None and type(cancel) is not threading.Event:
        raise TypeError("cancel must be a threading.Event")
    if cancel is not None and cancel.is_set():
        raise AnalysisUnavailable("analysis_cancelled")
    if len(content) > MAX_BYTES:
        return analyze_bytes(content)  # bounded rejection before child creation
    expected_digest = hashlib.sha256(content).hexdigest()
    code, output = _run_fixed_worker('worker_entry.py', content, MAX_RESULT_BYTES, timeout, cancel)
    if code != 0:
        raise AnalysisUnavailable("analysis_worker_failed")
    try:
        return validate_result(output, expected_byte_count=len(content), expected_sha256=expected_digest)
    except InvalidAnalysisResult:
        raise AnalysisUnavailable("analysis_invalid_result") from None


def acquire_in_worker(path: str, *, timeout: float = 5.0, cancel: threading.Event | None = None) -> bytes:
    """Acquire exactly one operator-selected file, never an application proposal.

    The helper retains normal account privileges. This is not path confinement
    against hostile same-user code, automatic monitoring or a file executor.
    """
    from .acquisition import ACQUISITION_FAILURES, MAX_PATH_MESSAGE, FileInputError, validate_selected_path
    validate_selected_path(path)  # syntax only; filesystem access is in the child
    message = json.dumps(path, ensure_ascii=True).encode('ascii')
    if len(message) > MAX_PATH_MESSAGE:
        raise FileInputError('unsupported_path')
    code, output = _run_fixed_worker('acquisition_entry.py', message, MAX_BYTES, timeout, cancel)
    if code != 0:
        reason = {value: key for key, value in ACQUISITION_FAILURES.items()}.get(code, 'file_unavailable')
        raise FileInputError(reason)
    return output


def _run_fixed_worker(entry_name, content, output_limit, timeout, cancel):
    if entry_name not in ('worker_entry.py', 'acquisition_entry.py'):
        raise ValueError('unsupported packaged worker')
    if type(timeout) not in (float, int) or not 0 < timeout <= 60:
        raise ValueError("timeout must be finite and between zero and 60 seconds")
    if cancel is not None and type(cancel) is not threading.Event:
        raise TypeError("cancel must be a threading.Event")
    if cancel is not None and cancel.is_set():
        raise AnalysisUnavailable("analysis_cancelled")
    if not _slot.acquire(blocking=False):
        raise AnalysisUnavailable("analysis_busy")
    process = None
    cleanup_failed = False
    try:
        deadline = time.monotonic() + timeout
        entry = Path(__file__).resolve().with_name(entry_name)
        environment = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR') if key in os.environ}
        process = subprocess.Popen(
            [sys.executable, '-I', '-S', str(entry)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=str(entry.parent), env=environment, close_fds=True, bufsize=0,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        sent = 0
        output = bytearray()
        input_closed = False
        output_closed = False
        while True:
            if cancel is not None and cancel.is_set():
                raise AnalysisUnavailable("analysis_cancelled")
            if time.monotonic() >= deadline:
                raise AnalysisUnavailable("analysis_timeout")
            if not input_closed:
                if sent == len(content):
                    process.stdin.close()
                    input_closed = True
                else:
                    try:
                        sent += os.write(process.stdin.fileno(), content[sent:sent + 8192])
                    except BlockingIOError:
                        pass
            if not output_closed:
                try:
                    chunk = os.read(process.stdout.fileno(), output_limit + 1 - len(output))
                    if chunk:
                        output.extend(chunk)
                        if len(output) > output_limit:
                            raise AnalysisUnavailable("analysis_output_limit")
                    else:
                        output_closed = True
                except BlockingIOError:
                    pass
            code = process.poll()
            if code is not None and output_closed:
                if not input_closed:
                    raise AnalysisUnavailable("analysis_worker_failed")
                return code, bytes(output)
            time.sleep(0.002)
    except OSError:
        raise AnalysisUnavailable("analysis_transport_unavailable") from None
    finally:
        try:
            if process is not None:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=1.0)
                except (OSError, subprocess.TimeoutExpired):
                    cleanup_failed = True
                    raise AnalysisUnavailable("analysis_cleanup_failed") from None
                finally:
                    process.stdin.close()
                    process.stdout.close()
        finally:
            # If reaping cannot be confirmed, keep admission closed until
            # parent restart rather than accumulate potentially live children.
            if not cleanup_failed:
                _slot.release()
