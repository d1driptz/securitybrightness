"""Inactive fixed fixture wait/acquisition child; private staging, no app delivery.

Thirty seconds for observation/review preparation, then at most five seconds for
one acquisition and retirement, within an original thirty-five-second lifetime.
The future coordinator must independently enforce exact-resource human control,
current authority and original native ownership; authenticated input is not that
authority. No existing host or owner walkthrough selects this entry.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
import threading
import time

from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_protocol import MAX_BODY_BYTES
from core.broker_wait_native import WaitNativeFixtureAdapter


def _bootstrap(source):
    # Use the original raw descriptor throughout: no buffered read-ahead can
    # hide pipelined protocol bytes when switching to nonblocking phase reads.
    result = bytearray()
    while len(result) < BOOT_SIZE:
        value = os.read(source, BOOT_SIZE-len(result))
        if type(value) is not bytes or not value or len(value) > BOOT_SIZE-len(result):
            raise ValueError('bootstrap_eof')
        result.extend(value)
    return bytes(result)


def _exact(source, size, adapter):
    result = bytearray()
    while len(result) < size:
        adapter._input_current()
        try:
            value = os.read(source, size-len(result))
        except BlockingIOError:
            time.sleep(.002)
            continue
        adapter._input_current()
        if type(value) is not bytes or not value or len(value) > size-len(result):
            raise ValueError('input_eof')
        result.extend(value)
    return bytes(result)


def _frame(source, adapter):
    prefix = _exact(source, 4, adapter)
    size = int.from_bytes(prefix, 'big')
    if not 32 <= size <= MAX_BODY_BYTES+32:
        raise ValueError('frame_size')
    return prefix+_exact(source, size, adapter)


def _eof(source, adapter):
    while True:
        adapter._input_current()
        try:
            value = os.read(source, 1)
        except BlockingIOError:
            time.sleep(.002)
            continue
        adapter._input_current()
        if type(value) is not bytes or len(value) > 1:
            raise ValueError('invalid_eof')
        if value:
            raise ValueError('trailing_input')
        return


def main():
    source, sink = sys.stdin.fileno(), sys.stdout.buffer
    boot = _bootstrap(source)
    if boot[:8] != MAGIC:
        raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:]
    with WaitNativeFixtureAdapter(key=key, session=session) as adapter:
        os.set_blocking(source, False)
        sink.write(ready(key, session, os.getpid())); sink.flush()
        sink.write(adapter.open(_frame(source, adapter))); sink.flush()
        sink.write(adapter.stage(_frame(source, adapter))); sink.flush()
        retirement = _frame(source, adapter)
        _eof(source, adapter)
        ack = adapter.retire(retirement)
    adapter._retired_snapshot_current()
    sink.write(ack); sink.flush()


def run():
    # Independent wall bound: never extended by input, progress or a heartbeat.
    watchdog = threading.Timer(40, lambda: os._exit(1))
    watchdog.daemon = True
    watchdog.start()
    try:
        main()
    finally:
        watchdog.cancel()


if __name__ == '__main__':
    try:
        run()
    except BaseException:
        sys.exit(1)
