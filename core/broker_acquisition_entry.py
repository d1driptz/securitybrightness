"""Fixed generated-fixture acquisition/discard child. Never delivers to apps."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
import threading
from time import monotonic
from core.broker_child_entry import exact
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_live_entry import read_frame
from core.broker_native_acquisition import NativeFixtureAcquisitionAdapter


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:]
    with NativeFixtureAcquisitionAdapter(key=key, session=session) as adapter:
        sink.write(ready(key, session, os.getpid())); sink.flush()
        sink.write(adapter.open(read_frame(source))); sink.flush()
        sink.write(adapter.stage(read_frame(source))); sink.flush()
        discard = read_frame(source)
        if source.read(1): raise ValueError('trailing_input')
        ack = adapter.retire(discard)  # Native ownership closes before acknowledgement.
    # Withhold acknowledgement until context-managed cleanup completes as well.
    adapter._owner.validate_description()
    adapter._validate_opening()
    adapter._wire_current(4)
    if (not adapter._owner._closed or adapter._owner._fd is not None
            or adapter._owner._cleanup_failed or monotonic() >= adapter._deadline):
        raise ValueError('changed_during_final_cleanup')
    sink.write(ack); sink.flush()


def run():
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True
    watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
