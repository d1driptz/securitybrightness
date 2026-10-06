"""Fixed native retained-check child; never delivers fixture bytes to apps."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
import threading
from core.broker_child_entry import exact
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_live_entry import read_frame
from core.broker_publication_native import PublicationNativeFixtureAdapter


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:]
    with PublicationNativeFixtureAdapter(key=key, session=session) as adapter:
        sink.write(ready(key, session, os.getpid())); sink.flush()
        sink.write(adapter.open(read_frame(source))); sink.flush()
        sink.write(adapter.stage(read_frame(source))); sink.flush()
        retirement = read_frame(source)
        if source.read(1): raise ValueError('trailing_input')
        ack = adapter.retire(retirement)
    adapter._retired_snapshot_current()
    sink.write(ack); sink.flush()  # No ACK if either native/context cleanup failed.


def run():
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True; watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
