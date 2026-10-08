"""Fixed inactive source/native association peer; no files or payload data."""
import os
from pathlib import Path
import sys
import threading
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_child_entry import exact
from core.broker_recipient_entry import read_frame
from core.broker_recipient_process import _OwnershipApi
from core.broker_source_association_protocol import SourceRecipientAssociationExchange


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:72]
    with SourceRecipientAssociationExchange(role='broker', key=key, session=session) as exchange:
        sink.write(ready(key, session, os.getpid())); sink.flush()
        requested = exchange.accept_request(read_frame(source)).inspect()
        native = _OwnershipApi()
        pid, creation_time = native.identity(native.k.GetCurrentProcess())
        channel = requested['recipient_channel']
        if (channel['pid'] != pid or channel['creation_time'] != creation_time
                or channel['witness_session'] != session.hex()):
            raise ValueError('association_native_binding')
        sink.write(exchange.prove()); sink.flush()
        exchange.accept_retirement(read_frame(source))
        if source.read(1): raise ValueError('trailing_input')
        ack = exchange.acknowledge_retirement()
    sink.write(ack); sink.flush()


def run():
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True; watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
