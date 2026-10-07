"""Inactive fixed synthetic-byte receiver: validate, discard, acknowledge, exit.

No file/resource lookup, authorization, application publication or data reply.
The trusted launcher owns this entry and its imports; this is not an OS sandbox.
"""
import os
from pathlib import Path
import sys
import threading
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_child_entry import exact
from core.broker_recipient_entry import read_frame
from core.broker_recipient_process import _OwnershipApi
from core.broker_synthetic_payload_protocol import SyntheticPayloadExchange


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:72]
    with SyntheticPayloadExchange(role='broker', key=key, session=session) as exchange:
        sink.write(ready(key, session, os.getpid())); sink.flush()
        prepared = exchange.accept_prepare(read_frame(source)).inspect()
        native = _OwnershipApi()
        pid, creation = native.identity(native.k.GetCurrentProcess())
        channel = prepared['channel']
        if (channel['pid'] != pid or channel['creation_time'] != creation
                or channel['witness_session'] != session.hex()):
            raise ValueError('synthetic_peer_binding')
        sink.write(exchange.ready()); sink.flush()
        exchange.accept_payload(read_frame(source))
        # The original private input must be EOF, with no extra command/frame.
        if source.read(1): raise ValueError('trailing_input')
        exchange.discard()
        receipt = exchange.receipt()
    sink.write(receipt); sink.flush()


def run():
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True; watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
