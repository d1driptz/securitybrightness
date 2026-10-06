"""Fixed inactive cooperating test peer; metadata only, never protected bytes."""
import os
from pathlib import Path
import sys
import threading
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_child_entry import exact
from core.broker_protocol import MAX_BODY_BYTES
from core.broker_recipient_protocol import RecipientWitnessExchange


def read_frame(source):
    prefix = exact(source, 4)
    size = int.from_bytes(prefix, 'big')
    if not 32 <= size <= MAX_BODY_BYTES + 32:
        raise ValueError('bounded_recipient_frame')
    return prefix + exact(source, size)


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:72]
    with RecipientWitnessExchange(role='broker', key=key, session=session) as exchange:
        sink.write(ready(key, session, os.getpid())); sink.flush()
        exchange.accept_request(read_frame(source))
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
