"""Fixed inactive child: authenticates one bounded request and only denies."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_protocol import FixtureBrokerExchange, MAX_BODY_BYTES


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise ValueError('truncated')
        result.extend(chunk)
    return bytes(result)


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC:
        raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:72]
    sink.write(ready(key, session, os.getpid()))
    sink.flush()
    prefix = exact(source, 4)
    size = int.from_bytes(prefix, 'big')
    if not 32 <= size <= MAX_BODY_BYTES + 32:
        raise ValueError('bounded_frame')
    frame = prefix + exact(source, size)
    if source.read(1):
        raise ValueError('trailing_input')
    exchange = FixtureBrokerExchange(role='broker', key=key, session=session)
    try:
        exchange.accept_request(frame)
        sink.write(exchange.reply(outcome='denied'))
        sink.flush()
    finally:
        exchange.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        sys.exit(1)
