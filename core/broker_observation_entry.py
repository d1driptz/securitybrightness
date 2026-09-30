"""Fixed inactive child: generated fixture metadata only; retires before reply."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
from core.broker_child_entry import exact
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_protocol import MAX_BODY_BYTES
from core.broker_observation import ObservationExchange, proposal_from_text
from core.broker_resource import BrokerFixtureOwner
from core.json_input import loads


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC:
        raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:]
    sink.write(ready(key, session, os.getpid())); sink.flush()
    exchange = ObservationExchange(role='broker', key=key, session=session)
    try:
        prefix = exact(source, 4)
        size = int.from_bytes(prefix, 'big')
        if not 32 <= size <= MAX_BODY_BYTES + 32:
            raise ValueError('bounded_frame')
        frame = prefix + exact(source, size)
        if source.read(1):
            raise ValueError('trailing_input')
        request = loads(exchange.accept_request(frame))
        proposal = proposal_from_text(request['proposal_json'])
        with BrokerFixtureOwner() as owner:
            description = owner.describe()
            binding = owner.bind(request['application_id'], proposal, request['decision_id'])
            owner.verify_once(binding, request['application_id'], proposal, request['decision_id'])
            observation = dict(owner_session=description.session, resource_token=description.resource_token,
                volume_serial=description.volume_serial, file_id=description.file_id.hex(),
                size_bytes=description.size_bytes, display_path=description.display_path)
        # Fixture closure/deletion must succeed before even serializing a reply.
        sink.write(exchange.reply(observation=observation)); sink.flush()
    finally:
        exchange.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        sys.exit(1)
