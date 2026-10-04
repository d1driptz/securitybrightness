"""Fixed inactive native-binding child. Generated metadata only, never reads."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dataclasses import asdict
import hashlib
import os
import threading
from core.broker_child_entry import exact
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_live_entry import read_frame
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_binding_protocol import AcquisitionBindingExchange
from core.broker_observation import proposal_from_text
from core.broker_session import BrokerResourceSession
from core.broker_pending_review import PendingDisplay
from core.broker_protocol import _canonical
from core.file_read_schema import inspect_file_read_proposal


def _validate_binding(message, registry, issued, request, proposal):
    """Validate local facts, not the peer's grant/review authority claims."""
    context = message['context']
    description = registry.inspect(issued, request['application_id'], proposal, request['decision_id'])
    intent = inspect_file_read_proposal(proposal)
    expected = dict(application_id=request['application_id'], proposal_id=intent.proposal_id,
        decision_id=request['decision_id'], registry_session=issued.session_id,
        owner_session=description.session, resource_token=description.resource_token,
        volume_serial=description.volume_serial, file_id=description.file_id.hex(),
        size_bytes=description.size_bytes, max_bytes=intent.max_bytes,
        operation='files.read', recipient='requesting_application')
    if any(context[name] != value for name, value in expected.items()):
        raise ValueError('native_binding_mismatch')
    display = PendingDisplay(request['decision_id'], request['application_id'], intent.proposal_id,
        context['draft_id'], context['draft_revision'], context['grant_id'], issued.session_id,
        description.session, description.resource_token, description.volume_serial,
        description.file_id.hex(), description.size_bytes, intent.max_bytes,
        description.display_path, request['proposal_json'])
    if hashlib.sha256(_canonical(asdict(display))).hexdigest() != message['display_digest']:
        raise ValueError('display_mismatch')


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:]
    sink.write(ready(key, session, os.getpid())); sink.flush()
    opening = LiveMetadataExchange(role='broker', key=key, session=session)
    binding = None
    try:
        request = opening.receive(read_frame(source))
        proposal = proposal_from_text(request['proposal_json'])
        with BrokerResourceSession(capacity=1) as registry:
            issued = registry.issue(request['application_id'], proposal, request['decision_id'])
            d = issued.description
            observed = dict(registry_session=issued.session_id, observation=dict(
                owner_session=d.session, resource_token=d.resource_token,
                volume_serial=d.volume_serial, file_id=d.file_id.hex(),
                size_bytes=d.size_bytes, display_path=d.display_path))
            # This profile switches domains after the initial observation. It
            # never accepts the old live-metadata finish as a binding command.
            binding = AcquisitionBindingExchange(role='broker', key=key, session=session)
            sink.write(opening.send(observed)); sink.flush()
            opening.close()
            message = binding.receive(read_frame(source))
            _validate_binding(message, registry, issued, request, proposal)
            digest = hashlib.sha256(_canonical(message)).hexdigest()
            sink.write(binding.send(dict(outcome='bound', binding_digest=digest))); sink.flush()
            finish = binding.receive(read_frame(source))
            if source.read(1): raise ValueError('trailing_input')
            if finish['action'] == 'retire':
                _validate_binding(message, registry, issued, request, proposal)
                registry.verify_once(issued.session_id, issued.resource_token,
                                     request['application_id'], proposal, request['decision_id'])
        # Ownership closes before acknowledgement, including for cancellation.
        sink.write(binding.send(dict(**finish, outcome='denied', lifecycle='retired', released_bytes=0)))
        sink.flush()
    finally:
        opening.close()
        if binding is not None: binding.close()


def run():
    # Codec expiry cannot interrupt blocking pipe reads. Independently bound the
    # process; the inherited kill-on-close job also handles parent loss.
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True
    watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
