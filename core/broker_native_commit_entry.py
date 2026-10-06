"""Fixed inactive dry-commit peer. Metadata only; no protected bytes or files."""
import os
from pathlib import Path
import sys
import threading
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_child_entry import exact
from core.broker_protocol import _canonical
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_recipient_entry import read_frame
from core.broker_recipient_process import _OwnershipApi
from core.broker_recipient_protocol import RecipientWitnessExchange


def main():
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    boot = exact(source, BOOT_SIZE)
    if boot[:8] != MAGIC: raise ValueError('bootstrap')
    key, session = boot[8:40], boot[40:72]
    with (RecipientWitnessExchange(role='broker', key=key, session=session) as witness,
          PublicationCommitExchange(role='broker', key=key, session=session) as commit):
        sink.write(ready(key, session, os.getpid())); sink.flush()
        requested = witness.accept_request(read_frame(source))
        sink.write(witness.prove()); sink.flush()
        prepared = commit.accept_prepare(read_frame(source)).inspect()
        # The coordinator's native claim is independently checked against the
        # original current-process handle. Never reopen a numeric process ID.
        native = _OwnershipApi()
        pid, creation_time = native.identity(native.k.GetCurrentProcess())
        channel = prepared['channel']
        if (_canonical(prepared['binding']) != requested.canonical_binding
                or channel['pid'] != pid or channel['creation_time'] != creation_time
                or channel['witness_session'] != session.hex()):
            raise ValueError('commit_peer_binding')
        sink.write(commit.ready()); sink.flush()
        commit.accept_dry_commit(read_frame(source))
        witness.accept_retirement(read_frame(source))
        # A receipt requires the original private input to be closed, with no
        # trailing messages. It remains a zero-release claim, never permission.
        if source.read(1): raise ValueError('trailing_input')
        receipt = commit.receipt()
        ack = witness.acknowledge_retirement()
    sink.write(receipt); sink.write(ack); sink.flush()


def run():
    watchdog = threading.Timer(10, lambda: os._exit(1))
    watchdog.daemon = True; watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__ == '__main__':
    try: run()
    except BaseException: sys.exit(1)
