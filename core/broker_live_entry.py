"""Fixed inactive live-metadata child. No reads, grants or data delivery."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import os
import threading
from core.broker_child_entry import exact
from core.broker_bootstrap import MAGIC, BOOT_SIZE, ready
from core.broker_protocol import MAX_BODY_BYTES
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_observation import proposal_from_text
from core.broker_session import BrokerResourceSession


def read_frame(source):
    prefix=exact(source,4)
    size=int.from_bytes(prefix,'big')
    if not 32 <= size <= MAX_BODY_BYTES+32:
        raise ValueError('frame_limit')
    return prefix+exact(source,size)


def main():
    source,sink=sys.stdin.buffer,sys.stdout.buffer
    boot=exact(source,BOOT_SIZE)
    if boot[:8]!=MAGIC: raise ValueError('bootstrap')
    key,session=boot[8:40],boot[40:]
    sink.write(ready(key,session,os.getpid()));sink.flush()
    exchange=LiveMetadataExchange(role='broker',key=key,session=session)
    try:
        request=exchange.receive(read_frame(source))
        proposal=proposal_from_text(request['proposal_json'])
        with BrokerResourceSession(capacity=1) as registry:
            issued=registry.issue(request['application_id'],proposal,request['decision_id'])
            description=issued.description
            observed=dict(registry_session=issued.session_id,observation=dict(
                owner_session=description.session,resource_token=description.resource_token,
                volume_serial=description.volume_serial,file_id=description.file_id.hex(),
                size_bytes=description.size_bytes,display_path=description.display_path))
            sink.write(exchange.send(observed));sink.flush()
            finish=exchange.receive(read_frame(source))
            if source.read(1): raise ValueError('trailing_input')
            if finish['action']=='verify':
                registry.verify_once(issued.session_id,issued.resource_token,
                    request['application_id'],proposal,request['decision_id'])
            # Cancellation and verification both close all ownership before ack.
        sink.write(exchange.send(dict(**finish,outcome='denied',lifecycle='retired')));sink.flush()
    finally:
        exchange.close()


def run():
    # Independent wall bound while pipe reads block. Kernel delete-on-close owns
    # crash cleanup; this is not a hard real-time scheduling guarantee.
    watchdog=threading.Timer(10,lambda:os._exit(1))
    watchdog.daemon=True
    watchdog.start()
    try: main()
    finally: watchdog.cancel()


if __name__=='__main__':
    try: run()
    except BaseException: sys.exit(1)
