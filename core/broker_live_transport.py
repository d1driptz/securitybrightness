"""Opt-in inactive two-round metadata diagnostic, never a human approval flow."""
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import os
import secrets
import threading
import time
from . import broker_transport as transport
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_process import _LiveMetadataChild, BrokerProcessError
from .broker_live_protocol import LiveMetadataExchange
from .broker_protocol import MAX_BODY_BYTES, _canonical
from .structured_proposal import StructuredActionProposal
from .json_input import loads


@dataclass(frozen=True)
class RetiredSessionDiagnostic:
    canonical_request: bytes = field(repr=False)
    canonical_observation: bytes = field(repr=False)
    action: str
    lifecycle: str = field(default='retired',init=False)
    outcome: str = field(default='denied',init=False)
    data: bytes = field(default=b'',init=False,repr=False)

    def inspect(self): return loads(self.canonical_observation)

    def __bool__(self): raise TypeError('A metadata diagnostic is not permission')


def diagnose_session(application_id, proposal, decision_id, *, action='verify', cancel=None, timeout=5.0):
    """Create, observe, verify/cancel and retire one synthetic handle in one child.

    No callback, path, peer selector, review state or authority inputs. Intermediate
    live metadata never leaves this call. A final result requires cleanup and exit.
    """
    error=transport.BrokerTransportError
    if (type(proposal) is not StructuredActionProposal or type(action) is not str or action not in {'verify','cancel'}
            or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 10
            or (cancel is not None and type(cancel) is not threading.Event)):
        raise error('invalid_diagnostic')
    deadline=time.monotonic()+timeout
    def check():
        if cancel is not None and cancel.is_set(): raise error('cancelled')
        if time.monotonic()>=deadline: raise error('deadline')
    check()
    key,session=secrets.token_bytes(32),secrets.token_bytes(32)
    exchange=LiveMetadataExchange(role='coordinator',key=key,session=session)
    child=None; acquired=False; cleanup_ok=True
    try:
        request=dict(application_id=application_id,decision_id=decision_id,
                     proposal_json=proposal.canonical_bytes().decode('ascii'))
        first=exchange.send(request)
        acquired=transport._slot.acquire(blocking=False)
        if not acquired: raise error('busy_or_unavailable')
        check()
        child=_LiveMetadataChild()
        def write(data):
            offset=0
            while offset<len(data):
                check()
                try:
                    count=os.write(child.stdin_fd,data[offset:])
                    if count<=0: raise error('pipe_failed')
                    offset+=count
                except BlockingIOError: time.sleep(.002)
        def read(size):
            result=bytearray()
            while len(result)<size:
                check()
                try:
                    chunk=os.read(child.stdout_fd,size-len(result))
                    if not chunk: raise error('truncated_output')
                    result.extend(chunk)
                except BlockingIOError: time.sleep(.002)
            return bytes(result)
        def frame():
            prefix=read(4); size=int.from_bytes(prefix,'big')
            if not 32<=size<=MAX_BODY_BYTES+32: raise error('output_limit')
            return prefix+read(size)
        write(MAGIC+key+session)
        if not hmac.compare_digest(read(READY_SIZE),ready(key,session,child.pid)):
            raise error('startup_rejected')
        write(first)
        observation=exchange.receive(frame())
        snapshot=_canonical(observation)
        finish=dict(action=action,observation_digest=hashlib.sha256(snapshot).hexdigest())
        write(exchange.send(finish))
        child.close_input()
        exchange.receive(frame())  # Exact retired denial acknowledgement only.
        while True:
            check()
            try:
                if os.read(child.stdout_fd,1): raise error('trailing_output')
                break
            except BlockingIOError: time.sleep(.002)
        while child.poll() is None:
            check();time.sleep(.002)
        if child.poll()!=0: raise error('child_failed')
        child.close();child=None
        result=RetiredSessionDiagnostic(_canonical(request),snapshot,action)
        check()
        return result
    except BrokerProcessError as exc:
        if str(exc)=='process_cleanup_failed': cleanup_ok=False
        raise error('process_failed') from None
    except transport.BrokerTransportError: raise
    except Exception: raise error('session_failed') from None
    finally:
        exchange.close()
        try:
            if child is not None: child.close()
        except BaseException:
            cleanup_ok=False
            raise error('cleanup_failed') from None
        finally:
            if acquired and cleanup_ok: transport._slot.release()
