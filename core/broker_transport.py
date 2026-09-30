"""Inactive, single-slot, denial-only private transport. Never file delivery.

Trusted packaged code/interpreter and coordinator are prerequisites. Cancellation
is observed at bounded polling points, not an atomic authority revocation API.
"""
import hmac
import math
import os
import secrets
import threading
import time
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_process import _ChildProcess, BrokerProcessError
from .broker_protocol import FixtureBrokerExchange, MAX_BODY_BYTES

_slot = threading.BoundedSemaphore(1)


class BrokerTransportError(RuntimeError):
    pass


def probe(binding, *, cancel=None, timeout=5.0):
    """Return authenticated denial evidence only; accepts no launch parameters.

    A fresh process/key/session per call. No retries or restored exchanges.
    Cleanup uncertainty permanently poisons this process's transport slot.
    """
    return _run(binding, FixtureBrokerExchange, _ChildProcess, cancel=cancel, timeout=timeout)


def observe_fixture(application_id, proposal, decision_id, *, cancel=None, timeout=5.0):
    """Opt-in retired synthetic metadata evidence. No live token, read or grant."""
    from .broker_observation import ObservationExchange
    from .broker_process import _ObservationChild
    from .structured_proposal import StructuredActionProposal
    if type(proposal) is not StructuredActionProposal:
        raise BrokerTransportError('invalid_proposal')
    try:
        request = dict(application_id=application_id, decision_id=decision_id,
                       proposal_json=proposal.canonical_bytes().decode('ascii'))
    except Exception:
        raise BrokerTransportError('invalid_proposal') from None
    return _run(request, ObservationExchange, _ObservationChild, cancel=cancel, timeout=timeout)


def _run(binding, exchange_type, child_type, *, cancel, timeout):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise BrokerTransportError('invalid_timeout')
    if cancel is not None and type(cancel) is not threading.Event:
        raise BrokerTransportError('invalid_cancellation')
    deadline = time.monotonic() + timeout
    def check():
        if cancel is not None and cancel.is_set():
            raise BrokerTransportError('cancelled')
        if time.monotonic() >= deadline:
            raise BrokerTransportError('deadline')
    check()
    key, session = secrets.token_bytes(32), secrets.token_bytes(32)
    exchange = exchange_type(role='coordinator', key=key, session=session)
    child = None
    acquired = False
    cleanup_ok = True
    try:
        frame = exchange.request(binding)  # Validate and detach before starting anything.
        acquired = _slot.acquire(blocking=False)
        if not acquired:
            raise BrokerTransportError('busy_or_unavailable')
        check()
        child = child_type()
        def write(data):
            offset = 0
            while offset < len(data):
                check()
                try:
                    count = os.write(child.stdin_fd, data[offset:])
                    if count <= 0:
                        raise BrokerTransportError('pipe_failed')
                    offset += count
                except BlockingIOError:
                    time.sleep(.002)
        def read(size):
            result = bytearray()
            while len(result) < size:
                check()
                try:
                    chunk = os.read(child.stdout_fd, size - len(result))
                    if not chunk:
                        raise BrokerTransportError('truncated_output')
                    result.extend(chunk)
                except BlockingIOError:
                    time.sleep(.002)
            return bytes(result)
        write(MAGIC + key + session)
        if not hmac.compare_digest(read(READY_SIZE), ready(key, session, child.pid)):
            raise BrokerTransportError('startup_rejected')
        write(frame)
        child.close_input()
        prefix = read(4)
        size = int.from_bytes(prefix, 'big')
        if not 32 <= size <= MAX_BODY_BYTES + 32:
            raise BrokerTransportError('output_limit')
        response = prefix + read(size)
        # EOF plus successful exit required: a valid prefix/reply is insufficient.
        while True:
            check()
            try:
                extra = os.read(child.stdout_fd, 1)
                if extra:
                    raise BrokerTransportError('trailing_output')
                break
            except BlockingIOError:
                time.sleep(.002)
        while child.poll() is None:
            check()
            time.sleep(.002)
        if child.poll() != 0:
            raise BrokerTransportError('child_failed')
        result = exchange.accept_reply(response)
        if result.outcome != 'denied' or result.data:
            raise BrokerTransportError('delivery_disabled')
        child.close()
        child = None
        check()
        return result
    except BrokerProcessError as error:
        if str(error) == 'process_cleanup_failed':
            cleanup_ok = False
        raise BrokerTransportError('process_failed') from None
    except BrokerTransportError:
        raise
    except Exception:
        raise BrokerTransportError('exchange_failed') from None
    finally:
        exchange.close()
        try:
            if child is not None:
                child.close()
        except BaseException:
            cleanup_ok = False
            raise BrokerTransportError('cleanup_failed') from None
        finally:
            if acquired and cleanup_ok:
                _slot.release()
