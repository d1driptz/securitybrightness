"""Inactive one-use binding transcript. No I/O, resource truth or authority.

This separate wire profile can only bind, acknowledge and retire/cancel metadata.
It has no acquire/read/release transition and is not imported by a live host.
"""
import hashlib
import hmac
import math
import re
from threading import Timer
from time import monotonic
from .broker_live_protocol import LiveMetadataExchange
from .broker_protocol import BrokerProtocolError, _canonical
from .broker_quarantine import _context
from .json_input import loads


class AcquisitionBindingExchange(LiveMetadataExchange):
    """Bind -> bound -> retire/cancel -> retired. No retry or restoration.

    Each endpoint has its own trusted monotonic deadline, never a peer-supplied
    lifetime. A lost frame cannot advance a receiver. Peer disappearance leaves
    only expiring metadata; a future host must independently kill/join children.
    'bound' acknowledges a transcript, not authority, native validation or a read.
    """
    def __init__(self, *, role, key, session, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_binding_lifetime')
        super().__init__(role=role, key=key, session=session)
        self._digest = None
        self._cancelled = False
        self._deadline = monotonic()+timeout
        self._timer = Timer(timeout, self.close)
        self._timer.daemon = True
        try:
            self._timer.start()
        except Exception:
            self.close()
            raise BrokerProtocolError('binding_unavailable') from None

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.inactive-acquisition-binding.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _failed(self):
        self._digest = None
        self._timer.cancel()
        super()._failed()

    def _validate(self, message):
        if type(message) is not dict: raise ValueError('invalid_message')
        message = message.copy()
        if self._step == 0:
            if set(message) != {'context', 'display_digest'}: raise ValueError('invalid_binding')
            digest = message['display_digest']
            if type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
                raise ValueError('invalid_display_digest')
            snapshot = _canonical(dict(context=loads(_context(message['context'])), display_digest=digest))
            self._digest = hashlib.sha256(snapshot).hexdigest()
            return snapshot
        if self._step == 1:
            expected = dict(outcome='bound', binding_digest=self._digest)
        elif self._step == 2:
            action = message.get('action')
            if type(action) is not str or action not in {'retire', 'cancel'}: raise ValueError('invalid_action')
            expected = dict(action=action, binding_digest=self._digest)
            self._action = action
        elif self._step == 3:
            expected = dict(action=self._action, binding_digest=self._digest,
                            outcome='denied', lifecycle='retired', released_bytes=0)
        else:
            raise ValueError('retired')
        snapshot = _canonical(message)
        if snapshot != _canonical(expected): raise ValueError('binding_mismatch')
        return snapshot

    def _exchange(self, operation, value):
        with self._lock:
            try:
                if self._cancelled or self._state == 'closed' or monotonic() >= self._deadline:
                    raise ValueError('expired_or_closed')
                result = operation(value)
                # Native/transport integrations must also validate their own
                # deadlines. A codec call itself cannot cross this deadline.
                if self._cancelled or monotonic() >= self._deadline: raise ValueError('cancelled_or_expired')
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('binding_message_rejected') from None

    def send(self, message): return self._exchange(super().send, message)
    def receive(self, frame): return self._exchange(super().receive, frame)

    def close(self):
        with self._lock:
            self._cancelled = True
            super().close()
