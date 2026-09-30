"""Inactive four-frame authenticated session protocol; never read permission."""
import hashlib
import hmac
import re
from .broker_protocol import FixtureBrokerExchange, BrokerProtocolError, _canonical
from .broker_observation import _request, _observation
from .json_input import loads

_DOMAIN = b'SecurityBrightness.live-metadata-session.v1\0'


class LiveMetadataExchange(FixtureBrokerExchange):
    """Exactly open -> observed -> verify/cancel -> retired, with transcript binding.

    All frames authenticate step, previous frame hash and canonical contents.
    Fresh trusted bootstrap per process is mandatory. No resume/reset/retry.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._step = 0
        self._previous = '0'*64
        self._observation_digest = None
        self._action = None

    def _mac(self, direction, body):
        key = hmac.digest(self._key, _DOMAIN+direction.encode('ascii'),hashlib.sha256)
        return hmac.digest(key,_DOMAIN+body,hashlib.sha256)

    def _failed(self):
        super()._failed()
        self._step = 4
        self._previous = self._observation_digest = self._action = None

    def _validate(self, message):
        if self._step == 0:
            return _request(message)
        if self._step == 1:
            if type(message) is not dict or set(message) != {'registry_session','observation'}:
                raise ValueError('invalid_observation')
            identity = message['registry_session']
            if type(identity) is not str or re.fullmatch('[0-9a-f]{64}',identity) is None:
                raise ValueError('invalid_registry_session')
            _observation(message['observation'])
            if identity in {message['observation']['owner_session'],message['observation']['resource_token']}:
                raise ValueError('identifier_collision')
            snapshot = _canonical(message)
            self._observation_digest = hashlib.sha256(snapshot).hexdigest()
            return snapshot
        if self._step == 2:
            if (type(message) is not dict or set(message) != {'action','observation_digest'}
                    or type(message['action']) is not str or message['action'] not in {'verify','cancel'}
                    or message['observation_digest'] != self._observation_digest):
                raise ValueError('invalid_finish')
            self._action = message['action']
            return _canonical(message)
        if self._step == 3:
            expected = dict(action=self._action,observation_digest=self._observation_digest,
                            outcome='denied',lifecycle='retired')
            if type(message) is not dict or _canonical(message) != _canonical(expected):
                raise ValueError('invalid_retirement')
            return _canonical(message)
        raise ValueError('retired')

    def send(self, message):
        with self._lock:
            try:
                sender = 'coordinator' if self._step in {0,2} else 'broker'
                if self._step >= 4 or self._role != sender:
                    raise ValueError('wrong_order')
                snapshot = self._validate(message)
                frame = self._encode('request' if sender == 'coordinator' else 'reply',
                    dict(step=self._step,previous=self._previous,message_json=snapshot.decode('ascii')))
                self._advance(frame)
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('live_message_rejected') from None

    def receive(self, frame):
        with self._lock:
            try:
                sender = 'coordinator' if self._step in {0,2} else 'broker'
                if self._step >= 4 or self._role == sender:
                    raise ValueError('wrong_order')
                value = self._decode('request' if sender == 'coordinator' else 'reply',frame)
                if (type(value) is not dict or set(value) != {'step','previous','message_json'}
                        or type(value['step']) is not int or value['step'] != self._step
                        or value['previous'] != self._previous or type(value['message_json']) is not str):
                    raise ValueError('invalid_sequence')
                snapshot = self._validate(loads(value['message_json'],max_depth=5))
                if snapshot.decode('ascii') != value['message_json']:
                    raise ValueError('noncanonical')
                self._advance(frame)
                return loads(snapshot)
            except Exception:
                self._failed()
                raise BrokerProtocolError('live_message_rejected') from None

    def _advance(self, frame):
        self._step += 1
        self._previous = hashlib.sha256(frame).hexdigest()
        if self._step == 4:
            self._failed()
    def _unsupported(self,*args,**kwargs):
        with self._lock:
            self._failed()
            raise BrokerProtocolError('unsupported_live_operation')

    request = accept_request = reply = accept_reply = _unsupported
