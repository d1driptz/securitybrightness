"""Inactive single-exchange fixture-broker wire contract; no I/O or authority.

Keys/session identifiers must come from a future trusted bootstrap. A verified
message proves only possession of that exchange key, never human permission,
resource truth, current registry authority or permission to deliver its bytes.
"""
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from threading import RLock

from .json_input import loads

MAX_BODY_BYTES = 8192
MAX_DATA_BYTES = 4096
_DOMAIN = b'SecurityBrightness.fixture-broker.v1\x00'
_BINDING = {'application_id', 'proposal_id', 'resource_token', 'decision_id', 'max_bytes'}


class BrokerProtocolError(ValueError):
    """Fixed error; never includes keys, buffered contents or requester labels."""


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _binding(value):
    if type(value) is not dict or set(value) != _BINDING:
        raise BrokerProtocolError('invalid_binding')
    app = value['application_id']
    if (type(app) is not str or not 1 <= len(app) <= 256 or app.strip() != app
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in app)):
        raise BrokerProtocolError('invalid_binding')
    if len(app.encode('utf-8')) > 256:
        raise BrokerProtocolError('invalid_binding')
    for name in ('resource_token', 'decision_id'):
        if type(value[name]) is not str or re.fullmatch('[0-9a-f]{64}', value[name]) is None:
            raise BrokerProtocolError('invalid_binding')
    proposal = value['proposal_id']
    if type(proposal) is not str or re.fullmatch('sbp2_sha256_[0-9a-f]{64}', proposal) is None:
        raise BrokerProtocolError('invalid_binding')
    if type(value['max_bytes']) is not int or not 1 <= value['max_bytes'] <= MAX_DATA_BYTES:
        raise BrokerProtocolError('invalid_binding')
    return _canonical(value)  # Detached immutable snapshot, including Unicode validation.


@dataclass(frozen=True)
class BrokerRequestEvidence:
    canonical_binding: bytes = field(repr=False)

    def inspect(self):
        return loads(self.canonical_binding)

    def __bool__(self):
        raise TypeError('A broker request is not permission')


@dataclass(frozen=True)
class StagedBrokerReply:
    outcome: str
    data: bytes = field(repr=False)
    canonical_binding: bytes = field(repr=False)

    def __bool__(self):
        raise TypeError('Authenticated staged bytes are not authorized delivery')


class FixtureBrokerExchange:
    """One request and one reply, then permanently spent. Not a transport.

    Receives complete length-prefixed frames, not arbitrary stream chunks.
    Invalid input, role/order violations or replay irreversibly close this endpoint.
    No restoration, sequence rollback, key negotiation or permissive retry exists.
    The peer must never be given an application-selected key or resource mapping.
    """
    def __init__(self, *, role, key, session):
        if type(role) is not str or role not in {'coordinator', 'broker'}:
            raise BrokerProtocolError('invalid_bootstrap')
        if type(key) is not bytes or len(key) != 32 or type(session) is not bytes or len(session) != 32:
            raise BrokerProtocolError('invalid_bootstrap')
        self._role, self._key, self._session = role, key, session.hex()
        self._state = 'new'
        self._binding = None
        self._lock = RLock()

    def _require(self, role, state):
        if self._role != role or self._state != state:
            raise BrokerProtocolError('exchange_unavailable')

    def _mac(self, direction, body):
        direction_key = hmac.digest(self._key, _DOMAIN + direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(direction_key, _DOMAIN + body, hashlib.sha256)

    def _encode(self, direction, payload):
        body = _canonical(dict(version=1, session=self._session, direction=direction, payload=payload))
        if len(body) > MAX_BODY_BYTES:
            raise BrokerProtocolError('frame_too_large')
        signed = body + self._mac(direction, body)
        return len(signed).to_bytes(4, 'big') + signed

    def _decode(self, direction, frame):
        if type(frame) is not bytes or not 36 <= len(frame) <= MAX_BODY_BYTES + 36:
            raise BrokerProtocolError('invalid_frame')
        length = int.from_bytes(frame[:4], 'big')
        if length != len(frame) - 4 or not 32 <= length <= MAX_BODY_BYTES + 32:
            raise BrokerProtocolError('invalid_frame')
        body, tag = frame[4:-32], frame[-32:]
        if not hmac.compare_digest(self._mac(direction, body), tag):
            raise BrokerProtocolError('invalid_frame')
        value = loads(body.decode('ascii'), max_depth=4)
        if (type(value) is not dict or set(value) != {'version', 'session', 'direction', 'payload'}
                or type(value['version']) is not int or value['version'] != 1
                or value['session'] != self._session or value['direction'] != direction
                or _canonical(value) != body):
            raise BrokerProtocolError('invalid_frame')
        return value['payload']

    def _failed(self):
        self._state = 'closed'
        self._binding = None
        self._key = b''

    def request(self, binding):
        with self._lock:
            try:
                self._require('coordinator', 'new')
                snapshot = _binding(binding)
                frame = self._encode('request', loads(snapshot))
                self._binding, self._state = snapshot, 'waiting'
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('request_rejected') from None

    def accept_request(self, frame):
        with self._lock:
            try:
                self._require('broker', 'new')
                snapshot = _binding(self._decode('request', frame))
                self._binding, self._state = snapshot, 'pending'
                return BrokerRequestEvidence(snapshot)
            except Exception:
                self._failed()
                raise BrokerProtocolError('request_rejected') from None

    def reply(self, *, outcome, data=b''):
        import base64
        with self._lock:
            try:
                self._require('broker', 'pending')
                if type(outcome) is not str or outcome not in {'buffered', 'denied'} or type(data) is not bytes:
                    raise BrokerProtocolError('invalid_reply')
                binding = loads(self._binding)
                if len(data) > binding['max_bytes'] or (outcome == 'denied' and data):
                    raise BrokerProtocolError('invalid_reply')
                frame = self._encode('reply', dict(binding=binding, outcome=outcome,
                                                   data=base64.b64encode(data).decode('ascii')))
                self._failed()  # Spent even if a future transport loses the frame.
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('reply_rejected') from None

    def accept_reply(self, frame):
        import base64
        with self._lock:
            try:
                self._require('coordinator', 'waiting')
                payload = self._decode('reply', frame)
                if type(payload) is not dict or set(payload) != {'binding', 'outcome', 'data'}:
                    raise BrokerProtocolError('invalid_reply')
                snapshot = _binding(payload['binding'])
                if snapshot != self._binding or type(payload['outcome']) is not str or payload['outcome'] not in {'buffered', 'denied'}:
                    raise BrokerProtocolError('invalid_reply')
                encoded = payload['data']
                if type(encoded) is not str or len(encoded) > 5464:
                    raise BrokerProtocolError('invalid_reply')
                data = base64.b64decode(encoded, validate=True)
                if base64.b64encode(data).decode('ascii') != encoded:
                    raise BrokerProtocolError('invalid_reply')
                if len(data) > payload['binding']['max_bytes'] or (payload['outcome'] == 'denied' and data):
                    raise BrokerProtocolError('invalid_reply')
                result = StagedBrokerReply(payload['outcome'], data, snapshot)
                self._failed()
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('reply_rejected') from None

    def close(self):
        with self._lock:
            self._failed()
