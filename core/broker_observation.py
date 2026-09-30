"""Inactive authenticated retired-observation exchange; no live capability."""
from dataclasses import dataclass, field
import hashlib
import hmac
import re

from .broker_protocol import FixtureBrokerExchange, BrokerProtocolError, _canonical, _binding
from .file_read_schema import inspect_file_read_proposal
from .structured_proposal import StructuredActionProposal
from .json_input import loads

_DOMAIN = b'SecurityBrightness.retired-observation.v1\0'


def proposal_from_text(text):
    if type(text) is not str or not 1 <= len(text) <= 4096:
        raise ValueError('invalid_proposal')
    payload = loads(text)
    if (type(payload) is not dict or set(payload) != {'version','operation','resources','effects','requester_context'}
            or type(payload['version']) is not int or payload['version'] != 2):
        raise ValueError('invalid_proposal')
    proposal = StructuredActionProposal(payload['operation'], payload['resources'],
        effects=payload['effects'], requester_context=payload['requester_context'])
    if proposal.canonical_bytes() != text.encode('ascii'):
        raise ValueError('noncanonical_proposal')
    intent = inspect_file_read_proposal(proposal)
    if not 37 <= intent.max_bytes <= 4096:
        raise ValueError('unsupported_bound')
    return proposal


def _request(value):
    if type(value) is not dict or set(value) != {'application_id','decision_id','proposal_json'}:
        raise ValueError('invalid_request')
    proposal = proposal_from_text(value['proposal_json'])
    intent = inspect_file_read_proposal(proposal)
    _binding(dict(application_id=value['application_id'], decision_id=value['decision_id'],
                  proposal_id=intent.proposal_id, resource_token='0'*64, max_bytes=intent.max_bytes))
    return _canonical(value)


def _observation(value):
    if type(value) is not dict or set(value) != {'owner_session','resource_token','volume_serial','file_id','size_bytes','display_path'}:
        raise ValueError('invalid_observation')
    for name, width in [('owner_session',64),('resource_token',64),('file_id',32)]:
        if type(value[name]) is not str or re.fullmatch('[0-9a-f]{'+str(width)+'}', value[name]) is None:
            raise ValueError('invalid_observation')
    if value['owner_session'] == value['resource_token']:
        raise ValueError('identifier_collision')
    if type(value['volume_serial']) is not int or not 0 <= value['volume_serial'] < 2**64:
        raise ValueError('invalid_observation')
    if type(value['size_bytes']) is not int or value['size_bytes'] != 37:
        raise ValueError('not_fixed_fixture')
    display = value['display_path']
    if (type(display) is not str or not 1 <= len(display) <= 1024
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in display)
            or len(display.encode('utf-8')) > 1024):
        raise ValueError('invalid_display')
    return _canonical(value)


@dataclass(frozen=True)
class RetiredObservation:
    canonical_request: bytes = field(repr=False)
    canonical_observation: bytes = field(repr=False)
    outcome: str = field(default='denied', init=False)
    data: bytes = field(default=b'', init=False, repr=False)
    lifecycle: str = field(default='retired', init=False)

    def inspect(self):
        return loads(self.canonical_observation)

    def __bool__(self):
        raise TypeError('Retired metadata is not authority or a live resource')


class ObservationExchange(FixtureBrokerExchange):
    """Separate MAC domain from the read codec; always retires after one attempt."""
    def _mac(self, direction, body):
        key = hmac.digest(self._key, _DOMAIN + direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, _DOMAIN + body, hashlib.sha256)

    def request(self, request):
        with self._lock:
            try:
                self._require('coordinator', 'new')
                snapshot = _request(request)
                frame = self._encode('request', loads(snapshot))
                self._binding, self._state = snapshot, 'waiting'
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('observation_request_rejected') from None

    def accept_request(self, frame):
        with self._lock:
            try:
                self._require('broker', 'new')
                snapshot = _request(self._decode('request', frame))
                self._binding, self._state = snapshot, 'pending'
                return snapshot
            except Exception:
                self._failed()
                raise BrokerProtocolError('observation_request_rejected') from None

    def reply(self, *, observation):
        with self._lock:
            try:
                self._require('broker', 'pending')
                snapshot = _observation(observation)
                frame = self._encode('reply', dict(request=loads(self._binding),
                    observation=loads(snapshot), outcome='denied', lifecycle='retired'))
                self._failed()
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('observation_reply_rejected') from None

    def accept_reply(self, frame):
        with self._lock:
            try:
                self._require('coordinator', 'waiting')
                payload = self._decode('reply', frame)
                if (type(payload) is not dict or set(payload) != {'request','observation','outcome','lifecycle'}
                        or payload['outcome'] != 'denied' or payload['lifecycle'] != 'retired'
                        or _request(payload['request']) != self._binding):
                    raise ValueError('invalid_reply')
                result = RetiredObservation(self._binding, _observation(payload['observation']))
                self._failed()
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('observation_reply_rejected') from None
