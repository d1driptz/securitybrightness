"""Inactive byte-quarantine wire draft. No I/O, authorization or release API.

Trusted bootstrap alone owns fresh keys and endpoints. Context fields are binding
claims, not proof of current authority or human review. No existing child or host
imports this module. Only authenticated discard is supported after staging.
"""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import math
import re
from threading import Timer
from time import monotonic
from uuid import UUID
from .broker_protocol import FixtureBrokerExchange, BrokerProtocolError, BrokerRequestEvidence, _binding, _canonical
from .json_input import loads


_FIELDS = {'application_id', 'proposal_id', 'grant_id', 'draft_id', 'draft_revision',
           'review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token',
           'volume_serial', 'file_id', 'size_bytes', 'max_bytes', 'operation', 'recipient'}


def _context(value):
    if type(value) is not dict or len(value) != len(_FIELDS):
        raise ValueError('invalid_context')
    value = value.copy()  # Detach caller-owned mapping before validating its scalar fields.
    if set(value) != _FIELDS:
        raise ValueError('invalid_context')
    _binding({name: value[name] for name in ('application_id', 'proposal_id', 'resource_token', 'decision_id', 'max_bytes')})
    identities = [value[name] for name in ('review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token')]
    if any(type(item) is not str or re.fullmatch('[0-9a-f]{64}', item) is None for item in identities):
        raise ValueError('invalid_identity')
    if len(set(identities)) != len(identities): raise ValueError('identity_collision')
    for name in ('grant_id', 'draft_id'):
        if type(value[name]) is not str or len(value[name]) != 36 or str(UUID(value[name])) != value[name]:
            raise ValueError('invalid_lifecycle_identity')
    if value['grant_id'] == value['draft_id']: raise ValueError('identity_collision')
    for name, lower, upper in [('draft_revision', 1, 2**31-1), ('volume_serial', 0, 2**64-1),
                               ('size_bytes', 0, value['max_bytes'])]:
        if type(value[name]) is not int or not lower <= value[name] <= upper:
            raise ValueError('invalid_bound')
    if type(value['file_id']) is not str or re.fullmatch('[0-9a-f]{32}', value['file_id']) is None:
        raise ValueError('invalid_resource_identity')
    if (type(value['operation']) is not str or value['operation'] != 'files.read'
            or type(value['recipient']) is not str or value['recipient'] != 'requesting_application'):
        raise ValueError('unsupported_effect')
    return _canonical(value)


@dataclass(frozen=True)
class QuarantineSummary:
    binding_digest: str
    staged_digest: str
    staged_bytes: int
    outcome: str
    def __bool__(self): raise TypeError('Staged metadata is not permission')


@dataclass(frozen=True)
class DiscardReceipt:
    binding_digest: str
    staged_digest: str
    released_bytes: int = 0
    def __bool__(self): raise TypeError('Discard evidence is not permission')


class QuarantinedReadExchange(FixtureBrokerExchange):
    """Bind -> stage/deny -> discard -> acknowledged discard, once per endpoint.

    Every frame binds the previous frame hash, exact context and fresh session.
    Decoded data is held privately in the coordinator and never returned. Closing,
    expiry, discard and every rejected transition clear that retained buffer.
    This is API separation, not a sandbox against hostile same-process code or a
    secure erasure guarantee for immutable Python/transport copies.
    """
    def __init__(self, *, role, key, session, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_quarantine_lifetime')
        super().__init__(role=role, key=key, session=session)
        self._step, self._previous = 0, '0'*64
        self._buffer = bytearray()
        self._deadline = monotonic()+timeout
        self._timer = Timer(timeout, self.close)
        self._timer.daemon = True
        try: self._timer.start()
        except Exception:
            self.close()
            raise BrokerProtocolError('quarantine_unavailable') from None

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.quarantined-read-draft.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _wipe(self):
        self._buffer[:] = b'\0'*len(self._buffer)
        self._buffer.clear()

    def _failed(self):
        self._wipe()
        self._step = 4
        self._timer.cancel()
        super()._failed()

    def _check(self, role, step):
        if self._role != role or self._step != step or self._state == 'closed' or monotonic() >= self._deadline:
            raise BrokerProtocolError('quarantine_unavailable')

    def _frame(self, direction, message):
        return self._encode(direction, dict(step=self._step, previous=self._previous, message_json=_canonical(message).decode('ascii')))

    def _message(self, direction, frame):
        value = self._decode(direction, frame)
        if (type(value) is not dict or set(value) != {'step', 'previous', 'message_json'}
                or type(value['step']) is not int or value['step'] != self._step
                or value['previous'] != self._previous or type(value['message_json']) is not str):
            raise ValueError('invalid_transcript')
        result = loads(value['message_json'], max_depth=3)
        if _canonical(result).decode('ascii') != value['message_json']: raise ValueError('noncanonical')
        return result

    def _advance(self, frame):
        if monotonic() >= self._deadline: raise ValueError('expired')
        self._step += 1
        self._previous = hashlib.sha256(frame).hexdigest()

    def _capture(self, context):
        self._binding = _context(context)
        self._binding_digest = hashlib.sha256(self._binding).hexdigest()
        self._size = loads(self._binding)['size_bytes']

    def request(self, context):
        with self._lock:
            try:
                self._check('coordinator', 0); self._capture(context)
                frame = self._frame('request', loads(self._binding)); self._advance(frame)
                return frame
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_request_rejected') from None

    def accept_request(self, frame):
        with self._lock:
            try:
                self._check('broker', 0); self._capture(self._message('request', frame))
                result = BrokerRequestEvidence(self._binding); self._advance(frame)
                return result
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_request_rejected') from None

    def _stage(self, outcome, data):
        if (type(outcome) is not str or outcome not in {'staged', 'denied'} or type(data) is not bytes
                or (outcome == 'denied' and data) or (outcome == 'staged' and len(data) != self._size)):
            raise ValueError('invalid_staged_data')
        self._digest = hashlib.sha256(data).hexdigest()
        return QuarantineSummary(self._binding_digest, self._digest, len(data), outcome)

    def reply(self, *, outcome, data=b''):
        with self._lock:
            try:
                self._check('broker', 1); self._stage(outcome, data)
                frame = self._frame('reply', dict(binding_digest=self._binding_digest, outcome=outcome,
                                                 data=base64.b64encode(data).decode('ascii')))
                self._advance(frame); return frame
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_stage_rejected') from None

    def accept_reply(self, frame):
        with self._lock:
            try:
                self._check('coordinator', 1); value = self._message('reply', frame)
                if (type(value) is not dict or set(value) != {'binding_digest', 'outcome', 'data'}
                        or value['binding_digest'] != self._binding_digest or type(value['data']) is not str
                        or len(value['data']) > 5464): raise ValueError('invalid_staging')
                data = base64.b64decode(value['data'], validate=True)
                if base64.b64encode(data).decode('ascii') != value['data']: raise ValueError('invalid_encoding')
                summary = self._stage(value['outcome'], data)
                self._buffer = bytearray(data)
                self._advance(frame); return summary
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_stage_rejected') from None

    def _discard_message(self):
        return dict(action='discard', binding_digest=self._binding_digest, staged_digest=self._digest)

    def discard(self):
        with self._lock:
            try:
                self._check('coordinator', 2); self._wipe()
                frame = self._frame('request', self._discard_message()); self._advance(frame)
                return frame
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_discard_rejected') from None

    def accept_discard(self, frame):
        with self._lock:
            try:
                self._check('broker', 2)
                if self._message('request', frame) != self._discard_message(): raise ValueError('not_discard')
                self._advance(frame)
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_discard_rejected') from None

    def _ack(self):
        return dict(outcome='discarded', binding_digest=self._binding_digest, staged_digest=self._digest, released_bytes=0)

    def acknowledge_discard(self):
        with self._lock:
            try:
                self._check('broker', 3)
                frame = self._frame('reply', self._ack()); self._advance(frame); self._failed()
                return frame
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_ack_rejected') from None

    def accept_discard_ack(self, frame):
        with self._lock:
            try:
                self._check('coordinator', 3)
                if _canonical(self._message('reply', frame)) != _canonical(self._ack()): raise ValueError('invalid_ack')
                result = DiscardReceipt(self._binding_digest, self._digest)
                self._advance(frame); self._failed(); return result
            except Exception:
                self._failed(); raise BrokerProtocolError('quarantine_ack_rejected') from None
