"""Inactive metadata-only recipient witness; no I/O or byte delivery.

Trusted bootstrap owns both private endpoints. A proof shows only possession of
that session key for one exact logical binding. It does not authenticate an OS
peer, prove human review, create authority or permit later publication. The host
must separately enforce its bounded lifetime and native/process cleanup.
"""
from dataclasses import dataclass, field
import hashlib
import hmac

from .broker_protocol import FixtureBrokerExchange, BrokerProtocolError, _canonical
from .broker_publication_protocol import _publication_binding
from .json_input import loads

_MEANING = 'Metadata witness only; not OS peer identity, authority or delivery permission.'


@dataclass(frozen=True)
class RecipientWitnessEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    outcome: str
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('Recipient witness evidence is not permission')


class RecipientWitnessExchange(FixtureBrokerExchange):
    """One exact binding -> witnessed -> retire -> retired, then permanently spent.

    No data/read/publish command exists. The original key, role, session, binding
    and transcript state are snapshotted; any rejected call, wrong phase or
    mutation closes this endpoint. No retry, renewal or restored generation is
    supported. A pure codec has no independent clock or process-cleanup claim.
    """
    def __init__(self, *, role, key, session):
        super().__init__(role=role, key=key, session=session)
        self._step, self._previous = 0, '0'*64
        self._binding_digest = self._binding_snapshot = None
        self._key_snapshot = hashlib.sha256(self._key).hexdigest()
        self._role_snapshot, self._session_snapshot = self._role, self._session
        self._phase_snapshot = (self._step, self._previous, self._state)

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.inactive-recipient-witness.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    @staticmethod
    def _binding_bytes(value):
        snapshot = _publication_binding(value)
        if loads(snapshot)['recipient']['recipient_revision'] != 1:
            raise ValueError('unsupported_recipient_revision')
        return snapshot

    def _integrity(self, *, captured=False):
        if (type(self._state) is not str or self._state != 'new'
                or type(self._step) is not int or not 0 <= self._step < 4
                or type(self._previous) is not str
                or type(self._phase_snapshot) is not tuple
                or (self._step, self._previous, self._state) != self._phase_snapshot
                or type(self._role) is not str or type(self._role_snapshot) is not str or self._role != self._role_snapshot
                or type(self._session) is not str or type(self._session_snapshot) is not str or self._session != self._session_snapshot
                or type(self._key) is not bytes or len(self._key) != 32
                or type(self._key_snapshot) is not str
                or hashlib.sha256(self._key).hexdigest() != self._key_snapshot):
            raise ValueError('changed_witness_exchange')
        if self._step == 0 and not captured:
            if self._binding is not None or self._binding_snapshot is not None or self._binding_digest is not None:
                raise ValueError('unexpected_witness_binding')
        elif (type(self._binding) is not bytes or type(self._binding_snapshot) is not bytes
                or self._binding != self._binding_snapshot
                or self._binding_bytes(loads(self._binding)) != self._binding_snapshot
                or type(self._binding_digest) is not str
                or self._binding_digest != hashlib.sha256(self._binding_snapshot).hexdigest()):
            raise ValueError('changed_witness_binding')

    def _check(self, role, step):
        self._integrity()
        if self._role != role or self._step != step:
            raise ValueError('wrong_witness_phase')

    def _capture(self, value):
        self._binding = self._binding_snapshot = self._binding_bytes(value)
        self._binding_digest = hashlib.sha256(self._binding).hexdigest()

    def _frame(self, direction, message):
        return self._encode(direction, dict(step=self._step, previous=self._previous,
                                          message_json=_canonical(message).decode('ascii')))

    def _message(self, direction, frame):
        value = self._decode(direction, frame)
        if (type(value) is not dict or set(value) != {'step', 'previous', 'message_json'}
                or type(value['step']) is not int or value['step'] != self._step
                or type(value['previous']) is not str or value['previous'] != self._previous
                or type(value['message_json']) is not str):
            raise ValueError('invalid_witness_transcript')
        message = loads(value['message_json'], max_depth=3)
        if _canonical(message).decode('ascii') != value['message_json']:
            raise ValueError('noncanonical_witness_message')
        return message

    def _advance(self, frame):
        self._step += 1
        self._previous = hashlib.sha256(frame).hexdigest()
        self._phase_snapshot = (self._step, self._previous, self._state)

    def _evidence(self, outcome):
        return RecipientWitnessEvidence(self._binding_snapshot, self._binding_digest, outcome)

    def _checked_evidence(self, outcome):
        result = self._evidence(outcome)
        if (type(result) is not RecipientWitnessEvidence
                or type(result.canonical_binding) is not bytes or result.canonical_binding != self._binding_snapshot
                or type(result.binding_digest) is not str or result.binding_digest != self._binding_digest
                or type(result.outcome) is not str or result.outcome != outcome
                or type(result.released_bytes) is not int or result.released_bytes != 0
                or type(result.meaning) is not str or result.meaning != _MEANING):
            raise ValueError('changed_witness_evidence')
        return result

    def _expected(self, phase):
        if phase == 1:
            return dict(binding_digest=self._binding_digest, outcome='witnessed')
        if phase == 2:
            return dict(binding_digest=self._binding_digest, action='retire')
        if phase == 3:
            return dict(binding_digest=self._binding_digest, action='retire',
                        outcome='witnessed', lifecycle='retired', released_bytes=0)
        raise ValueError('invalid_witness_phase')

    def _failed(self):
        self._step = 4
        self._binding_snapshot = self._binding_digest = None
        FixtureBrokerExchange._failed(self)
        self._phase_snapshot = (self._step, self._previous, self._state)

    def _exchange(self, role, step, operation):
        with self._lock:
            try:
                self._check(role, step)
                result, frame = operation()
                # Frame/evidence construction may run injected hooks in tests.
                # Nothing escapes after a reentrant close or state substitution.
                self._integrity(captured=step == 0)
                self._advance(frame)
                if self._step == 4: self._failed()
                else: self._integrity()
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('recipient_witness_rejected') from None

    def request(self, binding):
        def operation():
            self._capture(binding)
            frame = self._frame('request', loads(self._binding))
            if self._binding_bytes(self._message('request', frame)) != self._binding_snapshot:
                raise ValueError('changed_witness_frame')
            return frame, frame
        return self._exchange('coordinator', 0, operation)

    def accept_request(self, frame):
        def operation():
            self._capture(self._message('request', frame))
            return self._checked_evidence('requested'), frame
        return self._exchange('broker', 0, operation)

    def _send(self, step, role, direction):
        def operation():
            frame = self._frame(direction, self._expected(step))
            if _canonical(self._message(direction, frame)) != _canonical(self._expected(step)):
                raise ValueError('changed_witness_frame')
            return frame, frame
        return self._exchange(role, step, operation)

    def _receive(self, step, role, direction, frame, outcome):
        def operation():
            if _canonical(self._message(direction, frame)) != _canonical(self._expected(step)):
                raise ValueError('witness_binding_mismatch')
            return self._checked_evidence(outcome), frame
        return self._exchange(role, step, operation)

    def prove(self): return self._send(1, 'broker', 'reply')
    def accept_proof(self, frame): return self._receive(1, 'coordinator', 'reply', frame, 'witnessed')
    def retire(self): return self._send(2, 'coordinator', 'request')
    def accept_retirement(self, frame): return self._receive(2, 'broker', 'request', frame, 'retiring')
    def acknowledge_retirement(self): return self._send(3, 'broker', 'reply')
    def accept_ack(self, frame): return self._receive(3, 'coordinator', 'reply', frame, 'retired')

    def close(self):
        with self._lock: self._failed()

    # Inherited fixture methods have unrelated semantics and must not offer an
    # alternate authority/data path on this metadata-only profile.
    def reply(self, **kwargs):
        self.close(); raise BrokerProtocolError('recipient_witness_rejected')
    def accept_reply(self, frame):
        self.close(); raise BrokerProtocolError('recipient_witness_rejected')

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
