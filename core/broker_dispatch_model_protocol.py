"""Inactive bounded dispatch model. Metadata claims only; no data or I/O.

Visibility and receiver receipt are model claims, never authorization, native
peer truth or observed delivery. The nested commit remains discard-only.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import re

from .broker_protocol import BrokerProtocolError, MAX_BODY_BYTES, _canonical
from .broker_publication_commit_protocol import _commit_binding
from .broker_recipient_protocol import RecipientWitnessExchange
from .json_input import loads

_MEANING = 'Inactive dispatch model claim; not authority, transport or delivery proof.'


def _dispatch_binding(value):
    if type(value) is not dict or set(value) != {'revision', 'mode', 'attempt_id', 'commit'}:
        raise ValueError('invalid_dispatch_binding')
    if (type(value['revision']) is not int or value['revision'] != 1
            or type(value['mode']) is not str or value['mode'] != 'dispatch_model_only'
            or type(value['attempt_id']) is not str
            or re.fullmatch('[0-9a-f]{64}', value['attempt_id']) is None):
        raise ValueError('unsupported_dispatch_model')
    commit = loads(_commit_binding(value['commit']))
    identifiers = {commit['commit_id'], commit['channel']['witness_session']}
    identifiers.update(item for item in (*commit['binding']['context'].values(),
                                        *commit['binding']['recipient'].values())
                       if type(item) is str)
    if value['attempt_id'] in identifiers:
        raise ValueError('dispatch_identity_collision')
    snapshot = _canonical(dict(revision=1, mode='dispatch_model_only',
                               attempt_id=value['attempt_id'], commit=commit))
    if len(snapshot) > MAX_BODY_BYTES:
        raise ValueError('dispatch_model_too_large')
    return snapshot


@dataclass(frozen=True)
class DispatchModelEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    outcome: str
    claimed_bytes: int | None = None
    claimed_digest: str | None = None
    observed_delivery: str = field(default='unproven', init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('Dispatch model evidence is not permission or delivery proof')


class PublicationDispatchExchange(RecipientWitnessExchange):
    """Prepare -> prepared -> visibility model -> receiver claim, then spent.

    This pure codec has no independent authority, clock, transport or delivery
    observation. Its sole receipt is an exact count/digest claim bound to the
    original discard-only commit; loss of that receipt cannot permit retry.
    """
    _binding_bytes = staticmethod(_dispatch_binding)

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.inactive-dispatch-model.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _message(self, direction, frame):
        value = self._decode(direction, frame)
        if (type(value) is not dict or set(value) != {'step', 'previous', 'message_json'}
                or type(value['step']) is not int or value['step'] != self._step
                or type(value['previous']) is not str or value['previous'] != self._previous
                or type(value['message_json']) is not str):
            raise ValueError('invalid_dispatch_transcript')
        # The strict dispatch -> commit -> action/recipient nesting needs more
        # depth than the original witness. Framing still bounds the whole body.
        message = loads(value['message_json'], max_depth=6)
        if _canonical(message).decode('ascii') != value['message_json']:
            raise ValueError('noncanonical_dispatch_message')
        return message

    def _evidence(self, outcome):
        commit = loads(self._binding_snapshot)['commit']
        claimed = outcome == 'receiver_claimed'
        return DispatchModelEvidence(self._binding_snapshot, self._binding_digest, outcome,
            commit['staged_bytes'] if claimed else None, commit['staged_digest'] if claimed else None)

    def _checked_evidence(self, outcome):
        result = self._evidence(outcome)
        commit = loads(self._binding_snapshot)['commit']
        claimed = outcome == 'receiver_claimed'
        if (type(result) is not DispatchModelEvidence
                or type(result.canonical_binding) is not bytes or result.canonical_binding != self._binding_snapshot
                or type(result.binding_digest) is not str or result.binding_digest != self._binding_digest
                or type(result.outcome) is not str or result.outcome != outcome
                or (claimed and (type(result.claimed_bytes) is not int or result.claimed_bytes != commit['staged_bytes']
                    or type(result.claimed_digest) is not str or result.claimed_digest != commit['staged_digest']))
                or (not claimed and (result.claimed_bytes is not None or result.claimed_digest is not None))
                or type(result.observed_delivery) is not str or result.observed_delivery != 'unproven'
                or type(result.meaning) is not str or result.meaning != _MEANING):
            raise ValueError('changed_dispatch_evidence')
        return result

    def _expected(self, phase):
        phases = {1: 'prepared', 2: 'visibility_possible', 3: 'receiver_claimed'}
        if phase not in phases:
            raise ValueError('invalid_dispatch_phase')
        result = dict(revision=1, mode='dispatch_model_only', binding_digest=self._binding_digest,
                      outcome=phases[phase])
        if phase == 3:
            commit = loads(self._binding_snapshot)['commit']
            result.update(claimed_bytes=commit['staged_bytes'], claimed_digest=commit['staged_digest'])
        return result

    def _exchange(self, role, step, operation):
        with self._lock:
            try:
                self._check(role, step)
                result, frame = operation()
                self._integrity(captured=step == 0)
                self._advance(frame)
                if self._step == 4: self._failed()
                else: self._integrity()
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('dispatch_model_rejected') from None

    def prepare(self, binding): return RecipientWitnessExchange.request(self, binding)

    def accept_prepare(self, frame):
        def operation():
            self._capture(self._message('request', frame))
            return self._checked_evidence('requested'), frame
        return self._exchange('broker', 0, operation)

    def ready(self): return self._send(1, 'broker', 'reply')
    def accept_ready(self, frame): return self._receive(1, 'coordinator', 'reply', frame, 'prepared')
    def model_visibility(self): return self._send(2, 'coordinator', 'request')
    def accept_model_visibility(self, frame):
        return self._receive(2, 'broker', 'request', frame, 'visibility_possible')

    def receipt_claim(self, *, claimed_bytes, claimed_digest):
        def operation():
            commit = loads(self._binding_snapshot)['commit']
            if (type(claimed_bytes) is not int or claimed_bytes != commit['staged_bytes']
                    or type(claimed_digest) is not str or claimed_digest != commit['staged_digest']):
                raise ValueError('invalid_dispatch_receipt_claim')
            frame = self._frame('reply', self._expected(3))
            if _canonical(self._message('reply', frame)) != _canonical(self._expected(3)):
                raise ValueError('changed_dispatch_receipt_frame')
            return frame, frame
        return self._exchange('broker', 3, operation)

    def accept_receipt_claim(self, frame):
        return self._receive(3, 'coordinator', 'reply', frame, 'receiver_claimed')

    def _unsupported(self, *args, **kwargs):
        self.close(); raise BrokerProtocolError('dispatch_model_rejected')

    request = accept_request = prove = accept_proof = retire = accept_retirement = _unsupported
    acknowledge_retirement = accept_ack = reply = accept_reply = _unsupported
    dry_commit = accept_dry_commit = receipt = accept_receipt = _unsupported
    data = read = publish = deliver = retire_for_check = accept_retirement_ack = _unsupported
