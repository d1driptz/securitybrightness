"""Inactive metadata-only publication commit contract. No transport or delivery.

A prepared/commit/receipt transcript is a claim, never permission or native peer
proof. Only dry_run_discard_only is supported; no data or publish message exists.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import re
from .broker_protocol import BrokerProtocolError, _canonical
from .broker_publication_protocol import _publication_binding
from .broker_recipient_protocol import RecipientWitnessExchange
from .json_input import loads

_MEANING = 'Inactive dry commit evidence; not authority, delivery or native peer proof.'


def _commit_binding(value):
    if type(value) is not dict or set(value) != {
            'revision', 'mode', 'commit_id', 'binding', 'staged_bytes', 'staged_digest', 'channel'}:
        raise ValueError('invalid_commit_binding')
    if (type(value['revision']) is not int or value['revision'] != 1
            or type(value['mode']) is not str or value['mode'] != 'dry_run_discard_only'
            or type(value['commit_id']) is not str or re.fullmatch('[0-9a-f]{64}', value['commit_id']) is None):
        raise ValueError('unsupported_commit')
    binding = loads(_publication_binding(value['binding']))
    if binding['recipient']['recipient_revision'] != 1:
        raise ValueError('unsupported_recipient_revision')
    channel = value['channel']
    if (type(channel) is not dict or set(channel) != {'pid', 'creation_time', 'witness_session'}
            or type(channel['pid']) is not int or not 0 < channel['pid'] <= 0xffffffff
            or type(channel['creation_time']) is not int or not 0 < channel['creation_time'] <= 0xffffffffffffffff
            or type(channel['witness_session']) is not str
            or re.fullmatch('[0-9a-f]{64}', channel['witness_session']) is None):
        raise ValueError('invalid_commit_channel_claim')
    identifiers = {item for item in (*binding['context'].values(), *binding['recipient'].values())
                   if type(item) is str}
    if (value['commit_id'] in identifiers or channel['witness_session'] in identifiers
            or value['commit_id'] == channel['witness_session']):
        raise ValueError('commit_identity_collision')
    count, digest = value['staged_bytes'], value['staged_digest']
    if (type(count) is not int or not 0 <= count <= binding['context']['max_bytes']
            or count != binding['context']['size_bytes']
            or type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None
            or (count == 0 and digest != hashlib.sha256(b'').hexdigest())):
        raise ValueError('invalid_commit_summary')
    return _canonical(dict(revision=1, mode='dry_run_discard_only', commit_id=value['commit_id'],
        binding=binding, staged_bytes=count, staged_digest=digest, channel=channel.copy()))


@dataclass(frozen=True)
class PublicationCommitEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    outcome: str
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default=_MEANING, init=False)
    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('Dry publication commit evidence is not permission')


class PublicationCommitExchange(RecipientWitnessExchange):
    """Prepare -> prepared -> dry_commit -> dry_run_retired, permanently spent.

    Reuses bounded canonical framing/transcript integrity, with a separate MAC
    domain, strict commit envelope and no inherited witness or data operations.
    Clocks, current authority and original native ownership belong to the draft.
    """
    _binding_bytes = staticmethod(_commit_binding)

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.inactive-publication-dry-commit.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _evidence(self, outcome):
        return PublicationCommitEvidence(self._binding_snapshot, self._binding_digest, outcome)

    def _checked_evidence(self, outcome):
        result = self._evidence(outcome)
        if (type(result) is not PublicationCommitEvidence
                or type(result.canonical_binding) is not bytes or result.canonical_binding != self._binding_snapshot
                or type(result.binding_digest) is not str or result.binding_digest != self._binding_digest
                or type(result.outcome) is not str or result.outcome != outcome
                or type(result.released_bytes) is not int or result.released_bytes != 0
                or type(result.meaning) is not str or result.meaning != _MEANING):
            raise ValueError('changed_commit_evidence')
        return result

    def _expected(self, phase):
        phases = {1: 'prepared', 2: 'dry_commit', 3: 'dry_run_retired'}
        if phase not in phases: raise ValueError('invalid_commit_phase')
        return dict(revision=1, mode='dry_run_discard_only', binding_digest=self._binding_digest,
                    outcome=phases[phase], released_bytes=0)

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
                raise BrokerProtocolError('publication_commit_rejected') from None

    def prepare(self, binding): return RecipientWitnessExchange.request(self, binding)
    def accept_prepare(self, frame):
        def operation():
            self._capture(self._message('request', frame))
            return self._checked_evidence('requested'), frame
        return self._exchange('broker', 0, operation)
    def ready(self): return self._send(1, 'broker', 'reply')
    def accept_ready(self, frame): return self._receive(1, 'coordinator', 'reply', frame, 'prepared')
    def dry_commit(self): return self._send(2, 'coordinator', 'request')
    def accept_dry_commit(self, frame): return self._receive(2, 'broker', 'request', frame, 'committing')
    def receipt(self): return self._send(3, 'broker', 'reply')
    def accept_receipt(self, frame): return self._receive(3, 'coordinator', 'reply', frame, 'dry_run_retired')

    def _unsupported(self, *args, **kwargs):
        self.close(); raise BrokerProtocolError('publication_commit_rejected')
    request = accept_request = prove = accept_proof = retire = accept_retirement = _unsupported
    acknowledge_retirement = accept_ack = reply = accept_reply = _unsupported
