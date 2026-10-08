"""Inactive original-source/native-recipient association metadata contract.

The source dry-commit envelope remains unchanged and is merely a claim here.
Trusted composition must separately check original authority, lifecycle and
native ownership. This codec cannot authorize delivery or verify source truth.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import re
from threading import RLock
from uuid import UUID

from .broker_protocol import BrokerProtocolError, MAX_BODY_BYTES, _canonical
from .broker_publication_commit_protocol import _commit_binding
from .broker_recipient_protocol import RecipientWitnessExchange
from .json_input import loads

_MODE = 'source_native_association_discard_only'
_MEANING = 'Inactive source/native association claim; not authority or delivery permission'
_RLOCK_TYPE = type(RLock())


def _association_binding(value):
    if type(value) is not dict or set(value) != {
            'revision', 'mode', 'association_id', 'source_commit_json',
            'grant_id', 'grant_fingerprint', 'recipient_channel'}:
        raise ValueError('invalid_source_association')
    value = value.copy()
    if (type(value['revision']) is not int or value['revision'] != 1
            or type(value['mode']) is not str or value['mode'] != _MODE):
        raise ValueError('unsupported_source_association')
    for name in ('association_id', 'grant_fingerprint'):
        if type(value[name]) is not str or re.fullmatch('[0-9a-f]{64}', value[name]) is None:
            raise ValueError('invalid_source_association_identity')
    text = value['source_commit_json']
    if type(text) is not str or not 1 <= len(text) <= MAX_BODY_BYTES:
        raise ValueError('invalid_source_commit_claim')
    encoded = text.encode('ascii')
    source = loads(encoded, max_depth=3)
    if _commit_binding(source) != encoded:
        raise ValueError('noncanonical_source_commit_claim')
    grant_id = value['grant_id']
    if (type(grant_id) is not str or len(grant_id) != 36
            or str(UUID(grant_id)) != grant_id
            or grant_id != source['binding']['context']['grant_id']):
        raise ValueError('source_association_grant_mismatch')
    channel = value['recipient_channel']
    if (type(channel) is not dict or set(channel) != {'pid', 'creation_time', 'witness_session'}
            or type(channel['pid']) is not int or not 0 < channel['pid'] <= 0xffffffff
            or type(channel['creation_time']) is not int or not 0 < channel['creation_time'] <= 0xffffffffffffffff
            or type(channel['witness_session']) is not str
            or re.fullmatch('[0-9a-f]{64}', channel['witness_session']) is None):
        raise ValueError('invalid_association_recipient_channel')
    channel = channel.copy()
    old = source['channel']
    if (channel['pid'], channel['creation_time']) == (old['pid'], old['creation_time']):
        raise ValueError('source_recipient_channel_reuse')
    identifiers = {item for item in (*source['binding']['context'].values(),
                                    *source['binding']['recipient'].values()) if type(item) is str}
    identifiers.update((source['commit_id'], old['witness_session']))
    if (value['association_id'] == channel['witness_session']
            or value['association_id'] in identifiers or channel['witness_session'] in identifiers):
        raise ValueError('source_association_identity_collision')
    snapshot = _canonical(dict(revision=1, mode=_MODE, association_id=value['association_id'],
        source_commit_json=text, grant_id=grant_id, grant_fingerprint=value['grant_fingerprint'],
        recipient_channel=channel))
    if len(snapshot) > MAX_BODY_BYTES:
        raise ValueError('source_association_binding_too_large')
    return snapshot


@dataclass(frozen=True)
class SourceRecipientAssociationEvidence:
    canonical_binding: bytes = field(repr=False)
    binding_digest: str
    outcome: str
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default=_MEANING, init=False)

    def inspect(self): return loads(self.canonical_binding)
    def __bool__(self): raise TypeError('Source/native association evidence is not permission')


class SourceRecipientAssociationExchange(RecipientWitnessExchange):
    """Associate -> associated_ready -> source_discarded -> associated_retired.

    Four strictly bound metadata phases, one use per endpoint. No data operation
    exists, and a source-discard claim cannot grant or prove delivery authority.
    The trusted coordinator owns clocks and original source/native cleanup.
    """
    _binding_bytes = staticmethod(_association_binding)

    def __init__(self, *, role, key, session):
        if type(key) is bytes and type(session) is bytes and key == session:
            raise BrokerProtocolError('invalid_association_bootstrap')
        super().__init__(role=role, key=key, session=session)
        self._issued_lock = self._lock

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.inactive-source-native-association.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _capture(self, value):
        super()._capture(value)
        if loads(self._binding)['recipient_channel']['witness_session'] != self._session:
            raise ValueError('association_recipient_session_mismatch')

    def _integrity(self, *, captured=False):
        if (type(self._lock) is not _RLOCK_TYPE or self._lock is not self._issued_lock):
            raise ValueError('changed_source_association_lock')
        super()._integrity(captured=captured)
        if self._binding_snapshot is not None:
            if loads(self._binding_snapshot)['recipient_channel']['witness_session'] != self._session:
                raise ValueError('association_recipient_session_mismatch')

    def _evidence(self, outcome):
        return SourceRecipientAssociationEvidence(self._binding_snapshot, self._binding_digest, outcome)

    def _checked_evidence(self, outcome):
        result = self._evidence(outcome)
        if (type(result) is not SourceRecipientAssociationEvidence
                or type(result.canonical_binding) is not bytes or result.canonical_binding != self._binding_snapshot
                or type(result.binding_digest) is not str or result.binding_digest != self._binding_digest
                or type(result.outcome) is not str or result.outcome != outcome
                or type(result.released_bytes) is not int or result.released_bytes != 0
                or type(result.meaning) is not str or result.meaning != _MEANING):
            raise ValueError('changed_source_association_evidence')
        return result

    def _expected(self, phase):
        outcomes = {1: 'associated_ready', 2: 'source_discarded', 3: 'associated_retired'}
        if phase not in outcomes: raise ValueError('invalid_source_association_phase')
        return dict(revision=1, mode=_MODE, binding_digest=self._binding_digest,
                    outcome=outcomes[phase], released_bytes=0)

    def _exchange(self, role, step, operation):
        with self._original_lock():
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
                raise BrokerProtocolError('source_association_rejected') from None

    def _original_lock(self):
        lock = self.__dict__.get('_issued_lock')
        if type(lock) is not _RLOCK_TYPE or self.__dict__.get('_lock') is not lock:
            self._failed()
            raise BrokerProtocolError('source_association_rejected')
        return lock

    def close(self):
        with self._original_lock(): self._failed()

    def accept_proof(self, frame):
        return self._receive(1, 'coordinator', 'reply', frame, 'associated_ready')
    def accept_retirement(self, frame):
        return self._receive(2, 'broker', 'request', frame, 'source_discarded')
    def accept_ack(self, frame):
        return self._receive(3, 'coordinator', 'reply', frame, 'associated_retired')

    def _unsupported(self, *args, **kwargs):
        self.close(); raise BrokerProtocolError('source_association_rejected')
    reply = accept_reply = prepare = accept_prepare = ready = accept_ready = _unsupported
    dry_commit = accept_dry_commit = receipt = accept_receipt = _unsupported
    model_visibility = accept_model_visibility = receipt_claim = accept_receipt_claim = _unsupported
    payload = accept_payload = data = publish = release = acquire = _unsupported
