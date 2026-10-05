"""Inactive final-check quarantine transcript. No I/O, permission or delivery.

A peer retirement ACK is an authenticated cleanup claim, not native/process
cleanup proof. Coordinator bytes remain private until expiry, failure or close;
there is deliberately no publication/release API. Authority and recipient
freshness belong to a separate trusted live coordinator, never to this codec.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
from threading import Timer
from time import monotonic

from .broker_protocol import FixtureBrokerExchange, BrokerProtocolError, BrokerRequestEvidence, _canonical
from .broker_quarantine import QuarantinedReadExchange, QuarantineSummary, _context
from .json_input import loads


def _recipient(context, recipient):
    """Trusted endpoint descriptor claims; never requester-selected authority."""
    context = loads(_context(context))
    if (type(recipient) is not dict or set(recipient) != {'application_id', 'recipient_session', 'recipient_id', 'recipient_revision'}):
        raise ValueError('invalid_recipient')
    recipient = recipient.copy()
    if type(recipient['application_id']) is not str or recipient['application_id'] != context['application_id']:
        raise ValueError('recipient_application_mismatch')
    identifiers = [recipient[name] for name in ('recipient_session', 'recipient_id')]
    if (any(type(item) is not str or re.fullmatch('[0-9a-f]{64}', item) is None for item in identifiers)
            or len(set(identifiers)) != 2
            or set(identifiers) & {context[name] for name in ('review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token')}):
        raise ValueError('recipient_identity_collision')
    if type(recipient['recipient_revision']) is not int or not 1 <= recipient['recipient_revision'] <= 2**31-1:
        raise ValueError('invalid_recipient_revision')
    return recipient


def _publication_binding(value):
    if type(value) is not dict or set(value) != {'context', 'recipient'}:
        raise ValueError('invalid_publication_binding')
    value = value.copy()
    context = loads(_context(value['context']))
    recipient = _recipient(context, value['recipient'])
    return _canonical(dict(context=context, recipient=recipient))


@dataclass(frozen=True)
class RetiredForCheckReceipt:
    binding_digest: str
    staged_digest: str
    staged_bytes: int
    outcome: str = field(default='retired_for_check', init=False)
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default='Peer cleanup claim only; not permission or process-cleanup proof.', init=False)

    def __bool__(self):
        raise TypeError('Peer retirement evidence is not permission')


class PublicationCheckExchange(QuarantinedReadExchange):
    """Request -> staged/denied -> retire_for_check -> zero-release ACK.

    A distinct MAC domain forbids splicing the discard-only or older profiles.
    The immutable five-second lifetime also bounds coordinator retention AFTER
    ACK/key closure. Python buffer wiping is not a secure-erasure guarantee for
    immutable interpreter or transport copies, or hostile trusted-process code.
    """
    def __init__(self, *, role, key, session, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_publication_check_lifetime')
        FixtureBrokerExchange.__init__(self, role=role, key=key, session=session)
        self._step, self._previous = 0, '0'*64
        self._buffer = bytearray()
        self._issued_buffer = self._buffer
        self._deadline = monotonic()+timeout
        self._deadline_snapshot = self._deadline
        self._role_snapshot, self._session_snapshot = self._role, self._session
        self._key_digest = hashlib.sha256(self._key).hexdigest()
        self._context_snapshot = None
        self._summary_snapshot = None
        self._phase_snapshot = (self._step, self._previous, self._state)
        self._timer = Timer(timeout, self.close)
        self._timer_snapshot = self._timer
        self._timer.daemon = True
        try:
            self._timer.start()
        except Exception:
            self.close()
            raise BrokerProtocolError('publication_check_unavailable') from None

    def _mac(self, direction, body):
        domain = b'SecurityBrightness.final-publication-check-draft.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)

    def _wipe(self):
        # Keep the originally issued buffer reachable even if a mutated field
        # points elsewhere. Do not dispatch methods on requester-like objects.
        for buffer in (self._issued_buffer, self._buffer):
            if type(buffer) is bytearray:
                buffer[:] = b'\0'*len(buffer)
                buffer.clear()

    def _failed(self):
        self._wipe()
        try:
            self._timer_snapshot.cancel()
        finally:
            self._step = 4
            FixtureBrokerExchange._failed(self)
            self._phase_snapshot = (self._step, self._previous, self._state)

    def _integrity(self):
        if (type(self._deadline) is not float or self._deadline != self._deadline_snapshot
                or monotonic() >= self._deadline_snapshot
                or type(self._step) is not int
                or type(self._previous) is not str or type(self._state) is not str
                or (self._step, self._previous, self._state) != self._phase_snapshot
                or type(self._role) is not str or type(self._session) is not str
                or self._role != self._role_snapshot or self._session != self._session_snapshot
                or type(self._key) is not bytes or self._timer is not self._timer_snapshot
                or type(self._buffer) is not bytearray or self._buffer is not self._issued_buffer):
            raise ValueError('changed_exchange')
        if self._state == 'retired_for_check':
            if self._role != 'coordinator' or self._step != 4 or self._key:
                raise ValueError('changed_retirement')
        elif self._state == 'closed' or hashlib.sha256(self._key).hexdigest() != self._key_digest:
            raise ValueError('changed_key')
        if self._context_snapshot is None:
            if self._binding is not None or self._buffer or self._summary_snapshot is not None:
                raise ValueError('unexpected_context')
            return
        if (type(self._binding) is not bytes or self._binding != self._context_snapshot
                or _publication_binding(loads(self._binding)) != self._context_snapshot
                or type(self._binding_digest) is not str
                or self._binding_digest != hashlib.sha256(self._context_snapshot).hexdigest()
                or type(self._size) is not int or self._size != loads(self._context_snapshot)['context']['size_bytes']):
            raise ValueError('changed_context')
        if self._summary_snapshot is None:
            if self._buffer:
                raise ValueError('unexpected_buffer')
            return
        if type(self._summary_snapshot) is not tuple or len(self._summary_snapshot) != 4:
            raise ValueError('changed_staging')
        binding, digest, count, outcome = self._summary_snapshot
        if (type(self._digest) is not str or self._digest != digest
                or type(binding) is not str or type(digest) is not str or binding != self._binding_digest
                or type(count) is not int or not 0 <= count <= self._size
                or type(outcome) is not str or outcome not in ('staged', 'denied')
                or (outcome == 'staged' and count != self._size)
                or (outcome == 'denied' and (count or digest != hashlib.sha256(b'').hexdigest()))):
            raise ValueError('changed_staging')
        if self._role == 'coordinator':
            if len(self._buffer) != count or hashlib.sha256(self._buffer).hexdigest() != digest:
                raise ValueError('changed_buffer')
        elif self._buffer:
            raise ValueError('unexpected_peer_buffer')

    def _check(self, role, step):
        if self._role != role or self._step != step or self._state == 'retired_for_check':
            raise BrokerProtocolError('publication_check_unavailable')
        self._integrity()

    def _advance(self, frame):
        QuarantinedReadExchange._advance(self, frame)
        self._phase_snapshot = (self._step, self._previous, self._state)
        self._integrity()

    def _capture(self, context):
        self._binding = _publication_binding(context)
        self._context_snapshot = self._binding
        self._binding_digest = hashlib.sha256(self._binding).hexdigest()
        self._size = loads(self._binding)['context']['size_bytes']

    def _stage(self, outcome, data):
        summary = QuarantinedReadExchange._stage(self, outcome, data)
        if type(summary) is not QuarantineSummary:
            raise ValueError('invalid_staging_summary')
        self._summary_snapshot = (summary.binding_digest, summary.staged_digest, summary.staged_bytes, summary.outcome)
        return summary

    def request(self, context, recipient):
        with self._lock:
            try:
                self._check('coordinator', 0)
                self._capture(dict(context=context, recipient=recipient))
                frame = self._frame('request', loads(self._binding))
                self._integrity()
                self._advance(frame)
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_request_rejected') from None

    def accept_request(self, frame):
        with self._lock:
            try:
                self._check('broker', 0)
                self._capture(self._message('request', frame))
                result = BrokerRequestEvidence(self._binding)
                self._integrity()
                self._advance(frame)
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_request_rejected') from None

    def reply(self, *, outcome, data=b''):
        with self._lock:
            try:
                self._check('broker', 1)
                self._stage(outcome, data)
                frame = self._frame('reply', dict(binding_digest=self._binding_digest, outcome=outcome,
                                                data=base64.b64encode(data).decode('ascii')))
                self._integrity()
                self._advance(frame)
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_stage_rejected') from None

    def accept_reply(self, frame):
        with self._lock:
            try:
                self._check('coordinator', 1)
                value = self._message('reply', frame)
                if (type(value) is not dict or set(value) != {'binding_digest', 'outcome', 'data'}
                        or type(value['binding_digest']) is not str or value['binding_digest'] != self._binding_digest
                        or type(value['data']) is not str or len(value['data']) > 5464):
                    raise ValueError('invalid_staging')
                data = base64.b64decode(value['data'], validate=True)
                if base64.b64encode(data).decode('ascii') != value['data']:
                    raise ValueError('invalid_encoding')
                summary = self._stage(value['outcome'], data)
                self._buffer[:] = data
                self._integrity()
                self._advance(frame)
                return summary
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_stage_rejected') from None

    def _retirement(self):
        return dict(action='retire_for_check', binding_digest=self._binding_digest,
                    staged_digest=self._digest, staged_bytes=self._summary_snapshot[2])

    def retire_for_check(self):
        with self._lock:
            try:
                self._check('coordinator', 2)
                frame = self._frame('request', self._retirement())
                self._integrity()
                self._advance(frame)
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_retirement_rejected') from None

    def accept_retirement(self, frame):
        with self._lock:
            try:
                self._check('broker', 2)
                if _canonical(self._message('request', frame)) != _canonical(self._retirement()):
                    raise ValueError('invalid_retirement')
                self._integrity()
                self._advance(frame)
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_retirement_rejected') from None

    def _retirement_ack(self):
        return dict(outcome='retired_for_check', binding_digest=self._binding_digest,
                    staged_digest=self._digest, staged_bytes=self._summary_snapshot[2], released_bytes=0)

    def acknowledge_retirement(self):
        with self._lock:
            try:
                self._check('broker', 3)
                frame = self._frame('reply', self._retirement_ack())
                self._integrity()
                self._advance(frame)
                self._failed()
                return frame
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_ack_rejected') from None

    def accept_retirement_ack(self, frame):
        with self._lock:
            try:
                self._check('coordinator', 3)
                if _canonical(self._message('reply', frame)) != _canonical(self._retirement_ack()):
                    raise ValueError('invalid_ack')
                result = RetiredForCheckReceipt(self._binding_digest, self._digest, self._summary_snapshot[2])
                self._integrity()
                self._advance(frame)
                self._state, self._key = 'retired_for_check', b''
                self._phase_snapshot = (self._step, self._previous, self._state)
                self._integrity()
                return result
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_ack_rejected') from None

    def validate_retained(self):
        """Validate private retention without returning bytes or authority."""
        with self._lock:
            try:
                if self._state != 'retired_for_check':
                    raise ValueError('not_retired')
                self._integrity()
            except Exception:
                self._failed()
                raise BrokerProtocolError('publication_check_retention_rejected') from None

    def _unsupported(self, *args, **kwargs):
        with self._lock:
            self._failed()
            raise BrokerProtocolError('publication_check_profile_mismatch') from None

    # Older discard profile methods cannot shorten or change this transcript.
    discard = accept_discard = acknowledge_discard = accept_discard_ack = _unsupported
