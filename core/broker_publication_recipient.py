"""Inactive trusted-local logical recipient owner. No channel or permission.

Trusted bootstrap distributes this owner separately from proposal data. Its
generated session/nonce distinguish a logical one-use recipient, not an OS peer,
process, person, network endpoint or authenticated delivery channel.
"""
from dataclasses import asdict, dataclass
import math
import re
import secrets
from threading import RLock, Timer
from time import monotonic
from .broker_protocol import _binding, _canonical


class PublicationRecipientError(ValueError):
    pass


@dataclass(frozen=True)
class RecipientDescriptor:
    application_id: str
    recipient_session: str
    recipient_id: str
    recipient_revision: int
    def __bool__(self): raise TypeError('A recipient descriptor is not permission')


class LogicalPublicationRecipient:
    """One trusted-bootstrap owner, one claim, irreversible close, <=5 seconds.

    No caller nonce, PID, path, callback, restoration, rotation or generation
    setter is accepted. close holds only its own lock and calls no coordinator.
    Lock order when composed: lifecycle -> recipient -> acquisition -> review
    -> registry -> ledger -> wire. A fresh owner never restores an old claim.
    """
    def __init__(self, application_id, *, timeout=5):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_recipient_lifetime')
        _binding(dict(application_id=application_id, proposal_id='sbp2_sha256_'+'c'*64,
                      resource_token='a'*64, decision_id='b'*64, max_bytes=1))
        session, identity = secrets.token_hex(32), secrets.token_hex(32)
        if (any(type(item) is not str or re.fullmatch('[0-9a-f]{64}', item) is None
                for item in (session, identity)) or session == identity):
            raise PublicationRecipientError('invalid_recipient_identity')
        self._lock = RLock()
        self._state = 'new'
        self._terminal = self._ever_claimed = False
        self._claim = self._timer = None
        self._descriptor = self._issued = RecipientDescriptor(application_id, session, identity, 1)
        self._snapshot = _canonical(asdict(self._descriptor))
        self._deadline = self._deadline_snapshot = monotonic()+timeout
        self._timer = Timer(timeout, self.close)
        self._timer.daemon = True
        try: self._timer.start()
        except Exception:
            self.close()
            raise PublicationRecipientError('recipient_unavailable') from None

    def _validate_descriptor(self):
        value = self._descriptor
        if (type(value) is not RecipientDescriptor or value is not self._issued
                or type(value.application_id) is not str or type(value.recipient_session) is not str
                or type(value.recipient_id) is not str or type(value.recipient_revision) is not int
                or _canonical(asdict(value)) != self._snapshot):
            raise PublicationRecipientError('changed_recipient')

    def _current(self):
        self._validate_descriptor()
        if (self._terminal is not False or self._state not in ('new', 'bound')
                or type(self._state) is not str or type(self._deadline) is not float
                or self._deadline != self._deadline_snapshot or monotonic() >= self._deadline_snapshot):
            raise PublicationRecipientError('recipient_unavailable')

    @property
    def descriptor(self):
        with self._lock:
            self._current()
            return self._issued

    def _claim_for(self, owner):
        self._current()
        if self._state != 'new' or self._claim is not None or self._ever_claimed is not False:
            raise PublicationRecipientError('recipient_already_claimed')
        self._claim, self._ever_claimed, self._state = owner, True, 'bound'

    def _current_for(self, owner):
        self._current()
        if self._state != 'bound' or self._claim is not owner or self._ever_claimed is not True:
            raise PublicationRecipientError('wrong_recipient_owner')

    def close(self):
        with self._lock:
            self._terminal, self._state, self._claim = True, 'closed', None
            if self._timer is not None: self._timer.cancel()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
