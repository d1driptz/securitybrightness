"""Inactive bounded live ownership of generated fixtures; no read or grant API.

Not wired into child IPC, /check or the existing protected reader. Session/token
lookup establishes local ownership only, never application or human authority.
"""
from dataclasses import dataclass
import re
import secrets
from threading import RLock
from time import monotonic

from .broker_resource import BrokerFixtureOwner, BrokerResourceError


@dataclass(frozen=True)
class SessionObservation:
    session_id: str
    resource_token: str
    description: object

    def __bool__(self):
        raise TypeError('Live fixture ownership is not permission')


class BrokerResourceSession:
    """Fixed sixty-second lifetime; capacity counts retired tokens as well.

    Any failed operation retires the whole session. Cancellation is close();
    it serializes with verification and cannot retroactively recall a receipt.
    Explicit context-managed cleanup is required in trusted bootstrap code.
    """
    def __init__(self, *, capacity=4):
        if type(capacity) is not int or not 1 <= capacity <= 8:
            raise BrokerResourceError('invalid_capacity')
        self._lock = RLock()
        self._session = secrets.token_hex(32)
        if type(self._session) is not str or re.fullmatch('[0-9a-f]{64}', self._session) is None:
            raise BrokerResourceError('invalid_session')
        self._capacity = capacity
        self._deadline = monotonic()+60
        self._records = {}
        self._owner_sessions = set()
        self._closed = False

    def _current(self):
        if self._closed or monotonic() >= self._deadline:
            raise BrokerResourceError('session_unavailable')

    def issue(self, application_id, proposal, decision_id):
        with self._lock:
            owner = None
            try:
                self._current()
                if len(self._records) >= self._capacity:
                    raise BrokerResourceError('capacity_exhausted')
                owner = BrokerFixtureOwner()
                description = owner.describe()
                token = description.resource_token
                if (token in self._records or description.session in self._owner_sessions
                        or self._session in {token,description.session}):
                    raise BrokerResourceError('identifier_collision')
                binding = owner.bind(application_id, proposal, decision_id)
                self._current()
                # Only issued objects and bindings are stored; no deserialization
                # or token-selected path/handle acquisition occurs on lookup.
                self._records[token] = (owner,binding)
                self._owner_sessions.add(description.session)
                observation = SessionObservation(self._session,token,description)
                owner = None  # Ownership transferred to records, including on errors.
                self._current()
                return observation
            except Exception:
                try:
                    if owner is not None: owner.close()
                finally:
                    self.close()
                raise BrokerResourceError('session_issue_rejected') from None

    def verify_once(self, session_id, resource_token, application_id, proposal, decision_id):
        with self._lock:
            owner = None
            try:
                self._current()
                if (type(session_id) is not str or session_id != self._session
                        or type(resource_token) is not str
                        or re.fullmatch('[0-9a-f]{64}',resource_token) is None):
                    raise BrokerResourceError('invalid_lookup')
                record = self._records.get(resource_token)
                if record is None:
                    raise BrokerResourceError('unknown_or_retired_token')
                # Retire before any native calls. Failures never restore a slot.
                self._records[resource_token] = None
                owner,binding = record
                result = owner.verify_once(binding,application_id,proposal,decision_id)
                owner = None  # verify_once successfully closed it.
                self._current()
                return result
            except Exception:
                try:
                    if owner is not None: owner.close()
                finally:
                    self.close()
                raise BrokerResourceError('session_verification_rejected') from None

    def close(self):
        with self._lock:
            self._closed = True
            failed = False
            for token,record in self._records.items():
                self._records[token] = None
                if record is not None:
                    try: record[0].close()
                    except Exception: failed = True
            if failed:
                raise BrokerResourceError('session_cleanup_failed')

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()
