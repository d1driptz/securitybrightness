"""Inactive dispatch-loss model. No I/O, data, current authority or capability.

Binding fields are claims. An irreversible modeled visibility barrier precedes
notice encoding; any later uncertainty stays spent/unknown. This model cannot
authorize a transport operation, consume a real grant or prove actual delivery.
"""
from dataclasses import dataclass, field, asdict
import hashlib
import math
import secrets
from threading import Event, RLock, Timer
from time import monotonic
from .broker_dispatch_model_protocol import PublicationDispatchExchange, DispatchModelEvidence, _dispatch_binding
from .broker_publication_commit_protocol import _commit_binding
from .json_input import loads

_MEANING = 'Inactive dispatch attempt model; not authority, transport or delivery proof.'
_TERMINAL = ('not_started', 'receiver_claimed', 'outcome_unknown')
_LOCK_TYPE = type(RLock())


class DispatchAttemptError(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchAttemptSnapshot:
    attempt_id: str
    binding_digest: str
    state: str
    visibility_possible: bool
    model_written_bytes: int
    receiver_claimed_bytes: int | None
    observed_delivery: str = field(default='unproven', init=False)
    meaning: str = field(default=_MEANING, init=False)
    def __bool__(self): raise TypeError('A dispatch model snapshot is not permission')


def _values(value):
    return tuple((name, type(item), item) for name, item in asdict(value).items())


def _agreed(values, expected_type):
    # Recover only an original reference corroborated by independent aliases.
    # This handles a single corrupted field, not hostile trusted-process code.
    for value in values:
        if type(value) is expected_type and sum(item is value for item in values) >= 2:
            return value
    raise DispatchAttemptError('uncertain_model_ownership')


class PublicationDispatchLedger:
    """Bounded session-local model claims; no eviction, restoration or restart.

    Each original decision ID and resource token is claimed once in this ledger.
    Callers can construct claims, including new IDs/ledgers; none proves authority.
    Lock order is this original ledger only; no native/registry lock or wait exists.
    """
    def __init__(self, *, max_attempts=128):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 128:
            raise ValueError('invalid_model_capacity')
        self._lock = self._issued_lock = RLock()
        self._cleanup_lock = self._lock
        self._capacity = self._capacity_snapshot = max_attempts
        self._records = self._issued_records = {}
        self._sources = self._issued_sources = {}
        self._decisions = self._issued_decisions = {}
        self._origins = self._issued_origins = ()
        self._cleanup_origins = ()
        self._journal = self._issued_journal = ()
        self._closed = self._closed_snapshot = self._tainted = False

    def _guard(self):
        aliases = tuple(getattr(self, name, None) for name in ('_lock', '_issued_lock', '_cleanup_lock'))
        lock = _agreed(aliases, _LOCK_TYPE)
        if any(value is not lock for value in aliases):
            with lock: self._poison()
            raise DispatchAttemptError('changed_model_ledger')
        return lock

    def _original_origins(self):
        origins = _agreed(tuple(getattr(self, name, None) for name in
            ('_origins', '_issued_origins', '_cleanup_origins')), tuple)
        if len(origins) > 128: raise DispatchAttemptError('uncertain_model_ownership')
        for origin in origins:
            if (type(origin) is not tuple or len(origin) != 9
                    or type(origin[0]) is not PublicationDispatchAttempt
                    or type(origin[1]) is not PublicationDispatchExchange
                    or type(origin[2]) is not Timer or type(origin[3]) is not Event):
                raise DispatchAttemptError('uncertain_model_ownership')
            owner = origin[0]
            ownership = _agreed(tuple(getattr(owner, name, None) for name in
                ('_ownership', '_issued_ownership', '_recovery_ownership')), tuple)
            if len(ownership) != 2 or ownership[0] is not self:
                raise DispatchAttemptError('uncertain_model_ownership')
        return origins

    def _integrity(self):
        if (self._tainted is not False or type(self._closed) is not bool or self._closed is not self._closed_snapshot
                or type(self._capacity) is not int or type(self._capacity_snapshot) is not int or self._capacity != self._capacity_snapshot
                or self._records is not self._issued_records or type(self._records) is not dict
                or self._sources is not self._issued_sources or type(self._sources) is not dict
                or self._decisions is not self._issued_decisions or type(self._decisions) is not dict
                or self._origins is not self._issued_origins or self._origins is not self._cleanup_origins or type(self._origins) is not tuple
                or self._journal is not self._issued_journal or type(self._journal) is not tuple
                or len(self._origins) > self._capacity or len(self._journal) > self._capacity*8):
            raise DispatchAttemptError('changed_model_ledger')
        expected = dict(self._journal)
        if (set(self._records) != set(expected)
                or any(self._records[key] is not value for key, value in expected.items())
                or self._sources != {o[6]: o[0]._attempt_id for o in self._origins}
                or self._decisions != {o[7]: o[0]._attempt_id for o in self._origins}
                or len(expected) != len(self._origins)):
            raise DispatchAttemptError('changed_model_ledger')

    def open(self, commit, *, key, session, timeout=5):
        with self._guard():
            try: self._integrity()
            except Exception:
                self._poison()
                raise DispatchAttemptError('changed_model_ledger') from None
            if self._closed: raise DispatchAttemptError('closed_model_ledger')
            if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
                raise ValueError('invalid_model_lifetime')
            # No unrelated claim is spent until the entire bounded input validates.
            try:
                commit = loads(_commit_binding(commit))
                context = commit['binding']['context']
                source, decision = context['resource_token'], context['decision_id']
                if source in self._sources or decision in self._decisions or len(self._origins) >= self._capacity:
                    raise ValueError('duplicate_or_full_model')
                for _ in range(8):
                    identifier = secrets.token_hex(32)
                    try:
                        envelope = _dispatch_binding(dict(revision=1, mode='dispatch_model_only',
                            attempt_id=identifier, commit=commit))
                    except ValueError: continue
                    if identifier not in self._records: break
                else: raise ValueError('model_identity_unavailable')
                wire = PublicationDispatchExchange(role='coordinator', key=key, session=session)
            except Exception:
                raise DispatchAttemptError('invalid_model_claim') from None
            attempt = object.__new__(PublicationDispatchAttempt)
            attempt._ledger = attempt._issued_ledger = self
            attempt._ownership = attempt._issued_ownership = (self, self._issued_lock)
            attempt._recovery_ownership = attempt._ownership
            attempt._attempt_id = identifier
            attempt._envelope = attempt._envelope_snapshot = envelope
            attempt._wire = attempt._issued_wire = wire
            attempt._wire_identity = tuple((type(x), x) for x in (wire._role, wire._role_snapshot,
                wire._session, wire._session_snapshot, wire._key_snapshot))
            attempt._deadline = attempt._deadline_snapshot = monotonic()+timeout
            attempt._cancel = attempt._issued_cancel = Event()
            attempt._cancelled = False
            attempt._state, attempt._attempted, attempt._visibility_possible = 'new', False, False
            attempt._model_written_bytes, attempt._claim = 0, None
            attempt._snapshot = attempt._issued_snapshot = None
            timer = attempt._timer = attempt._issued_timer = Timer(timeout, attempt.close)
            timer.daemon = True
            origin = (attempt, wire, timer, attempt._cancel, envelope, attempt._deadline, source, decision, attempt._wire_identity)
            self._origins = self._issued_origins = self._cleanup_origins = self._origins+(origin,)
            self._sources[source], self._decisions[decision] = identifier, identifier
            try:
                self._save(attempt, 'new', False, False, 0, None)
                timer.start()
            except Exception:
                try: self._terminate(attempt)
                except Exception: self._poison()
                raise DispatchAttemptError('model_unavailable') from None
            return attempt

    def _origin(self, attempt):
        for origin in self._original_origins():
            if origin[0] is attempt: return origin
        raise DispatchAttemptError('foreign_model_attempt')

    def _save(self, attempt, state, attempted, possible, written, claim):
        origin = self._origin(attempt)
        envelope = loads(origin[4])
        snapshot = DispatchAttemptSnapshot(envelope['attempt_id'], hashlib.sha256(origin[4]).hexdigest(),
            state, possible, written, None if claim is None else claim.claimed_bytes)
        wire = origin[1]
        record = (attempt, state, attempted, possible, written, claim,
                  None if claim is None else _values(claim), wire._step, wire._previous, snapshot, _values(snapshot))
        self._issued_records[envelope['attempt_id']] = record
        self._journal = self._issued_journal = self._issued_journal+((envelope['attempt_id'], record),)
        attempt._state, attempt._attempted, attempt._visibility_possible = state, attempted, possible
        attempt._model_written_bytes, attempt._claim = written, claim
        attempt._snapshot = attempt._issued_snapshot = snapshot

    def _dispose(self, origin):
        # Captured original endpoints/events/timers, never mutable attempt fields.
        try: origin[3].set()
        finally:
            try: origin[1].close()
            finally: origin[2].cancel()
        wire = origin[1]
        if (type(wire._state) is not str or wire._state != 'closed'
                or type(wire._step) is not int or wire._step != 4
                or type(wire._key) is not bytes or wire._key
                or wire._binding is not None or wire._binding_snapshot is not None or wire._binding_digest is not None
                or not origin[2].finished.is_set() or not origin[3].is_set()):
            raise DispatchAttemptError('uncertain_model_cleanup')

    def _terminate(self, attempt):
        origin = self._origin(attempt)
        record = self._issued_records[loads(origin[4])['attempt_id']]
        if record[1] in _TERMINAL:
            self._dispose(origin)
            return
        try: self._dispose(origin)
        finally:
            self._save(attempt, 'outcome_unknown' if record[3] else 'not_started', True,
                record[3], record[4], None)
            attempt._cancelled = True

    def _poison(self):
        self._tainted, self._closed, self._closed_snapshot = True, True, True
        failed = False
        for origin in self._original_origins():
            try: self._dispose(origin)
            except BaseException: failed = True
        if failed: raise DispatchAttemptError('model_cleanup_failed') from None

    def close(self):
        with self._guard():
            try:
                self._integrity()
                self._closed = self._closed_snapshot = True
                for origin in self._issued_origins: self._terminate(origin[0])
                self._integrity()
            except Exception:
                self._poison()
                raise DispatchAttemptError('model_ledger_rejected') from None


class PublicationDispatchAttempt:
    """Created only by the model ledger. No authority booleans or execution port.

    One simulated local write observation is supported. A partial/zero write
    after the barrier is terminal unknown, never a safe retry or zero-delivery
    assertion. Future native chunking and authority integration are unproven.
    """
    def __init__(self, *args, **kwargs):
        raise TypeError('use the inactive model ledger')

    def _owner(self):
        try:
            if (self._ownership is not self._issued_ownership or self._ownership is not self._recovery_ownership or type(self._ownership) is not tuple
                    or len(self._ownership) != 2 or self._ledger is not self._ownership[0]
                    or self._issued_ledger is not self._ownership[0]
                    or type(self._ownership[0]) is not PublicationDispatchLedger
                    or self._ownership[1] is not self._ownership[0]._issued_lock):
                raise DispatchAttemptError('changed_model_owner')
            ledger = self._issued_ledger
            ledger._origin(self)
            return ledger
        except Exception:
            # Alias rejection must still spend/dispose the original claim.
            ownership = _agreed(tuple(getattr(self, name, None) for name in
                ('_ownership', '_issued_ownership', '_recovery_ownership')), tuple)
            if len(ownership) == 2:
                original, lock = ownership
                if type(original) is PublicationDispatchLedger and type(lock) is _LOCK_TYPE:
                    # Establish membership before touching any candidate ledger.
                    PublicationDispatchLedger._origin(original, self)
                    with lock:
                        try:
                            original._integrity(); original._terminate(self)
                        except Exception: original._poison()
            raise DispatchAttemptError('changed_model_owner') from None

    def _current(self, *, active=False, wire_transition=None):
        ledger = self._owner(); ledger._integrity()
        origin = ledger._origin(self)
        identifier = loads(origin[4])['attempt_id']
        record = ledger._records[identifier]
        if (self._attempt_id != identifier or type(self._attempt_id) is not str
                or self._envelope is not origin[4] or self._envelope_snapshot is not origin[4]
                or _dispatch_binding(loads(self._envelope)) != origin[4]
                or self._wire is not origin[1] or self._issued_wire is not origin[1]
                or self._timer is not origin[2] or self._issued_timer is not origin[2]
                or self._cancel is not origin[3] or self._issued_cancel is not origin[3]
                or type(self._deadline) is not float or self._deadline != origin[5]
                or type(self._deadline_snapshot) is not float or self._deadline_snapshot != origin[5]
                or record[0] is not self or type(self._state) is not str or self._state != record[1]
                or self._attempted is not record[2] or self._visibility_possible is not record[3]
                or type(self._model_written_bytes) is not int or self._model_written_bytes != record[4]
                or self._claim is not record[5] or (self._claim is not None and _values(self._claim) != record[6])
                or self._snapshot is not record[9] or self._issued_snapshot is not record[9]
                or type(self._snapshot) is not DispatchAttemptSnapshot or _values(self._snapshot) != record[10]):
            raise DispatchAttemptError('changed_model_attempt')
        wire = origin[1]
        step, previous = (record[7], record[8]) if wire_transition is None else wire_transition
        if (self._wire_identity is not origin[8]
                or type(wire) is not PublicationDispatchExchange or type(wire._step) is not int or wire._step != step
                or type(wire._previous) is not str or wire._previous != previous):
            raise DispatchAttemptError('changed_model_exchange')
        if self._state in _TERMINAL and step != 4:
            raise DispatchAttemptError('changed_model_retirement')
        if step == 4:
            if (type(wire._state) is not str or wire._state != 'closed' or type(wire._key) is not bytes or wire._key
                    or wire._binding is not None or wire._binding_snapshot is not None or wire._binding_digest is not None
                    or tuple((type(x), x) for x in (wire._role, wire._role_snapshot, wire._session,
                        wire._session_snapshot, wire._key_snapshot)) != self._wire_identity
                    or type(wire._phase_snapshot) is not tuple or wire._phase_snapshot != (4, previous, 'closed')
                    or any(type(x) is not t for x, t in zip(wire._phase_snapshot, (int, str, str)))):
                raise DispatchAttemptError('changed_model_retirement')
        else:
            wire._integrity()
            if wire._step and wire._binding != origin[4]: raise DispatchAttemptError('changed_model_binding')
        if active and (ledger._closed is not False or self._state in _TERMINAL
                or self._cancelled is not False or origin[3].is_set() or monotonic() >= origin[5]):
            raise DispatchAttemptError('closed_or_expired_model')
        return ledger, origin, record

    def _reject(self, ledger):
        try:
            ledger._integrity()
            ledger._terminate(self)
        except Exception:
            ledger._poison()
        raise DispatchAttemptError('dispatch_model_rejected') from None

    def _operation(self, state, operation):
        ledger = self._owner()
        with ledger._guard():
            try:
                self._current(active=True)
                if self._state != state: raise DispatchAttemptError('wrong_model_phase')
                return operation(ledger)
            except Exception:
                self._reject(ledger)

    def prepare(self):
        def operation(ledger):
            frame = self._issued_wire.prepare(loads(self._envelope))
            self._current(active=True, wire_transition=(1, hashlib.sha256(frame).hexdigest()))
            ledger._save(self, 'prepared', False, False, 0, None)
            self._current(active=True); return frame
        return self._operation('new', operation)

    def accept_ready(self, frame):
        def operation(ledger):
            self._issued_wire.accept_ready(frame)
            self._current(active=True, wire_transition=(2, hashlib.sha256(frame).hexdigest()))
            ledger._save(self, 'ready', False, False, 0, None)
            self._current(active=True)
        return self._operation('prepared', operation)

    def begin_model_visibility(self):
        def operation(ledger):
            # Irreversible model tombstone precedes even notice serialization.
            ledger._save(self, 'visibility_possible', True, True, 0, None)
            self._current(active=True)
            frame = self._issued_wire.model_visibility()
            self._current(active=True, wire_transition=(3, hashlib.sha256(frame).hexdigest()))
            ledger._save(self, 'visibility_possible', True, True, 0, None)
            self._current(active=True); return frame
        return self._operation('ready', operation)

    def record_model_write(self, count):
        def operation(ledger):
            total = loads(self._envelope)['commit']['staged_bytes']
            if type(count) is not int or not 0 <= count <= total:
                raise DispatchAttemptError('invalid_model_count')
            if count != total:
                ledger._save(self, 'visibility_possible', True, True, count, None)
                ledger._terminate(self)
            else:
                ledger._save(self, 'awaiting_claim', True, True, count, None)
                self._current(active=True)
        return self._operation('visibility_possible', operation)

    def accept_receipt_claim(self, frame):
        def operation(ledger):
            value = self._issued_wire.accept_receipt_claim(frame)
            self._current(active=True, wire_transition=(4, hashlib.sha256(frame).hexdigest()))
            commit = loads(self._envelope)['commit']
            if (type(value) is not DispatchModelEvidence or type(value.canonical_binding) is not bytes or value.canonical_binding != self._envelope
                    or type(value.binding_digest) is not str or value.binding_digest != hashlib.sha256(self._envelope).hexdigest()
                    or type(value.outcome) is not str or value.outcome != 'receiver_claimed'
                    or type(value.claimed_bytes) is not int or value.claimed_bytes != commit['staged_bytes']
                    or type(value.claimed_digest) is not str or value.claimed_digest != commit['staged_digest']
                    or type(value.observed_delivery) is not str or value.observed_delivery != 'unproven'
                    or type(value.meaning) is not str or value.meaning != DispatchModelEvidence.__dataclass_fields__['meaning'].default):
                raise DispatchAttemptError('changed_model_claim')
            # Renew clock/cancellation after decoding, before accepting the claim.
            origin = ledger._origin(self)
            if self._cancelled is not False or origin[3].is_set() or monotonic() >= origin[5]:
                raise DispatchAttemptError('expired_model_claim')
            ledger._save(self, 'receiver_claimed', True, True, self._model_written_bytes, value)
            ledger._dispose(origin); self._current()
            return self._snapshot
        return self._operation('awaiting_claim', operation)

    def inspect(self):
        ledger = self._owner()
        with ledger._guard():
            try:
                self._current(active=self._state not in _TERMINAL)
                return self._snapshot
            except Exception:
                self._reject(ledger)

    def close(self):
        ledger = self._owner()
        with ledger._guard():
            try:
                ledger._integrity(); ledger._terminate(self)
            except Exception:
                ledger._poison()
                raise DispatchAttemptError('model_cleanup_failed') from None
