"""Inactive one-use dry publication commit over an original live witness.

No I/O, delivery port or reusable capability. A synthetic metadata peer is used
in tests; its receipt is not proof that the actual native peer received a commit.
The original host still owns native cleanup and admission. Failure signals its
worker and wipes the original buffer; callers must join that worker.
"""
from contextlib import contextmanager
import hashlib
import math
import secrets
from threading import Event, RLock, Timer
from time import monotonic
from .broker_live_channel_check import LiveChannelPublicationCheck
from .broker_publication_lifecycle import FinalPublicationDraftCheck
from .broker_publication_commit_protocol import PublicationCommitExchange, PublicationCommitEvidence, _commit_binding, _MEANING
from .broker_recipient_channel import _values
from .broker_protocol import _canonical
from .json_input import loads


class PublicationCommitError(RuntimeError):
    pass


class PublicationCommitDraft:
    """Prepare/ready, one locked consume-and-discard, receipt; zero delivery.

    Lock order: original helper -> draft -> lifecycle -> recipient -> acquisition
    -> review -> registry -> ledger -> native ownership. No external wait occurs
    under authority locks. The commit attempt burns before invalid credentials,
    recipient or proposal validation; original source consumption is irreversible.
    """
    def __init__(self, helper, *, key, session, timeout=5):
        if type(helper) is not LiveChannelPublicationCheck:
            raise TypeError('expected exact original live channel check')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_commit_lifetime')
        self._helper = self._issued_helper = helper
        self._lock, self._cancel = RLock(), Event()
        self._issued_cancel = self._cancel
        self._cancelled = self._attempted = self._terminal = False
        self._source = helper._issued_lifecycle
        self._recipient = helper._issued_recipient
        self._acquisition = helper._issued_acquisition
        self._review = helper._issued_review
        self._issued_source, self._issued_recipient = self._source, self._recipient
        self._issued_acquisition, self._issued_review = self._acquisition, self._review
        self._buffer = self._issued_buffer = helper._owned_buffer
        self._wire = self._issued_wire = PublicationCommitExchange(role='coordinator', key=key, session=session)
        self._wire_identity = tuple((type(x), x) for x in (self._wire._role, self._wire._role_snapshot,
            self._wire._session, self._wire._session_snapshot, self._wire._key_snapshot))
        self._result = self._issued_result = self._result_snapshot = self._receipt = self._receipt_snapshot = None
        self._receipt_digest = None
        self._state, self._timer = 'new', None
        with self._owners():
            helper._current(); helper._native_current(); helper._proof_current(); helper._wire_current(2)
            if helper._state != 'witnessed': raise PublicationCommitError('live_witness_required')
            self._envelope = _commit_binding(dict(revision=1, mode='dry_run_discard_only',
                commit_id=secrets.token_hex(32), binding=loads(helper._binding_snapshot),
                staged_bytes=helper._summary.staged_bytes, staged_digest=helper._summary.staged_digest,
                channel=dict(pid=helper._native_observation.pid, creation_time=helper._native_observation.creation_time,
                    witness_session=helper._issued_wire._session)))
            self._native_snapshot = helper._child_snapshot
            self._child = self._issued_child = helper._issued_child
            self._observation = helper._native_observation
            self._envelope_snapshot = self._envelope
            self._deadline = self._deadline_snapshot = min(monotonic()+timeout, helper._deadline_snapshot,
                helper._source_deadline, helper._recipient_deadline, helper._quarantine_deadline)
            if monotonic() >= self._deadline: raise PublicationCommitError('expired_commit_source')
        self._timer = self._issued_timer = Timer(self._deadline-monotonic(), self.close)
        self._timer.daemon = True
        try: self._timer.start()
        except Exception:
            self.close(); raise PublicationCommitError('commit_unavailable') from None

    @contextmanager
    def _owners(self):
        # Use captured owners for locking; never invoke requester-like substitutes.
        with self._issued_helper._lock, self._lock, self._issued_source._lock, self._issued_recipient._lock, self._issued_acquisition._lock, self._issued_review._lock:
            yield

    def _clock(self):
        if (self._helper is not self._issued_helper or self._cancel is not self._issued_cancel
                or type(self._cancel) is not Event or self._cancelled is not False or self._cancel.is_set()
                or type(self._deadline) is not float or self._deadline != self._deadline_snapshot
                or type(self._deadline_snapshot) is not float or monotonic() >= self._deadline_snapshot
                or self._timer is not self._issued_timer or type(self._timer) is not Timer):
            raise PublicationCommitError('expired_or_cancelled_commit')

    def _wire_current(self, step):
        wire = self._wire
        if type(wire) is not PublicationCommitExchange or wire is not self._issued_wire or type(wire._step) is not int or wire._step != step:
            raise PublicationCommitError('changed_commit_exchange')
        with wire._lock:
            if step < 4:
                wire._integrity()
                if step and wire._binding != self._envelope: raise PublicationCommitError('changed_commit_binding')
            elif (type(wire._state) is not str or wire._state != 'closed' or type(wire._key) is not bytes or wire._key
                    or wire._binding is not None or wire._binding_snapshot is not None or wire._binding_digest is not None
                    or tuple((type(x), x) for x in (wire._role, wire._role_snapshot, wire._session,
                        wire._session_snapshot, wire._key_snapshot)) != self._wire_identity
                    or type(wire._previous) is not str or wire._previous != self._receipt_digest
                    or type(wire._phase_snapshot) is not tuple or wire._phase_snapshot != (4, self._receipt_digest, 'closed')
                    or any(type(x) is not t for x, t in zip(wire._phase_snapshot, (int, str, str)))):
                raise PublicationCommitError('changed_commit_retirement')

    def _identity_current(self, state):
        self._clock()
        helper = self._issued_helper
        if (type(self._state) is not str or self._state != state or self._terminal is not False
                or self._source is not self._issued_source or self._recipient is not self._issued_recipient
                or self._acquisition is not self._issued_acquisition or self._review is not self._issued_review
                or self._buffer is not self._issued_buffer
                or type(self._attempted) is not bool or (state in ('new', 'prepared') and self._attempted)
                or type(helper._state) is not str or helper._state != 'witnessed'
                or self._child is not self._issued_child or helper._child is not self._issued_child
                or helper._issued_child is not self._issued_child
                or helper._native_observation is not self._observation
                or self._observation is not self._issued_child._issued_observation
                or _values(self._observation) != self._native_snapshot
                or helper._lifecycle is not self._source or helper._recipient is not self._recipient
                or helper._acquisition is not self._acquisition or helper._review is not self._review
                or helper._owned_buffer is not self._buffer or helper._child_snapshot != self._native_snapshot
                or type(self._envelope) is not bytes or self._envelope != self._envelope_snapshot
                or _commit_binding(loads(self._envelope)) != self._envelope):
            raise PublicationCommitError('changed_commit_owner')
        envelope = loads(self._envelope)
        if (envelope['binding'] != loads(helper._binding_snapshot)
                or envelope['staged_bytes'] != helper._summary.staged_bytes
                or envelope['staged_digest'] != helper._summary.staged_digest
                or envelope['channel'] != dict(pid=helper._native_observation.pid,
                    creation_time=helper._native_observation.creation_time, witness_session=helper._issued_wire._session)):
            raise PublicationCommitError('changed_commit_envelope')
        return helper

    def _current(self, state, step):
        helper = self._identity_current(state)
        if state == 'consumed':
            if self._attempted is not True: raise PublicationCommitError('unconsumed_commit')
            helper._checked_source()
            self._result_current()
        else:
            helper._current()
            if helper._state != 'witnessed' or self._source._publication_attempted is not False:
                raise PublicationCommitError('spent_commit_source')
        helper._proof_current(); helper._wire_current(2); helper._native_current()
        self._wire_current(step)
        # Native queries can run reentrant test hooks; re-enter authority after them.
        if state == 'consumed': helper._checked_source()
        else: helper._current()
        # Native callbacks must not hide substitution of the issued proof,
        # observation, state, envelope or either original codec after its check.
        self._identity_current(state)
        helper._proof_current(); helper._wire_current(2); self._wire_current(step)
        if state == 'consumed':
            self._result_current(); helper._checked_source()
        else: helper._current()
        self._clock()

    def _result_current(self):
        value, envelope = self._result, loads(self._envelope)
        if (type(value) is not FinalPublicationDraftCheck or value is not self._issued_result or _values(value) != self._result_snapshot
                or type(value.binding_digest) is not str or value.binding_digest != hashlib.sha256(_canonical(envelope['binding'])).hexdigest()
                or type(value.recipient_digest) is not str or value.recipient_digest != hashlib.sha256(_canonical(envelope['binding']['recipient'])).hexdigest()
                or type(value.staged_bytes) is not int or value.staged_bytes != envelope['staged_bytes']
                or type(value.staged_digest) is not str or value.staged_digest != envelope['staged_digest']
                or type(value.released_bytes) is not int or value.released_bytes != 0
                or type(value.disposition) is not str or value.disposition != 'eligible_discarded'
                or type(value.meaning) is not str or value.meaning != FinalPublicationDraftCheck.__dataclass_fields__['meaning'].default):
            raise PublicationCommitError('changed_commit_result')

    def _phase(self, state, step, operation):
        with self._owners():
            try:
                self._current(state, step)
                return operation()
            except Exception:
                self._reject()

    def _reject(self):
        try: self.close()
        finally: raise PublicationCommitError('publication_commit_rejected') from None

    def prepare(self):
        def operation():
            frame = self._wire.prepare(loads(self._envelope))
            self._state = 'prepared'; self._current('prepared', 1)
            return frame
        return self._phase('new', 0, operation)

    def accept_ready(self, frame):
        def operation():
            self._wire.accept_ready(frame)
            self._state = 'ready'; self._current('ready', 2)
        return self._phase('prepared', 1, operation)

    def commit(self, app, credential, proposal, descriptor):
        with self._owners():
            try:
                if self._attempted is not False: raise PublicationCommitError('commit_already_attempted')
                self._attempted = True  # Even invalid first inputs consume this draft.
                self._current('ready', 2)
                helper = self._issued_helper
                with self._review._lease(), self._review._ledger._lock, self._issued_child._ownership_lock:
                    self._current('ready', 2)
                    self._source._authenticate(app, credential, proposal)
                    if descriptor is not helper._descriptor: raise PublicationCommitError('wrong_commit_recipient')
                    frame = self._wire.dry_commit()
                    # This is the explicit, locked DRY boundary: the existing
                    # one-use source final check consumes and discards. It never
                    # publishes, and the metadata frame remains private until
                    # fresh authority/native/result checks afterward succeed.
                    self._result = self._issued_result = self._source._check_publication(app, credential, proposal, descriptor)
                    self._result_snapshot = _values(self._result)
                    self._state = 'consumed'; self._current('consumed', 3)
                    return frame
            except Exception:
                self._reject()

    def finish(self, frame):
        def operation():
            value = self._wire.accept_receipt(frame)
            self._receipt_digest = hashlib.sha256(frame).hexdigest()
            if (type(value) is not PublicationCommitEvidence or type(value.canonical_binding) is not bytes
                    or value.canonical_binding != self._envelope
                    or type(value.binding_digest) is not str or value.binding_digest != hashlib.sha256(self._envelope).hexdigest()
                    or type(value.outcome) is not str or value.outcome != 'dry_run_retired'
                    or type(value.released_bytes) is not int or value.released_bytes != 0
                    or type(value.meaning) is not str or value.meaning != _MEANING):
                raise PublicationCommitError('changed_commit_receipt')
            self._receipt, self._receipt_snapshot = value, _values(value)
            self._current('consumed', 4)
            self._issued_timer.cancel()
            self._current('consumed', 4)
            if _values(value) != self._receipt_snapshot: raise PublicationCommitError('changed_commit_receipt')
            self._terminal, self._state = True, 'retired'
            return value
        return self._phase('consumed', 3, operation)

    def close(self):
        with self._owners():
            retired = self._terminal is True and self._state == 'retired'
            self._terminal, self._cancelled, self._state = True, True, 'closed'
            self._issued_cancel.set()
            try:
                if not retired:
                    self._issued_helper.close()  # Signal original worker; never close its native child here.
            finally:
                try:
                    if not retired and type(self._issued_buffer) is bytearray:
                        self._issued_buffer[:] = b'\0'*len(self._issued_buffer); self._issued_buffer.clear()
                finally:
                    try: self._issued_wire.close()
                    finally:
                        timer = getattr(self, '_issued_timer', None)
                        if timer is not None: timer.cancel()
