"""Inactive fixed native dry commit. Metadata traverses the original private peer.

The original quarantine is consumed and discarded while the peer is live. Both
terminal frames stay private until strict EOF, zero exit and guarded native join.
No protected-byte delivery operation, caller endpoint or executable selector.
"""
import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager
from time import sleep
from .broker_bootstrap import MAGIC, READY_SIZE, ready
from .broker_live_channel_check import LiveChannelPublicationCheck, LiveChannelCheckError
from .broker_native_commit_peer import _PublicationCommitPeer
from .broker_process import BrokerProcessError
from .broker_protocol import MAX_BODY_BYTES
from .broker_publication_commit_draft import PublicationCommitDraft, PublicationCommitError
from .broker_publication_commit_protocol import PublicationCommitEvidence, _MEANING
from .broker_publication_recipient import RecipientDescriptor
from .broker_publication_lifecycle import LivePublicationDraft
from .broker_recipient_channel import _values
from .broker_recipient_process import ProcessChannelObservation
from .broker_recipient_protocol import RecipientWitnessExchange
from .json_input import loads


class NativePublicationCommitDraft(PublicationCommitDraft):
    """Fixed native terminal gate, separate from synthetic live-peer finish.

    Public construction requires the exact fixed helper. A receipt is accepted
    only with both original transcript domains and the original joined channel.
    It is retired metadata, never authority or proof of byte delivery.
    """
    def __init__(self, helper, *, key, session, timeout=5):
        if type(helper) is not NativePublicationCommitCheck:
            raise TypeError('expected exact native commit helper')
        self._initialize(helper, key=key, session=session, timeout=timeout)

    def finish(self, frame):
        # Never silently substitute the old live/synthetic receipt path.
        self._reject()

    @contextmanager
    def _owners(self):
        helper = self._issued_helper
        if type(helper) is not NativePublicationCommitCheck or self._helper is not helper:
            raise PublicationCommitError('changed_native_commit_owner')
        with helper._lock:
            helper._source_identity()
            if (self._source is not self._issued_source or self._issued_source is not helper._issued_lifecycle
                    or self._recipient is not self._issued_recipient or self._issued_recipient is not helper._issued_recipient
                    or self._acquisition is not self._issued_acquisition or self._issued_acquisition is not helper._issued_acquisition
                    or self._review is not self._issued_review or self._issued_review is not helper._issued_review):
                raise PublicationCommitError('changed_native_commit_owner')
            with self._lock, self._issued_source._lock, self._issued_recipient._lock, self._issued_acquisition._lock, self._issued_review._lock:
                yield

    def _terminal_current(self, *, sealed, step):
        helper = self._owner_current()
        helper_state = helper._state
        if (type(helper) is not NativePublicationCommitCheck
                or helper._commit is not self or helper._issued_commit is not self
                or type(self._state) is not str or self._state != ('retired' if sealed else 'consumed')
                or self._terminal is not sealed or self._attempted is not True
                or type(helper._state) is not str
                or helper._state not in (('witnessed', 'retired') if sealed else ('witnessed',))):
            raise PublicationCommitError('changed_native_commit_owner')
        helper._checked_source(); self._result_current(); helper._result_current()
        if helper._issued_result is not self._issued_result:
            raise PublicationCommitError('changed_native_commit_result')
        helper._proof_current(); helper._wire_current(4); self._wire_current(step)
        helper._terminal_channel()
        # Native queries may invoke reentrant hooks. Recheck both domains and
        # current authority after them, before receipt sealing or consumption.
        self._owner_current(); helper._proof_current(); helper._wire_current(4)
        helper._ack_current(); self._wire_current(step)
        if sealed or step == 4: self._receipt_current()
        self._result_current(); helper._result_current(); helper._checked_source()
        self._clock()
        if (type(self._state) is not str or self._state != ('retired' if sealed else 'consumed') or self._terminal is not sealed
                or self._attempted is not True or helper._commit is not self or helper._issued_commit is not self
                or type(helper._state) is not str
                or helper._state != helper_state):
            raise PublicationCommitError('changed_native_commit_owner')

    def _receipt_current(self):
        value = self._receipt
        if (type(value) is not PublicationCommitEvidence or value is not self._issued_receipt
                or _values(value) != self._receipt_snapshot
                or type(value.canonical_binding) is not bytes or value.canonical_binding != self._envelope
                or type(value.binding_digest) is not str or value.binding_digest != hashlib.sha256(self._envelope).hexdigest()
                or type(value.outcome) is not str or value.outcome != 'dry_run_retired'
                or type(value.released_bytes) is not int or value.released_bytes != 0
                or type(value.meaning) is not str or value.meaning != _MEANING):
            raise PublicationCommitError('changed_native_commit_receipt')

    def finish_retired(self, frame):
        with self._owners():
            try:
                # No external wait occurs under these authority locks.
                with self._issued_review._lease(), self._issued_review._ledger._lock:
                    self._terminal_current(sealed=False, step=3)
                    value = self._issued_wire.accept_receipt(frame)
                    self._receipt_digest = hashlib.sha256(frame).hexdigest()
                    self._receipt = self._issued_receipt = value
                    self._receipt_snapshot = _values(value)
                    self._terminal_current(sealed=False, step=4)
                    self._issued_timer.cancel()
                    self._terminal_current(sealed=False, step=4)
                    self._terminal, self._state = True, 'retired'
                    self._terminal_current(sealed=True, step=4)
                    return value
            except BrokerProcessError:
                # Preserve uncertain original native cleanup for host admission.
                self.close()
                raise
            except Exception:
                self._reject()

    def retired_check(self):
        with self._owners():
            with self._issued_review._lease(), self._issued_review._ledger._lock:
                self._terminal_current(sealed=True, step=4)


class NativePublicationCommitCheck(LiveChannelPublicationCheck):
    """One fixed live peer, actual bounded dry-commit exchange, zero delivery.

    Reuses the original owner/clock/source validators. The original live native
    check stays alive-only; this fixed profile has an explicit joined terminal
    gate. The worker alone owns native close/join. Cancellation only signals it.
    """
    def __init__(self, lifecycle, *, timeout=5):
        if type(lifecycle) is not LivePublicationDraft:
            raise TypeError('expected exact live publication draft')
        self._original_owners = (lifecycle, lifecycle._recipient, lifecycle._acquisition, lifecycle._review)
        self._original_buffer = lifecycle._owned_buffer
        self._issued_original_owners, self._issued_original_buffer = self._original_owners, self._original_buffer
        self._commit = self._issued_commit = None
        super().__init__(lifecycle, timeout=timeout)

    def _expected_child_type(self):
        return _PublicationCommitPeer

    def _source_identity(self):
        if (self._original_owners is not self._issued_original_owners
                or type(self._original_owners) is not tuple or len(self._original_owners) != 4
                or self._original_buffer is not self._issued_original_buffer
                or any(current is not original for current, original in zip(
                    (self._lifecycle, self._recipient, self._acquisition, self._review), self._original_owners))
                or any(issued is not original for issued, original in zip(
                    (self._issued_lifecycle, self._issued_recipient, self._issued_acquisition, self._issued_review), self._original_owners))
                or self._owned_buffer is not self._original_buffer):
            raise LiveChannelCheckError('changed_native_commit_owner')
        super()._source_identity()

    @contextmanager
    def _owners(self):
        with self._lock:
            self._source_identity()
            source, recipient, acquisition, review = self._original_owners
            with source._lock, recipient._lock, acquisition._lock, review._lock:
                self._source_identity()
                yield

    def _current(self):
        # Lock captured original owners before inspecting mutable owner fields.
        with self._owners():
            self._source_identity(); self._clock_current()
            if type(self._state) is not str or self._state not in ('prepared', 'witnessed', 'checked'):
                raise LiveChannelCheckError('native_commit_unavailable')
            if self._state == 'checked': self._checked_source()
            else:
                self._issued_lifecycle._current('cleaned'); self._issued_lifecycle._wire_current(4)
                if self._issued_lifecycle._publication_attempted is not False:
                    raise LiveChannelCheckError('spent_native_commit_source')

    def _native_identity(self):
        child = self._issued_child
        if (type(child) is not _PublicationCommitPeer or self._child is not child
                or type(self._native_observation) is not ProcessChannelObservation
                or self._native_observation is not child._issued_observation
                or _values(self._native_observation) != self._child_snapshot
                or self._native_snapshot != self._child_snapshot):
            raise LiveChannelCheckError('changed_native_commit_channel')
        return child

    def _native_current(self):
        child = self._native_identity()
        if child._observe() is not self._native_observation:
            raise LiveChannelCheckError('changed_native_commit_channel')
        child._validate()
        self._native_identity()

    def _terminal_channel(self):
        child = self._native_identity()
        child._retired()
        self._native_identity()
        if type(child._exit) is not int or child._exit != 0:
            raise LiveChannelCheckError('native_commit_peer_failed')

    def _ack_current(self):
        if self._ack is not self._issued_ack or _values(self._ack) != self._ack_snapshot:
            raise LiveChannelCheckError('changed_native_commit_ack')
        self._evidence_current(self._ack, 'retired')

    def _commit_owner(self):
        draft = self._issued_commit
        if (type(draft) is not NativePublicationCommitDraft or self._commit is not draft
                or draft._issued_helper is not self):
            raise LiveChannelCheckError('changed_native_commit_draft')
        return draft

    def _transport_current(self, child, *, consumed, witness_step, retiring=False):
        with self._owners():
            if consumed:
                self._checked_source(); self._result_current()
                draft = self._commit_owner()
                draft._identity_current('consumed'); draft._result_current(); draft._wire_current(3)
            else: self._current()
            self._wire_current(witness_step)
            if witness_step >= 2: self._proof_current()
            if child is not self._native_identity(): raise LiveChannelCheckError('changed_native_commit_channel')
            if retiring: child._validate(retiring=True)
            else: self._native_current()
            # Repeat authority and evidence after native/OS calls.
            self._native_identity(); self._wire_current(witness_step)
            if witness_step >= 2: self._proof_current()
            if consumed:
                draft = self._commit_owner()
                draft._identity_current('consumed'); draft._result_current(); draft._wire_current(3)
                self._result_current(); self._checked_source()
            else: self._current()

    def run(self, app, credential, proposal, descriptor):
        with self._lock:
            if self._started is not False or self._finished is not False:
                self.close(); raise LiveChannelCheckError('native_commit_unavailable')
            self._started = True
        child, draft, draft_wire, draft_timer = None, None, None, None
        success, cleanup_ok = False, True
        try:
            self._current()
            if type(descriptor) is not RecipientDescriptor or descriptor is not self._descriptor:
                raise LiveChannelCheckError('wrong_native_commit_recipient')
            with self._owners():
                with self._issued_review._lease(), self._issued_review._ledger._lock:
                    self._issued_lifecycle._authenticate(app, credential, proposal); self._current()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            self._wire = self._issued_wire = RecipientWitnessExchange(role='coordinator', key=key, session=session)
            self._wire_identity_snapshot = tuple((type(x), x) for x in (self._wire._role,
                self._wire._role_snapshot, self._wire._session, self._wire._session_snapshot, self._wire._key_snapshot))
            request = self._wire.request(loads(self._binding_snapshot)); self._wire_current(1); self._current()
            child = self._child = self._issued_child = _PublicationCommitPeer()
            self._observe(); self._native_snapshot = self._child_snapshot; self._native_current()
            consumed, witness_step = False, 1

            def check(retiring=False):
                self._transport_current(child, consumed=consumed, witness_step=witness_step, retiring=retiring)

            def write(data):
                offset = 0
                while offset < len(data):
                    check()
                    try:
                        count = os.write(child.stdin_fd, data[offset:])
                        if count <= 0: raise LiveChannelCheckError('native_commit_pipe_failed')
                        offset += count
                    except BlockingIOError: sleep(.002)
                    check()

            def read(size, *, retiring=False):
                output = bytearray()
                while len(output) < size:
                    check(retiring)
                    try:
                        chunk = os.read(child.stdout_fd, size-len(output))
                        if not chunk: raise LiveChannelCheckError('truncated_native_commit_output')
                        output.extend(chunk)
                    except BlockingIOError: sleep(.002)
                    check(retiring)
                return bytes(output)

            def frame(*, retiring=False):
                prefix = read(4, retiring=retiring); size = int.from_bytes(prefix, 'big')
                if not 32 <= size <= MAX_BODY_BYTES+32: raise LiveChannelCheckError('native_commit_output_limit')
                return prefix+read(size, retiring=retiring)

            write(MAGIC+key+session)
            if not hmac.compare_digest(read(READY_SIZE), ready(key, session, self._native_observation.pid)):
                raise LiveChannelCheckError('native_commit_startup_rejected')
            write(request)
            self._proof = self._issued_proof = self._wire.accept_proof(frame())
            self._proof_snapshot = _values(self._proof)
            witness_step = 2; self._proof_current(); self._wire_current(2); self._current(); self._native_current()
            self._state = 'witnessed'
            draft = self._commit = self._issued_commit = NativePublicationCommitDraft(self, key=key, session=session)
            draft_wire, draft_timer = draft._issued_wire, draft._issued_timer
            write(draft.prepare()); draft.accept_ready(frame())
            notice = draft.commit(app, credential, proposal, descriptor)
            self._result = self._issued_result = draft._issued_result
            self._result_snapshot = _values(self._result); consumed = True
            check(); write(notice)
            retirement = self._wire.retire(); witness_step = 3
            write(retirement); self._wire_current(3); child.close_input()
            receipt, ack = frame(retiring=True), frame(retiring=True)
            while True:
                check(True)
                try:
                    if os.read(child.stdout_fd, 1): raise LiveChannelCheckError('trailing_native_commit_output')
                    break
                except BlockingIOError: sleep(.002)
            while child.poll() is None: check(True); sleep(.002)
            if child.poll() != 0: raise LiveChannelCheckError('native_commit_peer_failed')
            child.close(); self._terminal_channel()
            # Both frames remain private until original EOF, zero exit and join.
            # Validate the witness domain before sealing the commit receipt.
            self._checked_source(); self._proof_current(); self._wire_current(3)
            self._ack = self._issued_ack = self._wire.accept_ack(ack)
            self._ack_transcript_digest = hashlib.sha256(ack).hexdigest()
            self._ack_snapshot = _values(self._ack); self._ack_current(); self._wire_current(4)
            self._commit_owner().finish_retired(receipt)
            success = True
        except BrokerProcessError as error:
            if str(error) == 'process_cleanup_failed': cleanup_ok = False
            raise LiveChannelCheckError('native_commit_process_failed') from None
        except Exception:
            raise LiveChannelCheckError('native_commit_check_failed') from None
        finally:
            try:
                try:
                    if child is not None: child.close()
                finally:
                    try:
                        if not success and draft is not None:
                            try:
                                draft.close()  # Local original, never a substituted issued field.
                            finally:
                                # A corrupted draft owner must not prevent original
                                # key/timer disposal. Never read substitutes here.
                                try: draft_wire.close()
                                finally: draft_timer.cancel()
                    finally: self._dispose()
            except BaseException:
                cleanup_ok = False
                raise LiveChannelCheckError('native_commit_cleanup_failed') from None
            finally:
                with self._lock:
                    self._finished, self._cleanup_confirmed, self._state = True, cleanup_ok, 'retired'
        try:
            with self._owners():
                with self._issued_review._lease(), self._issued_review._ledger._lock:
                    self.retired_check(); self._result_current(); self.retired_check()
                    return self._result
        except BrokerProcessError:
            with self._lock: self._cleanup_confirmed = False
            raise LiveChannelCheckError('native_commit_cleanup_failed') from None
        except Exception:
            raise LiveChannelCheckError('stale_native_commit_check') from None

    def _retired_check(self):
        with self._owners():
            self._native_identity()  # Reject foreign native callbacks too.
            super()._retired_check()
            self._commit_owner().retired_check()

    def _dispose(self):
        # Restoration is for original disposal only. Terminal mutation evidence
        # remains irreversible, and foreign owner callbacks are not dispatched.
        owners, buffer = self._issued_original_owners, self._issued_original_buffer
        issued = (self._issued_lifecycle, self._issued_recipient, self._issued_acquisition, self._issued_review)
        if (self._original_owners is not owners or self._original_buffer is not buffer
                or any(x is not y for x, y in zip(issued, owners)) or self._owned_buffer is not buffer):
            self._owner_changed = True
            self._issued_lifecycle, self._issued_recipient, self._issued_acquisition, self._issued_review = owners
            self._owned_buffer = buffer
        super()._dispose()
