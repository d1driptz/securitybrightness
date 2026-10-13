"""Inactive logical custody plus two real metadata peers; no fixture I/O."""
from copy import copy
from dataclasses import replace
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_source_admission as admission
from core import broker_transport as transport
from core import test_broker_publication_lifecycle as helpers
from core.broker_source_association_protocol import SourceRecipientAssociationExchange
from core.broker_source_rendezvous import SourceAssociationRendezvousDryRun


class SourceAdmissionTests(unittest.TestCase):
    DATA = helpers.LivePublicationDraftTests.DATA
    install = helpers.LivePublicationDraftTests.install
    observe = helpers.LivePublicationDraftTests.observe
    review = helpers.LivePublicationDraftTests.review
    reserve = helpers.LivePublicationDraftTests.reserve
    stage = helpers.LivePublicationDraftTests.stage
    retirement = helpers.LivePublicationDraftTests.retirement

    def setUp(self):
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.slot = transport._slot
        self.custody = admission._SourceAdmissionCustody()
        self.custody.acquire()
        self.assertEqual(self.slot._value, 0, 'admission precedes model construction')
        helpers.LivePublicationDraftTests.setUp(self)
        self.custody.bind_source(self.lifecycle)
        self.addCleanup(self.custody.close)

    def begin(self):
        return self.custody.begin_review('app', self.credential, self.proposal, self.draft.draft_id, 1)

    def start(self, token=None, **overrides):
        token = self.reserve() if token is None else token
        values = dict(app='app', credential=self.credential, proposal=self.proposal)
        values.update(overrides)
        self.acquisition_frame = self.custody.begin_acquisition(token, **values)
        self.request_evidence = self.quarantine_peer.accept_request(self.acquisition_frame)
        return token

    def prepare(self):
        self.retirement()
        self.retained = self.lifecycle._owned_buffer

    def finish(self, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal, descriptor=self.descriptor)
        values.update(overrides)
        return self.custody.finish(**values)

    def reject_finish(self, **overrides):
        with self.assertRaises(admission.SourceAdmissionError): self.finish(**overrides)

    def terminal(self):
        self.assertEqual(self.lifecycle._state, 'closed')
        self.assertEqual(self.model._state, 'closed')
        self.assertEqual(self.recipient._state, 'closed')
        self.assertIs(self.recipient._terminal, True)
        self.assertIsNone(self.recipient._claim)
        if self.lifecycle._owned_buffer is not None:
            self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_admission_retained_through_logical_review_quarantine_and_both_real_workers(self):
        phases = []
        def observe(name):
            phases.append(name)
            self.assertFalse(self.slot.acquire(blocking=False))
        self.peer.receive(self.begin()); observe('begin')
        from core.test_broker_live import observed
        self.model.coordinator.observe(self.peer.send(observed())); observe('observation')
        display = self.model.operator.display(); observe('display')
        self.model.operator.record(display, 'ALLOW ONCE'); observe('review')
        token = self.lifecycle.coordinator.reserve(); observe('reserve')
        self.start(token); observe('begin_acquisition')
        self.lifecycle.adapter.stage(self.quarantine_peer.reply(outcome='staged', data=self.DATA)); observe('stage')
        self.quarantine_peer.accept_retirement(self.lifecycle.adapter.retire()); observe('retire')
        self.lifecycle.adapter.confirm_retirement(self.quarantine_peer.acknowledge_retirement()); observe('cleaned')
        original = admission._CustodiedRendezvous._release_admission
        def retain(gate):
            observe('before_return')
            sealed = original(gate)
            observe('after_return')
            self.assertEqual(sealed.state, 'joined_retained')
            self.assertIs(sealed.released, False)
            self.assertFalse(gate._issued_association_thread.is_alive())
            self.assertFalse(gate._issued_witness._issued_thread.is_alive())
            self.assertEqual(self.lifecycle._owned_buffer, bytearray())
            return sealed
        with patch.object(admission._CustodiedRendezvous, '_release_admission', retain): result = self.finish()
        self.assertEqual(phases, ['begin', 'observation', 'display', 'review', 'reserve', 'begin_acquisition',
                                  'stage', 'retire', 'cleaned', 'before_return', 'after_return'])
        self.assertEqual((result.outcome, result.released_bytes), ('associated_discarded', 0))
        self.assertIs(self.custody._history.result, result)
        self.assertTrue(self.custody._history.released)
        self.assertEqual(self.slot._value, 1)
        self.terminal()
        with self.assertRaises(TypeError): bool(result)
        for name in ('data', 'permission', 'token', 'read'): self.assertFalse(hasattr(result, name))

    def test_exact_original_absolute_deadline_is_not_renewed_at_handoff(self):
        self.prepare(); original = admission._CustodiedRendezvous._acquire_admission; reached = []
        def acquire(gate):
            reached.append(True)
            self.assertLessEqual(gate._deadline, self.custody._original().deadline)
            return original(gate)
        with patch.object(admission._CustodiedRendezvous, '_acquire_admission', acquire): self.finish()
        self.assertEqual(reached, [True])

    def test_separate_custody_cannot_acquire_held_slot_or_retry_busy_attempt(self):
        other = admission._SourceAdmissionCustody()
        with self.assertRaises(admission.SourceAdmissionError): other.acquire()
        self.custody.abort()
        with self.assertRaises(admission.SourceAdmissionError): other.acquire()
        self.assertEqual(self.slot._value, 1)

    def test_standalone_rendezvous_cannot_double_acquire_outer_admission(self):
        self.prepare(); gate = SourceAssociationRendezvousDryRun(self.lifecycle)
        with self.assertRaises(Exception): gate.run('app', self.credential, self.proposal, self.descriptor)
        self.assertEqual(self.slot._value, 0)
        self.custody.abort()
        self.assertEqual(self.slot._value, 1)

    def test_close_only_signals_until_original_bootstrap_aborts(self):
        self.begin(); self.custody.close()
        self.assertEqual(self.slot._value, 0)
        self.custody.abort()
        self.assertEqual(self.slot._value, 1)
        self.terminal()

    def test_pre_review_abort_retires_captured_recipient_timer(self):
        timer = self.recipient._timer
        self.custody.abort()
        self.assertTrue(timer.finished.is_set())
        self.assertEqual(self.slot._value, 1)
        self.terminal()

    def test_pre_acquisition_abort_removes_original_pending_review(self):
        self.review(); ticket = self.model._ticket
        self.custody.abort()
        self.assertNotIn(ticket.review.draft_id, self.ledger._reviews)
        self.assertNotIn(ticket.review.draft_id, self.model._reviews._pending)
        self.assertEqual(self.slot._value, 1)

    def test_staged_abort_wipes_original_buffer_keys_and_all_timer_signals(self):
        self.stage(); retained, timer = self.lifecycle._owned_buffer, self.lifecycle._wire._timer
        self.custody.abort()
        self.assertEqual(retained, bytearray())
        self.assertTrue(timer.finished.is_set())
        self.assertTrue(self.model._timer.finished.is_set())
        self.assertEqual(self.slot._value, 1)
        self.terminal()

    def test_application_authority_without_separate_review_cannot_finish(self):
        self.observe(); self.reject_finish()
        self.assertEqual(self.slot._value, 0)

    def test_deny_does_not_construct_a_rendezvous(self):
        self.review('DENY')
        with patch.object(admission._CustodiedRendezvous, '__init__') as launch:
            self.reject_finish(); launch.assert_not_called()
        self.assertEqual(self.slot._value, 0)

    def test_removed_authority_cannot_be_replaced_by_human_review(self):
        self.prepare(); self.registry.revoke('app'); self.reject_finish()
        self.assertIsNone(self.custody._history.result)
        self.assertEqual(self.slot._value, 0)  # Constructor uncertainty cannot release.

    def test_wrong_application_cannot_inherit_review(self):
        self.prepare(); self.reject_finish(app='other')
        self.assertIsNone(self.custody._history.result)
        self.terminal()

    def test_replay_after_success_cannot_reclaim_new_owner_admission(self):
        self.prepare(); self.finish()
        newer = admission._SourceAdmissionCustody(); newer.acquire()
        for action in (self.finish, self.custody.abort, self.custody.acquire):
            with self.assertRaises(admission.SourceAdmissionError): action()
        self.assertEqual(self.slot._value, 0)
        newer.abort(); self.assertEqual(self.slot._value, 1)

    def test_shallow_copy_cannot_abort_or_bind_original_admission(self):
        foreign = copy(self.custody)
        for action in (foreign.abort, foreign.close, foreign.acquire, lambda: foreign.bind_source(self.lifecycle)):
            with self.assertRaises(admission.SourceAdmissionError): action()
        self.assertFalse(self.custody._cancel.is_set())
        self.custody.abort(); self.assertEqual(self.slot._value, 1)

    def test_shallow_copy_after_begin_cannot_finish_original_review(self):
        self.prepare(); foreign = copy(self.custody)
        with self.assertRaises(admission.SourceAdmissionError):
            foreign.finish('app', self.credential, self.proposal, self.descriptor)
        self.assertEqual(self.slot._value, 0)
        self.finish(); self.assertEqual(self.slot._value, 1)

    def test_direct_review_begin_outside_custody_is_untracked_and_never_certifies_cleanup(self):
        self.model.coordinator.begin('app', self.credential, self.proposal, self.draft.draft_id, 1)
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertTrue(self.custody._history.poisoned)
        self.assertEqual(self.slot._value, 0)

    def test_missing_original_ticket_cannot_leave_pending_review_and_release_admission(self):
        self.review(); ticket = self.model._ticket; self.model._ticket = None
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)
        self.model._ticket = ticket
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)

    def test_erasing_all_wire_archives_and_current_pointers_is_not_never_started(self):
        self.stage(); wire, buffer = self.lifecycle._wire, self.lifecycle._owned_buffer
        self.custody._wire = self.custody._issued_wire = self.custody._recovery_wire = None
        self.lifecycle._wire = self.lifecycle._owned_buffer = None
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)
        # Restore only for test disposal, never for another admission attempt.
        self.lifecycle._wire, self.lifecycle._owned_buffer = wire, buffer

    def test_foreign_wire_timer_is_never_cancelled_or_trusted_for_release(self):
        self.stage(); wire = self.lifecycle._wire; original = wire._timer_snapshot; foreign = Mock()
        wire._timer_snapshot = foreign
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
            foreign.cancel.assert_not_called()
            self.assertEqual(self.slot._value, 0)
        finally: wire._timer_snapshot = original

    def proof_fault(self, action):
        self.prepare(); original = SourceRecipientAssociationExchange.accept_proof; reached = []
        def proof(wire, frame):
            value = original(wire, frame); reached.append(True); action(); return value
        with patch.object(SourceRecipientAssociationExchange, 'accept_proof', proof): self.reject_finish()
        self.assertEqual(reached, [True], 'fault must follow genuine second native proof')
        self.assertIsNone(self.custody._history.result)
        self.terminal()

    def test_revocation_during_native_proof_prevents_result_but_confirmed_cleanup_releases(self):
        self.proof_fault(lambda: self.registry.revoke('app'))
        self.assertEqual(self.slot._value, 1)

    def test_cancel_during_native_proof_prevents_result_but_confirmed_cleanup_releases(self):
        self.proof_fault(self.custody.close)
        self.assertEqual(self.slot._value, 1)

    def test_credential_rotation_during_native_proof_rejects_result(self):
        self.proof_fault(lambda: self.registry.rotate_credential('app'))
        self.assertEqual(self.slot._value, 1)

    def test_invalid_timeout_values(self):
        for value in (True, False, 0, -1, 5.001, float('inf'), float('nan'), '5', None):
            with self.subTest(value=value), self.assertRaises(admission.SourceAdmissionError):
                admission._SourceAdmissionCustody(timeout=value)

    def test_cancel_before_acquire_cannot_take_slot(self):
        other = admission._SourceAdmissionCustody(); other.close()
        with self.assertRaises(admission.SourceAdmissionError): other.acquire()
        self.assertEqual(self.slot._value, 0)

    def test_expired_custody_does_not_renew_and_abort_can_only_dispose(self):
        self.custody.abort()
        short = admission._SourceAdmissionCustody(timeout=.02); short.acquire()
        deadline = short._deadline; time.sleep(.03)
        with self.assertRaises(admission.SourceAdmissionError): short.acquire()
        self.assertEqual(short._deadline, deadline)
        self.assertEqual(self.slot._value, 0)

    def test_pre_release_history_replay_cannot_free_a_later_owner_slot(self):
        self.prepare(); old = self.custody._history
        self.finish()
        newer = admission._SourceAdmissionCustody(); newer.acquire()
        self.custody._history = self.custody._issued_history = self.custody._recovery_history = old
        self.custody._state = old.stage
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)
        self.assertFalse(newer._cancel.is_set())
        newer.abort(); self.assertEqual(self.slot._value, 1)

    def test_wire_creation_history_rollback_cannot_disguise_a_lost_buffer(self):
        self.review(); old = self.custody._history
        token = self.lifecycle.coordinator.reserve(); self.start(token)
        wire, buffer = self.lifecycle._wire, self.lifecycle._owned_buffer
        self.custody._history = self.custody._issued_history = self.custody._recovery_history = old
        self.custody._wire = self.custody._issued_wire = self.custody._recovery_wire = None
        self.lifecycle._wire = self.lifecycle._owned_buffer = None
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)
        self.lifecycle._wire, self.lifecycle._owned_buffer = wire, buffer

    def test_review_creation_history_rollback_cannot_disguise_a_lost_timer(self):
        old = self.custody._history; self.begin()
        timer = self.model._timer
        self.custody._history = self.custody._issued_history = self.custody._recovery_history = old
        self.custody._review = self.custody._issued_review = self.custody._recovery_review = None
        self.model._timer = None
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)
        self.model._timer = timer

    def test_source_binding_history_rollback_cannot_disguise_a_live_recipient_timer(self):
        old = self.custody._history._replace(bound=False)
        self.custody._history = self.custody._issued_history = self.custody._recovery_history = old
        self.custody._source = self.custody._issued_source = self.custody._recovery_source = None
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
        self.assertEqual(self.slot._value, 0)

    def test_noop_source_shutdown_cannot_certify_abort_cleanup(self):
        self.stage()
        with patch.object(self.lifecycle, '_shutdown') as dispose:
            with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
            dispose.assert_called_once()
        self.assertEqual(self.slot._value, 0)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_review_timer_created_before_begin_failure_never_has_confirmed_cleanup(self):
        original = self.model.coordinator.begin; reached = []
        def begin(*args):
            original(*args); reached.append(self.model._timer); raise ValueError('test startup failure')
        with patch.object(self.model.coordinator, 'begin', side_effect=begin):
            with self.assertRaises(admission.SourceAdmissionError): self.begin()
        self.assertEqual(len(reached), 1)
        self.assertTrue(self.custody._history.poisoned)
        self.assertEqual(self.slot._value, 0)
        with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()

    def test_quarantine_created_before_begin_failure_never_has_confirmed_cleanup(self):
        self.review(); token = self.lifecycle.coordinator.reserve()
        original = self.lifecycle.adapter.begin; reached = []
        def begin(*args):
            original(*args); reached.append(self.lifecycle._wire); raise ValueError('test startup failure')
        with patch.object(self.lifecycle.adapter, 'begin', side_effect=begin):
            with self.assertRaises(admission.SourceAdmissionError):
                self.custody.begin_acquisition(token, 'app', self.credential, self.proposal)
        self.assertEqual(len(reached), 1)
        self.assertTrue(self.custody._history.poisoned)
        self.assertEqual(self.slot._value, 0)

    def test_forced_cleanup_without_input_retirement_never_publishes_success(self):
        self.prepare(); reached = []
        original = self.custody._retire
        def retire(candidate):
            gate = self.custody._history.gate; child = gate._worker_original().native.child
            self.assertIsNotNone(candidate)
            child._input_closed = False; child._retired_snapshot = (child._exit, False)
            reached.append(True); return original(candidate)
        with patch.object(self.custody, '_retire', side_effect=retire): self.reject_finish()
        self.assertEqual(reached, [True])
        self.assertIsNone(self.custody._history.result)
        self.assertEqual(self.slot._value, 1)

    def test_nonzero_original_exit_never_publishes_success_after_cleanup(self):
        self.prepare(); reached = []
        original = self.custody._retire
        def retire(candidate):
            gate = self.custody._history.gate; child = gate._worker_original().native.child
            self.assertIsNotNone(candidate)
            child._exit = 7; child._retired_snapshot = (7, child._input_closed)
            reached.append(True); return original(candidate)
        with patch.object(self.custody, '_retire', side_effect=retire): self.reject_finish()
        self.assertEqual(reached, [True])
        self.assertIsNone(self.custody._history.result)
        self.assertEqual(self.slot._value, 1)


if __name__ == '__main__': unittest.main()
