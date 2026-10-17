"""Three original native children, one admission, generated fixture only."""
from copy import copy
from dataclasses import asdict, replace
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_source_fixture_host as host
from core import broker_source_fixture_stage as stage
from core import broker_source_fixture_process as process
from core import broker_transport as transport
from core import test_broker_review_host as helpers
from core.broker_live_review import LiveBrokerReview
from core.broker_process import _ChildProcess, BrokerProcessError
from core.broker_recipient_process import _RecipientWitnessChild
from core.broker_source_admission import _SourceAdmissionCustody, SourceAdmissionError
from core.broker_source_native_association import SourceNativeAssociationEvidence
from core.file_read_constraint import FileReadConstraint
from core.file_read_schema import make_file_read_proposal


class SourceFixtureHostTests(unittest.TestCase):
    def setUp(self):
        helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerSourceFixtureHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)
        self.slot = transport._slot

    run_host = helpers.BrokerReviewHostTests.run_host
    start = helpers.BrokerReviewHostTests.start
    reject = helpers.BrokerReviewHostTests.reject

    def allow(self):
        future, display = self.start()
        self.host.operator.respond(display, 'ALLOW ONCE')
        return future, display

    def terminal(self):
        self.assertEqual(self.host._issued_model._state, 'closed')
        self.assertEqual(self.host._issued_lifecycle._state, 'closed')
        self.assertEqual(self.host._issued_recipient._state, 'closed')
        self.assertIs(self.host._issued_recipient._terminal, True)
        if self.host._issued_lifecycle._owned_buffer is not None:
            self.assertEqual(self.host._issued_lifecycle._owned_buffer, bytearray())

    def test_three_genuine_children_share_original_admission_before_model_creation_until_final_cleanup(self):
        captured, events, model_slots = [], [], []
        original = _RecipientWitnessChild.__init__
        original_model = LiveBrokerReview.__init__
        def model_init(model, *args, **kwargs):
            model_slots.append(self.slot._value)
            return original_model(model, *args, **kwargs)
        def launch(child):
            self.assertEqual(self.slot._value, 0)
            if captured:
                captured[0]._retired()
                self.assertEqual(captured[0]._retired_snapshot, (0, True))
                self.assertIsNone(captured[0]._process); self.assertIsNone(captured[0]._job)
                self.assertFalse(Path(self.host._live.display.display_path).exists())
            original(child); captured.append(child); events.append(type(child).__name__)
        with patch.object(_RecipientWitnessChild, '__init__', launch), patch.object(LiveBrokerReview, '__init__', model_init):
            future, display = self.allow(); result = future.result(timeout=10)
        self.assertEqual(model_slots, [0])
        self.assertEqual(events, ['_SourceFixtureChild', '_RecipientWitnessChild', '_SourceAssociationPeer'])
        self.assertIs(type(result), SourceNativeAssociationEvidence)
        self.assertEqual((result.outcome, result.released_bytes), ('associated_discarded', 0))
        self.assertNotIn(b'SecurityBrightness synthetic fixture', result.canonical_binding)
        self.assertEqual(self.slot._value, 1)
        self.assertFalse(Path(display.display_path).exists())
        for child in captured: child._retired()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assertEqual(self.host.operator.pending(), ())
        self.terminal()
        with self.assertRaises(TypeError): bool(result)

    def test_deny_never_reserves_stages_or_launches_later_peers(self):
        with patch.object(stage._SourceFixtureStage, 'stage') as read:
            future, display = self.start()
            self.assertTrue(Path(display.display_path).exists())
            self.host.operator.respond(display, 'DENY')
            result = future.result(timeout=4)
            read.assert_not_called()
        self.assertIs(type(result), host.RetiredSourceFixtureDenial)
        self.assertEqual((result.decision, result.released_bytes), ('deny', 0))
        self.assertIsNone(self.host._issued_lifecycle._wire)
        self.assertIsNone(self.host._issued_custody._status().gate)
        self.assertEqual(self.slot._value, 1)
        self.assertFalse(Path(display.display_path).exists())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)
        self.terminal()
        with self.assertRaises(TypeError): bool(result)

    def test_authority_without_operator_response_does_not_stage(self):
        with patch.object(stage._SourceFixtureStage, 'stage') as read:
            future, display = self.start(); self.host.close(); self.reject(future, display)
            read.assert_not_called()
        self.assertEqual(self.slot._value, 1)
        self.terminal()

    def test_revoked_authority_cannot_be_replaced_by_allow_response(self):
        future, display = self.start(); self.registry.revoke('app')
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)
        self.assertIsNone(self.host._issued_custody._status().result)
        self.terminal()

    def test_credential_rotation_after_display_rejects_original_review(self):
        future, display = self.start(); self.registry.rotate_credential('app')
        self.host.operator.respond(display, 'ALLOW ONCE'); self.reject(future, display)
        self.terminal()

    def test_permission_change_after_display_rejects_original_review(self):
        future, display = self.start(); self.registry.update_permissions('app', scopes=['files.write'])
        self.host.operator.respond(display, 'ALLOW ONCE'); self.reject(future, display)
        self.terminal()

    def test_wrong_credentials_prevent_first_child_launch(self):
        self.credential = 'wrong'
        with patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        self.assertEqual(self.slot._value, 0)  # Interrupted review startup remains uncertain.

    def test_missing_read_scope_prevents_first_child_launch(self):
        self.registry.update_permissions('app', scopes=['files.write'])
        with patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_other_application_cannot_inherit_original_draft(self):
        credential = self.registry.register('other', ['files.read'])
        with patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError):
                self.host.worker.run('other', credential, self.proposal, self.draft.draft_id, 1)
            launch.assert_not_called()

    def test_unsupported_operation_never_launches_fixture(self):
        with patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError):
                self.host.worker.run('app', self.credential, {'operation': 'files.write'}, self.draft.draft_id, 1)
            launch.assert_not_called()

    def test_exact_37_byte_effect_boundary_succeeds_without_returning_payload(self):
        self.draft = self.ledger.create(FileReadConstraint('app', 'label', max_bytes=37))
        self.proposal = make_file_read_proposal('label', max_bytes=37)
        future, display = self.allow(); result = future.result(timeout=8)
        self.assertEqual(display.max_bytes, 37)
        self.assertEqual(result.released_bytes, 0)
        self.assertFalse(hasattr(result, 'data'))
        self.terminal()

    def test_effect_below_fixed_fixture_size_is_rejected_without_staging(self):
        self.draft = self.ledger.create(FileReadConstraint('app', 'label', max_bytes=36))
        self.proposal = make_file_read_proposal('label', max_bytes=36)
        with patch.object(stage._SourceFixtureStage, 'stage') as read:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            read.assert_not_called()

    def test_public_host_accepts_no_path_callback_or_profile_selector(self):
        for name in ('path', 'callback', 'profile', 'entry', 'already_admitted', 'child'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                host.BrokerSourceFixtureHost(self.registry, self.ledger, **{name: 'requester'})

    def test_invalid_lifetimes_cannot_extend_diagnostic(self):
        for value in (True, 0, -1, 5.001, float('inf'), float('nan'), '5', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                host.BrokerSourceFixtureHost(self.registry, self.ledger, timeout=value)

    def test_private_bootstrap_secret_cannot_equal_public_session(self):
        with patch.object(host.secrets, 'token_bytes', return_value=b'a'*32), \
                patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        self.assertEqual(self.slot._value, 1)

    def test_shallow_host_copy_cannot_start_or_cancel_original(self):
        foreign = copy(self.host)
        with self.assertRaises(host.BrokerReviewHostError): foreign.close()
        with self.assertRaises(host.BrokerReviewHostError):
            foreign._run('app', self.credential, self.proposal, self.draft.draft_id, 1)
        self.assertFalse(self.host._cancel.is_set())
        future, _ = self.allow(); self.assertEqual(future.result(timeout=8).released_bytes, 0)

    def test_replayed_host_does_not_free_new_owner_admission(self):
        future, _ = self.allow(); future.result(timeout=8)
        newer = _SourceAdmissionCustody(); newer.acquire()
        with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.slot._value, 0)
        self.assertFalse(newer._cancel.is_set())
        newer.abort(); self.assertEqual(self.slot._value, 1)

    def test_copied_display_cannot_record_operator_control(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(replace(display), 'ALLOW ONCE')
        self.reject(future, display); self.terminal()

    def test_invalid_or_duplicate_operator_answer_fails_closed(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'allow once')
        self.reject(future, display); self.terminal()

    def test_busy_admission_never_constructs_a_model_or_native_child(self):
        self.assertTrue(self.slot.acquire(blocking=False))
        with patch.object(host, 'LiveBrokerReview') as model, patch.object(process._SourceFixtureChild, '__init__') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            model.assert_not_called(); launch.assert_not_called()
        self.assertEqual(self.slot._value, 0); self.slot.release()

    def test_partial_native_constructor_failure_remains_poisoned_but_originals_retire(self):
        original = _ChildProcess.__init__; captured = []
        def construct(child):
            original(child); captured.append(child); raise BrokerProcessError('test constructor failure')
        with patch.object(_ChildProcess, '__init__', construct):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(len(captured), 1)
        self.assertIsNone(captured[0]._process); self.assertIsNone(captured[0]._job)
        self.assertEqual(self.slot._value, 0)
        self.terminal()

    def test_cancellation_at_native_constructor_return_retains_original_for_disposal(self):
        original = process._SourceFixtureChild.__init__; captured = []
        def construct(child):
            original(child); captured.append(child); self.host.close()
        with patch.object(process._SourceFixtureChild, '__init__', construct):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(len(captured), 1)
        captured[0]._retired()
        self.assertIsNone(captured[0]._process); self.assertIsNone(captured[0]._job)
        self.terminal()

    def test_duplicate_concurrent_worker_cannot_reuse_pending_review_or_launch_again(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.reject(future, display)
        self.terminal()
        self.assertIsNone(self.host._issued_custody._status().gate)

    def test_replay_of_initial_host_history_cannot_start_another_session(self):
        old = self.host._live
        future, _ = self.allow(); future.result(timeout=8)
        self.host._live = self.host._issued_live = self.host._recovery_live = old
        self.host._started = self.host._finished = self.host._cleanup_confirmed = False
        self.host._display = self.host._answer = None
        for name in ('custody', 'model', 'recipient', 'lifecycle', 'fixture_stage'):
            setattr(self.host, '_'+name, None); setattr(self.host, '_issued_'+name, None)
        with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.slot._value, 1)

    def test_copy_of_native_stage_cannot_dispose_or_open_original_child(self):
        future, display = self.start()
        copied = copy(self.host._issued_fixture_stage)
        with self.assertRaises(stage.SourceFixtureStageError): copied.close()
        self.assertIsNone(self.host._issued_fixture_stage._native_original().child.poll())
        self.host.operator.respond(display, 'DENY')
        self.assertEqual(future.result(timeout=4).released_bytes, 0)

    def test_invalid_mutated_display_never_dispatches_deepcopy_callback(self):
        future, display = self.start(); original = display.application_id
        class Foreign:
            def __deepcopy__(self, memo):
                raise AssertionError('foreign deepcopy callback must never run')
        object.__setattr__(display, 'application_id', Foreign())
        self.assertEqual(self.host.operator.pending(), ())
        with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=8)
        object.__setattr__(display, 'application_id', original)
        self.assertFalse(Path(display.display_path).exists())
        self.terminal()

    def test_oversized_mutated_display_is_bounded_before_serialization(self):
        future, display = self.start(); original = display.proposal_json
        object.__setattr__(display, 'proposal_json', 'x'*4097)
        self.assertEqual(self.host.operator.pending(), ())
        with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=8)
        object.__setattr__(display, 'proposal_json', original)
        self.assertFalse(Path(display.display_path).exists())
        self.terminal()

    def test_failure_after_real_staging_wipes_quarantine_and_starts_no_later_peer(self):
        original = stage._SourceFixtureStage.stage; reached = []
        def staged(owner, *args):
            result = original(owner, *args)
            self.assertEqual(bytes(self.host._issued_lifecycle._owned_buffer), b'SecurityBrightness synthetic fixture\n')
            reached.append(True)
            raise ValueError('test adapter failure after buffering')
        with patch.object(stage._SourceFixtureStage, 'stage', staged):
            future, display = self.allow(); self.reject(future, display)
        self.assertEqual(reached, [True])
        self.assertIsNone(self.host._issued_custody._status().gate)
        self.terminal()

    def test_attached_first_native_stage_cannot_be_erased_to_claim_no_child(self):
        future, display = self.start()
        custody = self.host._issued_custody
        custody._fixture = custody._issued_fixture = custody._recovery_fixture = None
        custody._fixture_stage = custody._issued_fixture_stage = custody._recovery_fixture_stage = None
        self.host.close(); self.reject(future, display)
        self.assertEqual(self.slot._value, 0)
        self.terminal()

    def test_unchanged_absolute_timeout_covers_first_fixture_and_review_wait(self):
        self.host = host.BrokerSourceFixtureHost(self.registry, self.ledger, timeout=.5)
        self.addCleanup(self.host.close)
        future, display = self.start()
        deadline = self.host._deadline
        self.reject(future, display)
        self.assertEqual(self.host._deadline, deadline)
        self.assertEqual(deadline, self.host._issued_custody._original().deadline)
        self.terminal()

    def test_single_foreign_source_archive_never_receives_disposal_callbacks(self):
        future, display = self.start(); custody = self.host._issued_custody
        foreign = Mock(); custody._source = foreign
        self.host.close(); self.reject(future, display)
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.slot._value, 0)
        self.terminal()

    def test_single_foreign_review_archive_never_receives_disposal_callbacks(self):
        future, display = self.start(); custody = self.host._issued_custody
        foreign = Mock(); custody._review = foreign
        self.host.close(); self.reject(future, display)
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.slot._value, 0)
        self.terminal()

    def test_single_foreign_wire_archive_after_staging_never_receives_disposal_callbacks(self):
        original = stage._SourceFixtureStage.stage; reached, foreign = [], Mock()
        def staged(owner, *args):
            value = original(owner, *args)
            self.host._issued_custody._wire = foreign
            reached.append(True)
            return value
        with patch.object(stage._SourceFixtureStage, 'stage', staged):
            future, display = self.allow(); self.reject(future, display)
        self.assertEqual(reached, [True])
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.slot._value, 0)
        self.terminal()

    def test_held_host_control_cannot_block_cancellation_or_native_disposal(self):
        future, display = self.start()
        held, release = threading.Event(), threading.Event()
        def hold():
            with self.host._original().condition_lock:
                held.set(); release.wait(3)
        owner = threading.Thread(target=hold); owner.start()
        try:
            self.assertTrue(held.wait(1))
            started = time.monotonic(); self.host.close()
            self.assertLess(time.monotonic()-started, .2)
            with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=2)
            self.assertFalse(Path(display.display_path).exists())
            self.terminal()
        finally: release.set(); owner.join(1)


if __name__ == '__main__': unittest.main()
