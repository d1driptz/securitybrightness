"""Inactive real-child acquisition tests; scripted answers are not human review."""
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from core import broker_acquisition_host as host
from core import broker_process as process
from core import broker_transport as transport
from core import test_broker_review_host as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_acquisition_lifecycle import LiveAcquisitionLifecycle
from core.broker_quarantine import QuarantinedReadExchange
from core.file_read_schema import make_file_read_proposal


class AcquisitionDiscardHostTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerAcquisitionDiscardHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)

    run_host = helpers.BrokerReviewHostTests.run_host
    start = helpers.BrokerReviewHostTests.start
    reject = helpers.BrokerReviewHostTests.reject
    test_cancel_while_waiting_kills_child_and_deletes_fixture = helpers.BrokerReviewHostTests.test_cancel_while_waiting_kills_child_and_deletes_fixture
    test_timeout_while_waiting_deletes_fixture = helpers.BrokerReviewHostTests.test_timeout_while_waiting_deletes_fixture
    test_operator_and_worker_ports_are_separate = helpers.BrokerReviewHostTests.test_operator_and_worker_ports_are_separate
    test_forged_display_cancels_session = helpers.BrokerReviewHostTests.test_forged_display_cancels_session
    test_mutated_display_cancels_session = helpers.BrokerReviewHostTests.test_mutated_display_cancels_session
    test_inexact_answer_cancels_session = helpers.BrokerReviewHostTests.test_inexact_answer_cancels_session
    test_registry_revocation_after_display_rejects_answer = helpers.BrokerReviewHostTests.test_registry_revocation_after_display_rejects_answer
    test_rotation_after_display_rejects_answer = helpers.BrokerReviewHostTests.test_rotation_after_display_rejects_answer
    test_draft_revocation_after_display_rejects_answer = helpers.BrokerReviewHostTests.test_draft_revocation_after_display_rejects_answer
    test_duplicate_worker_cancels_original = helpers.BrokerReviewHostTests.test_duplicate_worker_cancels_original
    test_duplicate_queued_answer_cancels_before_recording = helpers.BrokerReviewHostTests.test_duplicate_queued_answer_cancels_before_recording

    def allowed(self):
        future, display = self.start()
        self.host.operator.respond(display, 'ALLOW ONCE')
        return future, display

    def test_real_allow_stages_exact_fixture_and_returns_only_zero_release_metadata(self):
        original_app = self.registry.get('app')
        future, display = self.allowed()
        result = future.result(timeout=3)
        self.assertEqual(result.decision, 'allow_once')
        self.assertEqual(result.staged_bytes, 37)
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual((result.lifecycle, result.released_bytes), ('retired', 0))
        self.assertFalse(Path(display.display_path).exists())
        self.assertFalse(hasattr(result, 'data'))
        self.assertNotIn(self.DATA, result.canonical_display)
        self.assertNotIn(self.credential, result.canonical_display.decode())
        self.assertIs(self.registry.get('app'), original_app)
        with self.assertRaises(TypeError): bool(result)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assertEqual(self.host.operator.pending(), ())

    def test_deny_never_reserves_or_acquires_and_returns_zero_release_metadata(self):
        with patch.object(AcquisitionDraft, '_reserve', side_effect=AssertionError('DENY must not reserve')) as reserve:
            future, display = self.start(); self.host.operator.respond(display, 'DENY')
            result = future.result(timeout=3)
            reserve.assert_not_called()
        self.assertEqual((result.decision, result.staged_bytes, result.released_bytes), ('deny', 0, 0))
        self.assertEqual(result.staged_digest, hashlib.sha256(b'').hexdigest())
        self.assertFalse(Path(display.display_path).exists())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_application_authority_without_human_answer_never_stages(self):
        with patch.object(LiveAcquisitionLifecycle, '_begin', side_effect=AssertionError('human required')) as begin:
            future, display = self.start(); self.host.operator.cancel()
            self.reject(future, display)
            begin.assert_not_called()

    def test_revoked_application_cannot_launch_child(self):
        self.registry.revoke('app')
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_bad_credential_cannot_launch_child(self):
        self.credential = 'wrong'
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_application_without_read_permission_cannot_launch_child(self):
        self.registry.update_permissions('app', scopes=['files.write'])
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_wrong_application_cannot_reuse_other_application_draft(self):
        credential = self.registry.register('other', ['files.read'])
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError):
                self.host.worker.run('other', credential, self.proposal, self.draft.draft_id, 1)
            launch.assert_not_called()

    def test_cancellation_before_launch_confirms_no_child(self):
        self.host.close()
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_replay_cannot_launch_or_review_again(self):
        future, display = self.allowed(); future.result(timeout=3)
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_shared_admission_prevents_launch(self):
        transport._slot.acquire()
        with patch.object(host, '_AcquisitionDiscardChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_launch_failure_releases_slot_and_confirms_cleanup(self):
        with patch.object(host, '_AcquisitionDiscardChild', side_effect=process.BrokerProcessError('launch_failed')):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertTrue(transport._slot.acquire(blocking=False)); transport._slot.release()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_launch_cleanup_uncertainty_poisons_slot(self):
        with patch.object(host, '_AcquisitionDiscardChild', side_effect=process.BrokerProcessError('process_cleanup_failed')):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)

    def cleanup_fault(self, effect, answer='ALLOW ONCE'):
        original = process._AcquisitionDiscardChild.close
        def close(child):
            original(child); effect()
        with patch.object(process._AcquisitionDiscardChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, answer)
            self.reject(future, display)

    def test_revocation_during_child_cleanup_withholds_result(self):
        self.cleanup_fault(lambda: self.registry.revoke('app'))

    def test_cancellation_during_child_cleanup_withholds_result(self):
        self.cleanup_fault(self.host.close)

    def test_expiry_during_child_cleanup_withholds_result(self):
        self.cleanup_fault(lambda: setattr(self.host, '_deadline', 0))

    def test_registry_failure_after_cleanup_withholds_result(self):
        self.cleanup_fault(self.registry.close)

    def test_deny_revocation_during_cleanup_withholds_result(self):
        self.cleanup_fault(lambda: self.registry.revoke('app'), answer='DENY')

    def test_process_cleanup_failure_poisons_slot_and_withholds_result(self):
        def fail(): raise process.BrokerProcessError('process_cleanup_failed')
        self.cleanup_fault(fail)
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_cleanup_status_unavailable_until_worker_finishes(self):
        future, display = self.start()
        self.assertIsNone(self.host.operator.shutdown_status())
        self.host.close(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def after_stage_fault(self, effect):
        original = LiveAcquisitionLifecycle._stage
        owned = []
        def stage(lifecycle, frame):
            result = original(lifecycle, frame)
            owned.append(lifecycle)
            effect()
            return result
        with patch.object(LiveAcquisitionLifecycle, '_stage', stage):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(owned), 1)
        self.assertEqual(owned[0]._wire._buffer, bytearray())
        self.assertEqual(owned[0]._review._state, 'closed')

    def test_revocation_after_buffering_clears_quarantine(self):
        self.after_stage_fault(lambda: self.registry.revoke('app'))

    def test_cancellation_after_buffering_clears_quarantine(self):
        self.after_stage_fault(self.host.close)

    def test_expiry_after_buffering_clears_quarantine(self):
        self.after_stage_fault(lambda: setattr(self.host, '_deadline', 0))

    def test_changed_draft_after_buffering_clears_quarantine(self):
        self.after_stage_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.draft.constraint))

    def test_proposal_mutation_after_buffering_clears_quarantine(self):
        self.after_stage_fault(lambda: object.__setattr__(self.proposal, '_body',
            make_file_read_proposal('changed', max_bytes=128).canonical_bytes()))

    def slot_fault(self, effect):
        slot = transport._slot; original = slot.release
        def release():
            original(); effect()
        with patch.object(slot, 'release', release):
            future, display = self.allowed(); self.reject(future, display)

    def test_revocation_at_slot_release_withholds_result(self):
        self.slot_fault(lambda: self.registry.revoke('app'))

    def test_cancellation_at_slot_release_withholds_result(self):
        self.slot_fault(self.host.close)

    def test_expiry_at_slot_release_withholds_result(self):
        self.slot_fault(lambda: setattr(self.host, '_deadline', 0))

    def test_draft_revocation_at_slot_release_withholds_result(self):
        self.slot_fault(lambda: self.ledger.revoke(self.draft.draft_id, 1))

    def final_evidence_fault(self, effect):
        captured = []; original = LiveAcquisitionLifecycle._check_publication
        def check(owner, *args):
            result = original(owner, *args); captured.append(owner); return result
        with patch.object(LiveAcquisitionLifecycle, '_check_publication', check):
            self.slot_fault(lambda: effect(captured[0]))
        self.assertEqual(len(captured), 1)

    def test_ticket_mutation_at_slot_release_withholds_result(self):
        self.final_evidence_fault(lambda owner: object.__setattr__(
            owner._review._ticket.review, 'proposal_id', 'sbp2_sha256_'+'f'*64))

    def test_decision_mutation_at_slot_release_withholds_result(self):
        self.final_evidence_fault(lambda owner: setattr(owner._review, '_decision', 'deny'))

    def test_equal_valued_decision_subclass_at_slot_release_withholds_result(self):
        class DerivedDecision(str): pass
        self.final_evidence_fault(lambda owner: setattr(owner._review, '_decision', DerivedDecision('allow_once')))

    def test_display_identity_substitution_at_slot_release_withholds_result(self):
        from dataclasses import replace
        self.final_evidence_fault(lambda owner: setattr(owner._review, '_shown', replace(owner._review._shown)))

    def test_mutated_publication_check_result_cannot_report_false_staging(self):
        original = LiveAcquisitionLifecycle._check_publication
        def check(owner, *args):
            result = original(owner, *args)
            object.__setattr__(result, 'staged_bytes', 4096)
            return result
        with patch.object(LiveAcquisitionLifecycle, '_check_publication', check):
            future, display = self.allowed(); self.reject(future, display)

    def test_slot_release_failure_reports_finished_and_uncertain_cleanup(self):
        with patch.object(transport._slot, 'release', side_effect=ValueError('release failed')):
            future, display = self.allowed()
            with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=3)
        self.assertFalse(Path(display.display_path).exists())
        status = self.host.operator.shutdown_status()
        self.assertIsNotNone(status)
        self.assertFalse(status.cleanup_confirmed)

    def helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_acquisition_entry as entry\n'
            'from core import broker_native_acquisition as native\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(process._AcquisitionDiscardChild, '_entry_path', return_value=path)

    def test_valid_ack_then_nonzero_exit_is_rejected(self):
        with self.helper(ending='os._exit(9)'):
            future, display = self.allowed(); self.reject(future, display)

    def test_valid_ack_then_trailing_output_is_rejected(self):
        with self.helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"):
            future, display = self.allowed(); self.reject(future, display)

    def test_valid_ack_then_hang_is_rejected(self):
        with self.helper(ending='time.sleep(30)'):
            future, display = self.start()
            self.host._deadline = time.monotonic()+.5
            self.host.operator.respond(display, 'ALLOW ONCE'); self.reject(future, display)

    def test_child_native_acquisition_failure_is_rejected(self):
        prefix = ('def acquire(*args): raise native.NativeAcquisitionError("native failed")\n'
                  'native._NativeReadFixture.acquire_once=acquire\n')
        with self.helper(prefix=prefix):
            future, display = self.allowed(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_cancellation_interrupts_child_blocked_in_native_acquisition(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        marker = Path(directory.name)/'entered.txt'
        prefix = ('from pathlib import Path\n'
                  'def acquire(*args):\n Path('+repr(str(marker))+').write_text("entered")\n time.sleep(30)\n'
                  'native._NativeReadFixture.acquire_once=acquire\n')
        with self.helper(prefix=prefix):
            future, display = self.allowed()
            deadline = time.monotonic()+2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.005)
            self.assertTrue(marker.exists(), 'child must enter the blocking acquisition')
            self.host.close(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_mutation_during_final_child_context_cleanup_withholds_ack(self):
        prefix = ('original=native.NativeFixtureAcquisitionAdapter.__exit__\n'
                  'def exit(owner,*args):\n original(owner,*args)\n'
                  ' object.__setattr__(owner._owner.description,"size_bytes",36)\n'
                  'native.NativeFixtureAcquisitionAdapter.__exit__=exit\n')
        with self.helper(prefix=prefix):
            future, display = self.allowed(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_child_crash_during_native_acquisition_is_rejected_and_fixture_deleted(self):
        prefix = ('def acquire(*args): os._exit(9)\n'
                  'native._NativeReadFixture.acquire_once=acquire\n')
        with self.helper(prefix=prefix):
            future, display = self.allowed(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_child_crash_after_buffering_clears_quarantine(self):
        prefix = ('original=native.NativeFixtureAcquisitionAdapter.retire\n'
                  'def retire(*args): os._exit(9)\n'
                  'native.NativeFixtureAcquisitionAdapter.retire=retire\n')
        captured = []; original = LiveAcquisitionLifecycle._stage
        def stage(owner, frame):
            result = original(owner, frame); captured.append(owner); return result
        with self.helper(prefix=prefix), patch.object(LiveAcquisitionLifecycle, '_stage', stage):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]._wire._buffer, bytearray())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_child_native_close_failure_after_staging_clears_quarantine(self):
        prefix = ('original=native._NativeReadFixture.close\n'
                  'def close(owner):\n original(owner)\n raise native.NativeAcquisitionError("close failed")\n'
                  'native._NativeReadFixture.close=close\n')
        captured = []; original = LiveAcquisitionLifecycle._stage
        def stage(owner, frame):
            result = original(owner, frame); captured.append(owner); return result
        with self.helper(prefix=prefix), patch.object(LiveAcquisitionLifecycle, '_stage', stage):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]._wire._buffer, bytearray())

    def test_child_forged_staging_after_native_read_is_rejected(self):
        prefix = ('original=native.NativeFixtureAcquisitionAdapter.stage\n'
                  'def stage(owner,frame):\n result=original(owner,frame)\n'
                  ' return result[:-1]+bytes([result[-1]^1])\n'
                  'native.NativeFixtureAcquisitionAdapter.stage=stage\n')
        with self.helper(prefix=prefix):
            future, display = self.allowed(); self.reject(future, display)

    def test_bad_startup_never_publishes_prompt(self):
        prefix = ('entry.ready=lambda key,session,pid: b"x"*76\n')
        with self.helper(prefix=prefix):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.host.operator.pending(), ())

    def test_startup_hang_is_bounded(self):
        self.host.close()
        self.host = host.BrokerAcquisitionDiscardHost(self.registry, self.ledger, timeout=.2)
        self.addCleanup(self.host.close)
        with self.helper(prefix='time.sleep(30)'):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.host.operator.pending(), ())

    def test_short_budget_cannot_be_extended_by_caller(self):
        for value in (True, 0, 6, float('nan'), float('inf'), '5'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                host.BrokerAcquisitionDiscardHost(self.registry, self.ledger, timeout=value)

    def test_ports_have_no_data_read_delivery_or_binding_bypass(self):
        for port in (self.host.worker, self.host.operator):
            for name in ('read', 'release', 'publish', 'get_buffer', 'stage', 'check_publication', 'data'):
                self.assertFalse(hasattr(port, name))


if __name__ == '__main__': unittest.main()
