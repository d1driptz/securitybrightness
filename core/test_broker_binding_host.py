"""Inactive host integration tests; scripted responses are not human review."""
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from core import test_broker_review_host as helpers
from core import broker_binding_host as host
from core import broker_process as process
from core import broker_transport as transport
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_binding_protocol import AcquisitionBindingExchange


class BindingHostTests(unittest.TestCase):
    def setUp(self):
        helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerBindingHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)

    run_host = helpers.BrokerReviewHostTests.run_host
    start = helpers.BrokerReviewHostTests.start
    reject = helpers.BrokerReviewHostTests.reject
    test_real_allow_only_returns_retired_metadata_after_deletion = helpers.BrokerReviewHostTests.test_real_allow_only_returns_retired_metadata_after_deletion
    test_deny_retires_and_deletes_fixture = helpers.BrokerReviewHostTests.test_deny_retires_and_deletes_fixture
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

    def test_deny_cannot_create_reservation(self):
        with patch.object(AcquisitionDraft, '_reserve', side_effect=AssertionError('DENY must not reserve')) as reserve:
            future, display = self.start(); self.host.operator.respond(display, 'DENY')
            self.assertEqual(future.result(timeout=3).decision, 'deny')
            reserve.assert_not_called()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_cancel_before_launch_confirms_no_child(self):
        self.host.close()
        with patch.object(host, '_BindingMetadataChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_bad_credential_never_launches(self):
        self.credential = 'wrong'
        with patch.object(host, '_BindingMetadataChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_shared_admission_prevents_launch(self):
        transport._slot.acquire()
        with patch.object(host, '_BindingMetadataChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_replay_cannot_launch_again(self):
        future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
        future.result(timeout=3)
        with patch.object(host, '_BindingMetadataChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def cleanup_fault(self, effect):
        original = process._BindingMetadataChild.close
        def close(child):
            original(child); effect()
        with patch.object(process._BindingMetadataChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_cleanup_revocation_withholds_result(self):
        self.cleanup_fault(lambda: self.registry.revoke('app'))

    def test_cleanup_cancellation_withholds_result(self):
        self.cleanup_fault(self.host.close)

    def test_cleanup_expiry_withholds_result(self):
        self.cleanup_fault(lambda: setattr(self.host, '_deadline', 0))

    def test_cleanup_failure_poisons_admission(self):
        def fail(): raise process.BrokerProcessError('process_cleanup_failed')
        self.cleanup_fault(fail)
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_revocation_during_final_model_cleanup_is_rejected(self):
        original = AcquisitionDraft.close
        count = 0
        def close(model):
            nonlocal count
            original(model); count += 1
            if count == 2: self.registry.revoke('app')
        with patch.object(AcquisitionDraft, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_revocation_after_bound_prevents_retire_message(self):
        original = AcquisitionBindingExchange.receive
        def receive(endpoint, frame):
            result = original(endpoint, frame)
            if endpoint._step == 2: self.registry.revoke('app')
            return result
        with patch.object(AcquisitionBindingExchange, 'receive', receive):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def helper(self, ending):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_binding_entry as entry\nentry.run()\n'+ending, encoding='utf-8')
        return patch.object(process._BindingMetadataChild, '_entry_path', return_value=path)

    def test_final_ack_followed_by_nonzero_exit_is_rejected(self):
        with self.helper('os._exit(9)'):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_final_ack_followed_by_trailing_output_is_rejected(self):
        with self.helper("sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_final_ack_followed_by_hang_is_rejected(self):
        with self.helper('time.sleep(30)'):
            future, display = self.start()
            self.host._deadline = time.monotonic()+.5
            self.host.operator.respond(display, 'ALLOW ONCE'); self.reject(future, display)

    def test_cleanup_status_is_unavailable_until_worker_finishes(self):
        future, display = self.start()
        self.assertIsNone(self.host.operator.shutdown_status())
        self.host.close(); self.reject(future, display)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_launch_failure_releases_admission(self):
        with patch.object(host, '_BindingMetadataChild', side_effect=process.BrokerProcessError('launch_failed')):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertTrue(transport._slot.acquire(blocking=False))
        transport._slot.release()
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_launch_cleanup_uncertainty_poisons_admission(self):
        with patch.object(host, '_BindingMetadataChild', side_effect=process.BrokerProcessError('process_cleanup_failed')):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_deny_cleanup_revocation_withholds_receipt(self):
        original = process._BindingMetadataChild.close
        def close(child):
            original(child); self.registry.revoke('app')
        with patch.object(process._BindingMetadataChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'DENY')
            self.reject(future, display)

    def test_registry_failure_after_cleanup_withholds_receipt(self):
        original = process._BindingMetadataChild.close
        def close(child):
            original(child); self.registry.close()
        with patch.object(process._BindingMetadataChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_short_lifetime_cannot_be_extended(self):
        for value in (True, 0, 6, float('nan'), '5'):
            with self.assertRaises(ValueError): host.BrokerBindingHost(self.registry, self.ledger, timeout=value)
