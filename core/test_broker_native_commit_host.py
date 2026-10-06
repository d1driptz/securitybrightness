"""Inactive host composition of real fixture staging and native dry commitment."""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from core import broker_native_commit_host as host
from core import broker_native_commit_check as channel
from core import broker_native_commit_peer as peer
from core import broker_process as fixture_process
from core import broker_recipient_process as guarded_process
from core import broker_transport as transport
from core import test_broker_review_host as review_helpers
from core import test_broker_publication_host as publication_helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_live_review import LiveBrokerReview
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_publication_lifecycle import LivePublicationDraft
from core.broker_recipient_channel import RecipientChannelShutdownStatus


class NativePublicationCommitHostTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        review_helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerNativePublicationCommitHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)

    run_host = review_helpers.BrokerReviewHostTests.run_host
    start = review_helpers.BrokerReviewHostTests.start
    reject = review_helpers.BrokerReviewHostTests.reject
    allowed = publication_helpers.PublicationDiscardHostTests.allowed

    def assert_retired(self, helper):
        self.assertEqual(helper._lifecycle._owned_buffer, bytearray())
        self.assertEqual(helper._review._state, 'closed')
        self.assertIs(helper._recipient._terminal, True)

    def test_sequential_native_children_share_admission_and_retire_without_delivery(self):
        events = []; fixtures = []; checks = []
        original_fixture_init = fixture_process._PublicationCheckChild.__init__
        original_peer_init = peer._PublicationCommitPeer.__init__
        original_ready = PublicationCommitExchange.accept_ready
        original_receipt = PublicationCommitExchange.accept_receipt
        original_record = LiveBrokerReview._record
        original_reserve = AcquisitionDraft._reserve
        def fixture_init(child):
            original_fixture_init(child); fixtures.append(child); events.append('fixture')
        def peer_init(child):
            self.assertEqual(len(fixtures), 1)
            self.assertIsNone(fixtures[0]._process); self.assertIsNone(fixtures[0]._job)
            self.assertEqual(transport._slot._value, 0)
            original_peer_init(child); events.append('fixed_peer')
        def ready(wire, frame):
            value = original_ready(wire, frame)
            helper = self.host._channel_check
            self.assertEqual(bytes(helper._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll())
            checks.append(helper); events.append('ready'); return value
        def receipt(wire, frame):
            helper = self.host._channel_check
            self.assertEqual(helper._owned_buffer, bytearray())
            helper._issued_child._retired()
            self.assertEqual(helper._issued_child._exit, 0)
            self.assertIsNone(helper._issued_child._process)
            self.assertIsNone(helper._issued_child._job)
            value = original_receipt(wire, frame)
            events.append('joined_receipt'); return value
        with patch.object(fixture_process._PublicationCheckChild, '__init__', fixture_init), \
                patch.object(peer._PublicationCommitPeer, '__init__', peer_init), \
                patch.object(PublicationCommitExchange, 'accept_ready', ready), \
                patch.object(PublicationCommitExchange, 'accept_receipt', receipt), \
                patch.object(LiveBrokerReview, '_record', autospec=True, side_effect=original_record) as record, \
                patch.object(AcquisitionDraft, '_reserve', autospec=True, side_effect=original_reserve) as reserve:
            future, display = self.allowed(); result = future.result(timeout=3)
            self.assertEqual(record.call_count, 1)
            self.assertEqual(reserve.call_count, 1)
        self.assertEqual(events, ['fixture', 'fixed_peer', 'ready', 'joined_receipt'])
        self.assertEqual((result.decision, result.staged_bytes, result.released_bytes), ('allow_once', 37, 0))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertFalse(Path(display.display_path).exists())
        self.assertIs(self.host.operator.shutdown_status().cleanup_confirmed, True)
        self.assertEqual(len(checks), 1); self.assert_retired(checks[0])
        self.assertIsNone(checks[0].retired_check())
        for name in ('data', 'frame', 'permission', 'token', 'process_id'):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(TypeError): bool(result)

    def test_human_deny_never_launches_commit_peer_or_reserves(self):
        with patch.object(channel, '_PublicationCommitPeer') as launch, patch.object(AcquisitionDraft, '_reserve') as reserve:
            future, display = self.start(); self.host.operator.respond(display, 'DENY')
            result = future.result(timeout=3)
            launch.assert_not_called(); reserve.assert_not_called()
        self.assertEqual((result.decision, result.staged_bytes, result.released_bytes), ('deny', 0, 0))
        self.assertFalse(Path(display.display_path).exists())

    def test_application_authority_without_human_response_cannot_launch_commit_peer(self):
        with patch.object(channel, '_PublicationCommitPeer') as launch:
            future, display = self.start(); self.host.close(); self.reject(future, display)
            launch.assert_not_called()

    def test_human_response_cannot_replace_removed_application_authority(self):
        with patch.object(channel, '_PublicationCommitPeer') as launch:
            future, display = self.start(); self.registry.revoke('app')
            # Respond queues an answer; only the worker can validate current
            # authority. A queued answer must never become permission.
            self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display); launch.assert_not_called()

    def test_success_does_not_create_reusable_permission(self):
        future, display = self.allowed(); self.assertEqual(future.result(timeout=3).released_bytes, 0)
        with patch.object(channel, '_PublicationCommitPeer') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')

    def ready_fault(self, effect):
        original = PublicationCommitExchange.accept_ready; entered = []
        def ready(wire, frame):
            value = original(wire, frame); helper = self.host._channel_check
            self.assertEqual(bytes(helper._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll())
            entered.append(helper); effect(helper); return value
        with patch.object(PublicationCommitExchange, 'accept_ready', ready):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'must reach real native READY')
        self.assert_retired(entered[0])

    def test_revocation_after_native_ready_withholds_host_result(self):
        self.ready_fault(lambda helper: self.registry.revoke('app'))

    def test_cancellation_after_native_ready_withholds_host_result(self):
        self.ready_fault(lambda helper: self.host.close())

    def test_owned_buffer_substitution_after_ready_is_rejected(self):
        self.ready_fault(lambda helper: setattr(helper._lifecycle._wire, '_buffer', bytearray(self.DATA)))

    def test_commit_owner_substitution_after_ready_is_rejected_without_invoking_foreign_owner(self):
        foreign = Mock()
        self.ready_fault(lambda helper: setattr(helper, '_commit', foreign))
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()

    def cleanup_fault(self, effect):
        original = guarded_process._RecipientWitnessChild.close; entered = []
        def close(child):
            original(child); helper = self.host._channel_check
            self.assertEqual(helper._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(guarded_process._RecipientWitnessChild, 'close', close):
            future, display = self.allowed(); self.reject(future, display)
        self.assertTrue(entered, 'must reach fixed peer cleanup')
        self.assert_retired(entered[0])

    def test_revocation_after_private_receipts_and_native_join_withholds_host_result(self):
        self.cleanup_fault(lambda helper: self.registry.revoke('app'))

    def test_cancel_after_private_receipts_and_native_join_withholds_host_result(self):
        self.cleanup_fault(lambda helper: self.host.close())

    def test_uncertain_joined_peer_cleanup_retains_admission(self):
        def fail(helper): raise guarded_process.BrokerProcessError('process_cleanup_failed')
        self.cleanup_fault(fail)
        self.assertIs(self.host.operator.shutdown_status().cleanup_confirmed, False)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def uncertain_status_fault(self, **options):
        with patch.object(channel.NativePublicationCommitCheck, 'shutdown_status', **options):
            self.ready_fault(lambda helper: helper.close())
        self.assertIs(self.host.operator.shutdown_status().cleanup_confirmed, False)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def test_missing_helper_cleanup_status_retains_admission(self):
        self.uncertain_status_fault(side_effect=OSError('status unavailable'))

    def test_requester_shaped_helper_cleanup_status_retains_admission(self):
        self.uncertain_status_fault(return_value={'cleanup_confirmed': True})

    def test_truthy_cleanup_status_retains_admission(self):
        self.uncertain_status_fault(return_value=RecipientChannelShutdownStatus(1))

    def slot_fault(self, effect):
        slot = transport._slot; original = slot.release; entered = []
        def release():
            original(); helper = self.host._channel_check
            self.assertIsNotNone(helper._issued_commit._receipt)
            self.assertIsNotNone(helper._ack)
            self.assertEqual(helper._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(slot, 'release', release):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'fault must follow both joined children and native receipt')
        self.assert_retired(entered[0])

    def test_registry_revocation_at_admission_release_withholds_result(self):
        self.slot_fault(lambda helper: self.registry.revoke('app'))

    def test_helper_owner_substitution_at_admission_release_is_rejected(self):
        foreign = Mock()
        self.slot_fault(lambda helper: setattr(self.host, '_channel_check', foreign))
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()

    def test_commit_receipt_copy_at_admission_release_is_rejected(self):
        self.slot_fault(lambda helper: setattr(helper._issued_commit, '_receipt', replace(helper._issued_commit._receipt)))

    def test_native_cleanup_mutation_at_admission_release_poisons_admission(self):
        self.slot_fault(lambda helper: setattr(helper._issued_child, '_cleanup_failed', True))
        self.assertIs(self.host.operator.shutdown_status().cleanup_confirmed, False)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def test_guard_substitution_and_reinserted_bytes_still_wipe_original(self):
        foreign = Mock()
        def replace_owner(helper):
            helper._owned_buffer.extend(self.DATA)
            self.host._channel_check = foreign
        self.slot_fault(replace_owner)
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()

    def post_fence_fault(self, effect):
        original = host.BrokerNativePublicationCommitHost._post_check_evidence; entered = []
        def post_check(owner):
            original(owner); helper = owner._channel_check
            self.assertIsNotNone(helper._issued_commit._receipt)
            self.assertIsNotNone(helper._ack)
            self.assertEqual(helper._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(host.BrokerNativePublicationCommitHost, '_post_check_evidence', post_check):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'must reach delegated terminal native validation')
        self.assert_retired(entered[0])

    def test_revocation_after_terminal_native_validation_is_rechecked(self):
        self.post_fence_fault(lambda helper: self.registry.revoke('app'))

    def test_reintroduced_bytes_after_terminal_native_validation_are_wiped(self):
        self.post_fence_fault(lambda helper: helper._owned_buffer.extend(self.DATA))

    def test_helper_swap_after_terminal_evidence_hook_is_rechecked(self):
        foreign = SimpleNamespace(_lock=MagicMock(), close=Mock(), retired_check=Mock())
        self.post_fence_fault(lambda helper: setattr(self.host, '_channel_check', foreign))
        foreign._lock.__enter__.assert_not_called()
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()

    def test_helper_swap_during_delegated_terminal_validation_is_rechecked(self):
        foreign = SimpleNamespace(_lock=MagicMock(), close=Mock(), retired_check=Mock())
        original = channel.NativePublicationCommitCheck.retired_check; entered = []
        def retired(helper):
            original(helper)
            if transport._slot._value == 1 and not entered:
                self.assertIsNotNone(helper._issued_commit._receipt)
                entered.append(helper); self.host._channel_check = foreign
        with patch.object(channel.NativePublicationCommitCheck, 'retired_check', retired):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'owner swap must occur inside post-release native validation')
        self.assert_retired(entered[0])
        foreign._lock.__enter__.assert_not_called()
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()

    def peer_helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'native-commit-host-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_native_commit_entry as entry\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(peer._PublicationCommitPeer, '_entry_path', return_value=path)

    def test_native_receipts_then_trailing_output_withhold_host_result(self):
        with self.peer_helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"):
            future, display = self.allowed(); self.reject(future, display)

    def test_native_receipts_then_nonzero_exit_withhold_host_result(self):
        with self.peer_helper(ending='os._exit(9)'):
            future, display = self.allowed(); self.reject(future, display)

    def test_native_startup_hang_is_cancelled_with_confirmed_cleanup(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        marker = Path(directory.name)/'native-peer-entered.txt'
        prefix = 'from pathlib import Path\nPath('+repr(str(marker))+').write_text("entered")\ntime.sleep(30)'
        with self.peer_helper(prefix=prefix):
            future, display = self.allowed()
            deadline = time.monotonic()+2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.002)
            self.assertTrue(marker.exists(), 'fixed peer must start before cancel')
            helper = self.host._channel_check
            self.assertEqual(bytes(helper._owned_buffer), self.DATA)
            self.host.close(); self.reject(future, display)
        self.assert_retired(helper)
        self.assertIs(self.host.operator.shutdown_status().cleanup_confirmed, True)


if __name__ == '__main__': unittest.main()
