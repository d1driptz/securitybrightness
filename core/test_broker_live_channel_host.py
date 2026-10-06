"""Inactive generated-fixture final checks against a live fixed private peer."""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_live_channel_host as host
from core import broker_live_channel_check as channel
from core import broker_process as fixture_process
from core import broker_recipient_process as recipient_process
from core import broker_transport as transport
from core import test_broker_review_host as review_helpers
from core import test_broker_publication_host as publication_helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_live_review import LiveBrokerReview
from core.broker_publication_lifecycle import LivePublicationDraft
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.broker_recipient_channel import RecipientChannelShutdownStatus
from core.file_read_schema import make_file_read_proposal


class LiveChannelPublicationHostTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        review_helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerLiveChannelPublicationHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)

    run_host = review_helpers.BrokerReviewHostTests.run_host
    start = review_helpers.BrokerReviewHostTests.start
    reject = review_helpers.BrokerReviewHostTests.reject
    allowed = publication_helpers.PublicationDiscardHostTests.allowed
    test_operator_and_worker_ports_are_separate = review_helpers.BrokerReviewHostTests.test_operator_and_worker_ports_are_separate
    test_cancel_while_waiting_kills_fixture = review_helpers.BrokerReviewHostTests.test_cancel_while_waiting_kills_child_and_deletes_fixture
    test_forged_display_cancels_session = review_helpers.BrokerReviewHostTests.test_forged_display_cancels_session
    test_mutated_display_cancels_session = review_helpers.BrokerReviewHostTests.test_mutated_display_cancels_session
    test_registry_revocation_after_display_rejects_answer = review_helpers.BrokerReviewHostTests.test_registry_revocation_after_display_rejects_answer
    test_rotation_after_display_rejects_answer = review_helpers.BrokerReviewHostTests.test_rotation_after_display_rejects_answer
    test_duplicate_worker_cancels_original = review_helpers.BrokerReviewHostTests.test_duplicate_worker_cancels_original
    test_application_without_read_scope_cannot_launch_fixture = publication_helpers.PublicationDiscardHostTests.test_application_without_read_permission_cannot_launch_child
    test_bad_credential_cannot_launch_fixture = publication_helpers.PublicationDiscardHostTests.test_bad_credential_cannot_launch_child

    def lifecycle(self): return self.host._channel_check._lifecycle

    def assert_retired(self, lifecycle):
        self.assertEqual(lifecycle._owned_buffer, bytearray())
        self.assertEqual(lifecycle._review._state, 'closed')
        self.assertTrue(lifecycle._recipient._terminal)

    def test_real_fixture_and_live_recipient_retire_sequentially_with_zero_release(self):
        events = []; fixtures = []; checks = []
        original_fixture_init = fixture_process._PublicationCheckChild.__init__
        original_fixture_close = fixture_process._PublicationCheckChild.close
        original_recipient_init = recipient_process._RecipientWitnessChild.__init__
        original_proof = RecipientWitnessExchange.accept_proof
        original_final = LivePublicationDraft._check_publication
        original_record = LiveBrokerReview._record
        original_reserve = AcquisitionDraft._reserve
        def fixture_init(child):
            original_fixture_init(child); fixtures.append(child); events.append('fixture_launched')
        def fixture_close(child):
            original_fixture_close(child); events.append('fixture_joined')
        def recipient_init(child):
            self.assertEqual(len(fixtures), 1)
            self.assertIsNone(fixtures[0]._process)
            self.assertIsNone(fixtures[0]._job)
            self.assertEqual(transport._slot._value, 0, 'both sequential children use one admission')
            original_recipient_init(child); events.append('recipient_launched')
        def proof(wire, frame):
            result = original_proof(wire, frame)
            helper = self.host._channel_check
            lifecycle = helper._lifecycle
            self.assertEqual(bytes(lifecycle._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll(), 'recipient must still be live during proof')
            self.assertEqual(lifecycle._state, 'cleaned')
            checks.append(helper); events.append('live_proof')
            return result
        def final(lifecycle, *args):
            helper = self.host._channel_check
            self.assertIs(lifecycle, helper._lifecycle)
            self.assertIs(lifecycle._recipient_descriptor, args[-1])
            self.assertEqual(bytes(lifecycle._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll(), 'recipient must be live at the final check')
            events.append('final_check')
            result = original_final(lifecycle, *args)
            self.assertEqual(lifecycle._owned_buffer, bytearray())
            self.assertIsNone(helper._child.poll(), 'quarantine wipes before recipient retirement')
            events.append('quarantine_wiped')
            return result
        with patch.object(fixture_process._PublicationCheckChild, '__init__', fixture_init), \
                patch.object(fixture_process._PublicationCheckChild, 'close', fixture_close), \
                patch.object(recipient_process._RecipientWitnessChild, '__init__', recipient_init), \
                patch.object(RecipientWitnessExchange, 'accept_proof', proof), \
                patch.object(LivePublicationDraft, '_check_publication', final), \
                patch.object(LiveBrokerReview, '_record', autospec=True, side_effect=original_record) as record, \
                patch.object(AcquisitionDraft, '_reserve', autospec=True, side_effect=original_reserve) as reserve:
            future, display = self.allowed(); result = future.result(timeout=3)
            self.assertEqual(record.call_count, 1, 'no second review is manufactured')
            self.assertEqual(reserve.call_count, 1, 'live channel uses the existing one-use reservation')
        self.assertEqual(events, ['fixture_launched', 'fixture_joined', 'recipient_launched',
                                  'live_proof', 'final_check', 'quarantine_wiped'])
        self.assertEqual(len(checks), 1)
        self.assertEqual((result.decision, result.staged_bytes, result.released_bytes), ('allow_once', 37, 0))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertFalse(Path(display.display_path).exists())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assert_retired(checks[0]._lifecycle)
        self.assertTrue(checks[0]._issued_child._closed)
        self.assertIsNone(checks[0]._issued_child._process)
        self.assertIsNone(checks[0]._issued_child._job)
        for name in ('data', 'frame', 'token', 'permission', 'process_id'):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(TypeError): bool(result)

    def test_deny_never_launches_recipient_or_reserves(self):
        with patch.object(channel, '_RecipientWitnessChild') as launch, \
                patch.object(AcquisitionDraft, '_reserve') as reserve:
            future, display = self.start(); self.host.operator.respond(display, 'DENY')
            result = future.result(timeout=3)
            launch.assert_not_called(); reserve.assert_not_called()
        self.assertEqual((result.decision, result.staged_bytes, result.released_bytes), ('deny', 0, 0))
        self.assertFalse(Path(display.display_path).exists())

    def test_authority_without_human_response_cannot_launch_recipient(self):
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            future, display = self.start(); self.host.close(); self.reject(future, display)
            launch.assert_not_called()

    def test_successful_run_cannot_be_replayed(self):
        future, display = self.allowed(); future.result(timeout=3)
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')

    def proof_fault(self, effect):
        entered = []; original = RecipientWitnessExchange.accept_proof
        def proof(wire, frame):
            result = original(wire, frame)
            helper = self.host._channel_check
            self.assertEqual(bytes(helper._lifecycle._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll())
            entered.append(helper); effect(helper)
            return result
        with patch.object(RecipientWitnessExchange, 'accept_proof', proof):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'fault must follow valid native channel proof')
        self.assert_retired(entered[0]._lifecycle)

    def test_recipient_death_after_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: helper._child.close())

    def test_revocation_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: self.registry.revoke('app'))

    def test_credential_rotation_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: self.registry.rotate_credential('app'))

    def test_draft_version_change_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: self.ledger.replace(self.draft.draft_id, 1, self.draft.constraint))

    def test_recipient_close_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: helper._lifecycle._recipient.close())

    def test_buffer_mutation_after_live_proof_discards_and_withholds_result(self):
        def mutate(helper): helper._lifecycle._owned_buffer[0] ^= 1
        self.proof_fault(mutate)

    def test_buffer_identity_substitution_after_live_proof_is_rejected(self):
        self.proof_fault(lambda helper: setattr(helper._lifecycle._wire, '_buffer', bytearray(self.DATA)))

    def test_proposal_change_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: object.__setattr__(self.proposal, '_body',
            make_file_read_proposal('changed', max_bytes=128).canonical_bytes()))

    def test_cancellation_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: self.host.close())

    def test_expiry_after_live_proof_discards_and_withholds_result(self):
        self.proof_fault(lambda helper: setattr(self.host, '_deadline', 0))

    def test_native_process_observation_copy_after_proof_is_rejected(self):
        self.proof_fault(lambda helper: setattr(helper, '_native_observation', replace(helper._native_observation)))

    def test_native_process_observation_mutation_after_proof_is_rejected(self):
        self.proof_fault(lambda helper: object.__setattr__(helper._native_observation, 'pid', 1))

    def final_fault(self, effect, *, after=False):
        entered = []; original = LivePublicationDraft._check_publication
        def check(lifecycle, *args):
            helper = self.host._channel_check
            self.assertIs(lifecycle, helper._lifecycle)
            self.assertEqual(bytes(lifecycle._owned_buffer), self.DATA)
            self.assertIsNone(helper._child.poll())
            entered.append(helper)
            if not after: effect(helper)
            result = original(lifecycle, *args)
            if after: effect(helper)
            return result
        with patch.object(LivePublicationDraft, '_check_publication', check):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'fault must reach the one-use final check')
        self.assert_retired(entered[0]._lifecycle)

    def test_recipient_death_at_final_check_entry_is_rejected(self):
        self.final_fault(lambda helper: helper._child.close())

    def test_registry_revocation_at_final_check_entry_is_rejected(self):
        self.final_fault(lambda helper: self.registry.revoke('app'))

    def test_changed_recipient_at_final_check_entry_is_rejected(self):
        self.final_fault(lambda helper: object.__setattr__(helper._lifecycle._recipient_descriptor, 'recipient_id', 'f'*64))

    def test_recipient_death_immediately_after_final_check_is_rejected(self):
        self.final_fault(lambda helper: helper._child.close(), after=True)

    def test_registry_revocation_immediately_after_final_check_is_rejected(self):
        self.final_fault(lambda helper: self.registry.revoke('app'), after=True)

    def test_cancellation_immediately_after_final_check_is_rejected(self):
        self.final_fault(lambda helper: self.host.close(), after=True)

    def cleanup_fault(self, effect):
        original = recipient_process._RecipientWitnessChild.close
        entered = []
        def close(child):
            original(child)
            helper = self.host._channel_check
            self.assertEqual(helper._lifecycle._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(recipient_process._RecipientWitnessChild, 'close', close):
            future, display = self.allowed(); self.reject(future, display)
        self.assertTrue(entered, 'fault must occur in recipient cleanup')
        self.assert_retired(entered[0]._lifecycle)

    def test_revocation_during_recipient_cleanup_withholds_result(self):
        self.cleanup_fault(lambda helper: self.registry.revoke('app'))

    def test_cancellation_during_recipient_cleanup_withholds_result(self):
        self.cleanup_fault(lambda helper: self.host.close())

    def test_uncertain_recipient_cleanup_poisons_admission(self):
        def fail(helper): raise recipient_process.BrokerProcessError('process_cleanup_failed')
        self.cleanup_fault(fail)
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def uncertain_status_fault(self, **options):
        with patch.object(channel.LiveChannelPublicationCheck, 'shutdown_status', **options):
            self.proof_fault(lambda helper: helper.close())
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assertFalse(transport._slot.acquire(blocking=False), 'uncertain status must retain admission')

    def test_helper_shutdown_lookup_failure_is_uncertain_and_retains_admission(self):
        self.uncertain_status_fault(side_effect=OSError('cleanup evidence unavailable'))

    def test_requester_shaped_helper_shutdown_status_is_uncertain_and_retains_admission(self):
        self.uncertain_status_fault(return_value={'cleanup_confirmed': True})

    def test_truthy_non_bool_helper_shutdown_status_is_uncertain_and_retains_admission(self):
        self.uncertain_status_fault(return_value=RecipientChannelShutdownStatus(1))

    def slot_fault(self, effect):
        entered = []; slot = transport._slot; original = slot.release
        def release():
            original()
            helper = self.host._channel_check
            self.assertIsNotNone(helper._proof)
            self.assertIsNotNone(helper._ack)
            self.assertEqual(helper._lifecycle._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(slot, 'release', release):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'fault must follow both native children and final check')
        self.assert_retired(entered[0]._lifecycle)

    def test_revocation_at_final_slot_release_withholds_result(self):
        self.slot_fault(lambda helper: self.registry.revoke('app'))

    def test_helper_identity_substitution_at_slot_release_withholds_result(self):
        self.slot_fault(lambda helper: setattr(self.host, '_channel_check', object()))

    def test_guard_substitution_and_reinserted_bytes_still_wipe_original_quarantine(self):
        foreign = Mock()
        def change(helper):
            helper._lifecycle._owned_buffer.extend(self.DATA)
            self.host._channel_check = foreign
        self.slot_fault(change)
        foreign.close.assert_not_called()
        foreign.retired_check.assert_not_called()

    def final_evidence_hook_fault(self, effect):
        original = host.BrokerLiveChannelPublicationHost._post_check_evidence
        entered = []
        def post_check(owner):
            original(owner)
            helper = owner._channel_check
            self.assertIsNotNone(helper._proof, 'late hook must follow valid native proof')
            self.assertIsNotNone(helper._ack, 'late hook must follow confirmed native cleanup ACK')
            self.assertEqual(helper._lifecycle._owned_buffer, bytearray())
            entered.append(helper); effect(helper)
        with patch.object(host.BrokerLiveChannelPublicationHost, '_post_check_evidence', post_check):
            future, display = self.allowed(); self.reject(future, display)
        self.assertEqual(len(entered), 1, 'late fault must follow successful delegated native validation')
        self.assert_retired(entered[0]._lifecycle)

    def test_registry_revocation_after_delegated_final_native_validation_is_rejected(self):
        self.final_evidence_hook_fault(lambda helper: self.registry.revoke('app'))

    def test_bytes_reinserted_after_delegated_final_native_validation_are_wiped(self):
        self.final_evidence_hook_fault(lambda helper: helper._lifecycle._owned_buffer.extend(self.DATA))

    def test_native_cleanup_state_mutation_at_slot_release_poisons_admission(self):
        self.slot_fault(lambda helper: setattr(helper._issued_child, '_cleanup_failed', True))
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def test_stale_native_observation_at_slot_release_withholds_result(self):
        self.slot_fault(lambda helper: object.__setattr__(helper._native_observation, 'creation_time', 1))

    def test_recipient_substitution_at_slot_release_withholds_result(self):
        self.slot_fault(lambda helper: setattr(helper._lifecycle._recipient, '_descriptor',
            replace(helper._lifecycle._recipient_descriptor)))

    def recipient_helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'recipient-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_recipient_entry as entry\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(recipient_process._RecipientWitnessChild, '_entry_path', return_value=path)

    def test_recipient_valid_ack_then_trailing_output_is_rejected(self):
        with self.recipient_helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"):
            future, display = self.allowed(); self.reject(future, display)

    def test_recipient_valid_ack_then_nonzero_exit_is_rejected(self):
        with self.recipient_helper(ending='os._exit(9)'):
            future, display = self.allowed(); self.reject(future, display)

    def test_recipient_hang_is_interrupted_by_cancellation_and_discards(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        marker = Path(directory.name)/'recipient-entered.txt'
        prefix = 'from pathlib import Path\nPath('+repr(str(marker))+').write_text("entered")\ntime.sleep(30)'
        with self.recipient_helper(prefix=prefix):
            future, display = self.allowed()
            deadline = time.monotonic()+2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.002)
            self.assertTrue(marker.exists(), 'recipient must start before cancellation')
            helper = self.host._channel_check
            self.assertEqual(bytes(helper._lifecycle._owned_buffer), self.DATA)
            self.host.close(); self.reject(future, display)
        self.assert_retired(helper._lifecycle)
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)


if __name__ == '__main__': unittest.main()
