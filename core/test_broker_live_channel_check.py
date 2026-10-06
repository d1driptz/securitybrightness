"""Real fixed-peer witness with synthetic resource evidence; inactive zero-byte check."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from core import broker_live_channel_check as channel
from core import broker_recipient_process as process
from core import broker_transport as transport
from core import test_broker_publication_lifecycle as helpers
from core.broker_protocol import _canonical
from core.broker_publication_lifecycle import FinalPublicationDraftCheck, PublicationLifecycleError
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.file_read_schema import make_file_read_proposal


class LiveChannelPublicationCheckTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'
    install = helpers.LivePublicationDraftTests.install
    begin = helpers.LivePublicationDraftTests.begin
    observe = helpers.LivePublicationDraftTests.observe
    review = helpers.LivePublicationDraftTests.review
    reserve = helpers.LivePublicationDraftTests.reserve
    start = helpers.LivePublicationDraftTests.start
    stage = helpers.LivePublicationDraftTests.stage
    retirement = helpers.LivePublicationDraftTests.retirement

    def setUp(self):
        helpers.LivePublicationDraftTests.setUp(self)
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.addCleanup(self.pool.shutdown, wait=True)
        self.check = None

    def prepare(self, **options):
        self.retirement()
        self.retained = self.lifecycle._owned_buffer
        self.check = channel.LiveChannelPublicationCheck(self.lifecycle, **options)
        self.addCleanup(self.check.close)
        return self.check

    def run_check(self, **overrides):
        if self.check is None: self.prepare()
        values = dict(app='app', credential=self.credential, proposal=self.proposal, descriptor=self.descriptor)
        values.update(overrides)
        return self.check.run(values['app'], values['credential'], values['proposal'], values['descriptor'])

    def terminal(self):
        self.assertEqual(self.model._state, 'closed')
        self.assertEqual(self.recipient._state, 'closed')
        self.assertIs(self.recipient._terminal, True)
        self.assertIsNone(self.recipient._claim)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        if hasattr(self, 'retained'): self.assertEqual(self.retained, bytearray())

    def reject(self, operation):
        with self.assertRaises(channel.LiveChannelCheckError): operation()
        self.terminal()

    def helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'fixed-channel-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_recipient_entry as entry\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(process._RecipientWitnessChild, '_entry_path', return_value=path)

    def require_proof(self):
        self.assertIsNotNone(self.check._proof, 'late test must follow a valid real child proof')
        self.assertEqual(self.check._proof.outcome, 'witnessed')

    def proof_fault(self, action):
        self.prepare(); original = RecipientWitnessExchange.accept_proof; reached = []
        def proof(wire, frame):
            result = original(wire, frame); reached.append(True); action(); return result
        with patch.object(RecipientWitnessExchange, 'accept_proof', proof): self.reject(self.run_check)
        self.assertEqual(reached, [True])

    def final_fault(self, action, *, after=False):
        self.prepare(); original = self.lifecycle.coordinator.check_publication; reached = []
        def final(*args, **kwargs):
            self.require_proof(); reached.append(True)
            if not after: action()
            result = original(*args, **kwargs)
            if after: action()
            return result
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final):
            self.reject(self.run_check)
        self.assertEqual(reached, [True])

    def terminate_child(self):
        child = self.check._child
        child._ownership.check(child._ownership.k.TerminateProcess(child._owned[4], 7))
        deadline = time.monotonic()+1
        while child.poll() is None and time.monotonic() < deadline: time.sleep(.002)
        self.assertEqual(child.poll(), 7)

    def test_real_live_peer_is_checked_while_quarantine_is_retained_then_dry_run_discards(self):
        self.prepare(); original = self.lifecycle.coordinator.check_publication; reached = []
        def final(*args, **kwargs):
            self.require_proof(); self.check._child._validate()
            self.assertEqual(bytes(self.retained), self.DATA)
            self.assertEqual(self.lifecycle._wire._state, 'retired_for_check')
            reached.append(True); result = original(*args, **kwargs)
            self.assertEqual(self.retained, bytearray())
            self.check._child._validate()
            return result
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final): result = self.run_check()
        self.assertEqual(reached, [True])
        self.assertIs(type(result), FinalPublicationDraftCheck)
        self.assertEqual((result.disposition, result.released_bytes, result.staged_bytes), ('eligible_discarded', 0, 37))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(result.recipient_digest, hashlib.sha256(_canonical(asdict(self.descriptor))).hexdigest())
        self.assertNotIn('data', asdict(result))
        with self.assertRaises(TypeError): bool(result)
        self.assertIs(self.check._finished, True)
        self.assertIs(self.check._cleanup_confirmed, True)
        self.assertIsNone(self.check.retired_check())
        self.terminal()

    def test_descriptor_copy_burns_first_attempt_and_wipes_quarantine(self):
        self.prepare(); self.reject(lambda: self.run_check(descriptor=replace(self.descriptor)))
        self.reject(self.run_check)

    def test_requester_descriptor_mapping_cannot_become_a_live_channel(self):
        self.prepare(); self.reject(lambda: self.run_check(descriptor=asdict(self.descriptor)))

    def test_wrong_credential_is_spent_without_child_launch(self):
        self.prepare()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_check(credential='wrong')); launch.assert_not_called()
        self.reject(self.run_check)

    def test_oversized_or_non_string_credential_is_spent(self):
        self.prepare(); self.reject(lambda: self.run_check(credential='x'*513))

    def test_boolean_credential_is_not_human_or_application_permission(self):
        self.prepare(); self.reject(lambda: self.run_check(credential=True))

    def test_equal_application_subclass_cannot_create_a_channel(self):
        class Application(str): pass
        self.prepare(); self.reject(lambda: self.run_check(app=Application('app')))

    def test_wrong_application_cannot_transfer_review_or_recipient(self):
        self.prepare(); credential = self.registry.register('other', ['files.read'])
        self.reject(lambda: self.run_check(app='other', credential=credential))

    def test_changed_request_or_effect_cannot_inherit_existing_review(self):
        self.prepare()
        self.reject(lambda: self.run_check(proposal=make_file_read_proposal('changed resource', max_bytes=4096)))

    def test_descriptor_revision_mutation_is_terminal(self):
        self.prepare(); object.__setattr__(self.descriptor, 'recipient_revision', 2)
        self.reject(self.run_check)

    def test_descriptor_identity_mutation_is_terminal(self):
        self.prepare(); object.__setattr__(self.descriptor, 'recipient_id', 'f'*64)
        self.reject(self.run_check)

    def test_closed_recipient_cannot_be_restored_by_channel_proof(self):
        self.prepare(); self.recipient.close(); self.reject(self.run_check)

    def test_revoked_authority_before_start_cannot_launch_peer(self):
        self.prepare(); self.registry.revoke('app')
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(self.run_check); launch.assert_not_called()

    def test_stale_credential_before_start_cannot_launch_peer(self):
        self.prepare(); self.registry.rotate_credential('app'); self.reject(self.run_check)

    def test_stale_draft_before_start_cannot_launch_peer(self):
        self.prepare(); self.ledger.replace(self.draft.draft_id, 1, self.constraint); self.reject(self.run_check)

    def test_superseding_review_before_start_cannot_launch_peer(self):
        self.prepare(); self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)
        self.reject(self.run_check)

    def test_private_quarantine_mutation_before_start_is_rejected_and_wiped(self):
        self.prepare(); self.retained[0] ^= 1; self.reject(self.run_check)

    def test_helper_binding_mutation_cannot_substitute_actual_source_evidence(self):
        self.prepare()
        from core.json_input import loads
        binding = loads(self.check._binding_snapshot); binding['context']['file_id'] = 'f'*32
        self.check._binding_snapshot = _canonical(binding)
        self.reject(self.run_check)

    def test_equal_buffer_copy_cannot_replace_owned_quarantine(self):
        self.prepare(); self.lifecycle._wire._buffer = bytearray(self.DATA); self.reject(self.run_check)

    def test_retirement_receipt_copy_cannot_replace_original_evidence(self):
        self.prepare(); self.lifecycle._retirement = replace(self.lifecycle._retirement); self.reject(self.run_check)

    def test_summary_copy_cannot_replace_original_evidence(self):
        self.prepare(); self.lifecycle._summary = replace(self.lifecycle._summary); self.reject(self.run_check)

    def test_source_deadline_extension_before_start_is_rejected(self):
        self.prepare(); self.model._deadline += 60; self.reject(self.run_check)

    def test_quarantine_deadline_extension_before_start_is_rejected(self):
        self.prepare(); self.lifecycle._wire._deadline += 60; self.reject(self.run_check)

    def test_recipient_deadline_extension_before_start_is_rejected(self):
        self.prepare(); self.recipient._deadline += 60; self.reject(self.run_check)

    def test_helper_deadline_extension_is_rejected(self):
        self.prepare(); self.check._deadline += 60; self.reject(self.run_check)

    def test_helper_expiry_is_terminal(self):
        self.prepare(); self.check._deadline = 0; self.reject(self.run_check)

    def test_cancel_before_start_wipes_quarantine_without_launch(self):
        self.prepare(); self.check.close()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(self.run_check); launch.assert_not_called()

    def test_enclosing_host_retains_admission_ownership_through_helper_cleanup(self):
        self.prepare(); transport._slot.acquire()
        result = self.run_check()
        self.assertEqual(result.released_bytes, 0)
        self.assertFalse(transport._slot.acquire(blocking=False))
        transport._slot.release()

    def test_launch_failure_closes_source_and_confirms_cleanup(self):
        self.prepare()
        with patch.object(channel, '_RecipientWitnessChild', side_effect=process.BrokerProcessError('launch_failed')):
            self.reject(self.run_check)
        self.assertIs(self.check._cleanup_confirmed, True)

    def test_uncertain_launch_cleanup_is_reported_to_enclosing_host(self):
        self.prepare()
        with patch.object(channel, '_RecipientWitnessChild', side_effect=process.BrokerProcessError('process_cleanup_failed')):
            self.reject(self.run_check)
        self.assertIs(self.check._cleanup_confirmed, False)

    def test_revocation_after_genuine_proof_withholds_result(self):
        self.proof_fault(lambda: self.registry.revoke('app'))

    def test_rotation_after_genuine_proof_withholds_result(self):
        self.proof_fault(lambda: self.registry.rotate_credential('app'))

    def test_scope_removal_after_genuine_proof_withholds_result(self):
        self.proof_fault(lambda: self.registry.update_permissions('app', scopes=[]))

    def test_draft_change_after_genuine_proof_withholds_result(self):
        self.proof_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))

    def test_cancellation_after_genuine_proof_withholds_result(self):
        self.proof_fault(lambda: self.check.close())

    def test_proof_mutation_cannot_be_sealed_as_trusted(self):
        self.prepare(); original = RecipientWitnessExchange.accept_proof
        def proof(wire, frame):
            result = original(wire, frame); object.__setattr__(result, 'binding_digest', 'f'*64); return result
        with patch.object(RecipientWitnessExchange, 'accept_proof', proof): self.reject(self.run_check)

    def test_native_observation_mutation_after_proof_cannot_claim_another_peer(self):
        self.proof_fault(lambda: object.__setattr__(self.check._native_observation, 'pid', 1))

    def test_native_observation_copy_after_proof_cannot_replace_original_owner(self):
        self.proof_fault(lambda: setattr(self.check, '_native_observation', replace(self.check._native_observation)))

    def test_requester_wire_replacement_after_proof_is_terminal(self):
        self.proof_fault(lambda: setattr(self.check, '_wire', {'approved': True}))

    def native_fault(self, action):
        self.prepare(); original = process._RecipientWitnessChild._validate; reached = []
        def validate(child, **kwargs):
            result = original(child, **kwargs)
            if self.check._proof is not None and not reached:
                self.require_proof(); reached.append(True); action()
            return result
        with patch.object(process._RecipientWitnessChild, '_validate', validate): self.reject(self.run_check)
        self.assertEqual(reached, [True], 'race must execute during a post-proof native query')

    def test_revocation_during_post_proof_native_query_is_rechecked(self):
        self.native_fault(lambda: self.registry.revoke('app'))

    def test_buffer_mutation_during_post_proof_native_query_is_rechecked_and_wiped(self):
        self.native_fault(lambda: self.retained.extend(b'x'))

    def test_child_death_before_final_check_is_rejected(self):
        self.final_fault(self.terminate_child)

    def test_child_death_during_original_final_cleanup_is_rejected(self):
        self.prepare(); original = self.model._reviews.discard_review; reached = []
        def discard(ticket):
            original(ticket)
            if not reached:
                self.require_proof(); reached.append(True); self.terminate_child()
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard): self.reject(self.run_check)
        self.assertEqual(reached, [True])

    def test_child_death_after_original_final_check_is_rejected(self):
        self.final_fault(self.terminate_child, after=True)

    def test_revocation_after_original_final_check_withholds_result(self):
        self.final_fault(lambda: self.registry.revoke('app'), after=True)

    def test_rotation_after_original_final_check_withholds_result(self):
        self.final_fault(lambda: self.registry.rotate_credential('app'), after=True)

    def test_cancel_after_original_final_check_withholds_result(self):
        self.final_fault(lambda: self.check.close(), after=True)

    def test_reintroduced_buffer_after_original_dry_run_is_rejected_and_wiped(self):
        self.final_fault(lambda: self.retained.extend(self.DATA), after=True)

    def test_descriptor_mutation_after_original_dry_run_is_rejected(self):
        self.final_fault(lambda: object.__setattr__(self.descriptor, 'recipient_session', 'f'*64), after=True)

    def test_source_decision_change_after_original_dry_run_is_rejected(self):
        self.final_fault(lambda: setattr(self.model, '_decision', 'deny'), after=True)

    def test_recipient_state_rollback_after_original_dry_run_is_rejected(self):
        self.final_fault(lambda: setattr(self.recipient, '_state', 'bound'), after=True)

    def test_original_final_result_false_release_cannot_escape(self):
        self.prepare(); original = self.lifecycle.coordinator.check_publication
        def final(*args, **kwargs):
            self.require_proof(); result = original(*args, **kwargs)
            object.__setattr__(result, 'released_bytes', 1); return result
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final): self.reject(self.run_check)

    def test_original_final_result_copy_cannot_inflate_metadata(self):
        self.prepare(); original = self.lifecycle.coordinator.check_publication
        def final(*args, **kwargs):
            self.require_proof(); result = original(*args, **kwargs)
            return replace(result, staged_bytes=38)
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final): self.reject(self.run_check)

    def test_valid_metadata_ack_followed_by_nonzero_child_exit_is_rejected(self):
        self.prepare()
        with self.helper(ending='os._exit(9)'): self.reject(self.run_check)

    def test_native_cleanup_uncertainty_withholds_result_for_enclosing_host(self):
        self.prepare(); original = process._RecipientWitnessChild.close; reached = []
        def close(child):
            original(child); self.require_proof()
            self.assertEqual(self.retained, bytearray())
            reached.append(True)
            raise process.BrokerProcessError('process_cleanup_failed')
        with patch.object(process._RecipientWitnessChild, 'close', close): self.reject(self.run_check)
        self.assertTrue(reached)
        self.assertIs(self.check._cleanup_confirmed, False)

    def test_source_cleanup_failure_still_wipes_quarantine_and_withholds_result(self):
        self.prepare(); original = self.recipient.close; reached = []
        def close():
            original(); self.require_proof(); reached.append(True)
            raise OSError('source cleanup uncertain')
        with patch.object(self.recipient, 'close', side_effect=close): self.reject(self.run_check)
        self.assertTrue(reached)

    def test_valid_metadata_ack_followed_by_trailing_output_is_rejected(self):
        self.prepare()
        with self.helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"): self.reject(self.run_check)

    def test_valid_metadata_ack_followed_by_hang_is_bounded(self):
        self.prepare(timeout=1)
        with self.helper(ending='time.sleep(30)'): self.reject(self.run_check)

    def test_startup_hang_is_bounded_and_cleanup_confirmed(self):
        self.prepare(timeout=1)
        with self.helper(prefix='time.sleep(30)'): self.reject(self.run_check)
        self.assertIs(self.check._cleanup_confirmed, True)

    def test_forged_startup_cannot_become_a_current_channel(self):
        self.prepare()
        with self.helper(prefix="sys.stdout.buffer.write(b'x'*32);sys.stdout.buffer.flush();os._exit(0)"):
            self.reject(self.run_check)

    def test_cancel_blocked_worker_joins_child_before_confirming_cleanup(self):
        self.prepare()
        with self.helper(prefix='time.sleep(30)'):
            future = self.pool.submit(self.run_check)
            deadline = time.monotonic()+2
            while not self.check._started and time.monotonic() < deadline: time.sleep(.002)
            self.assertIs(self.check._started, True)
            self.check.close()
            with self.assertRaises(channel.LiveChannelCheckError): future.result(timeout=3)
        self.assertIs(self.check._finished, True)
        self.assertIs(self.check._cleanup_confirmed, True)
        self.terminal()

    def test_duplicate_worker_cancels_original_one_use_attempt(self):
        self.prepare()
        with self.helper(prefix='time.sleep(30)'):
            future = self.pool.submit(self.run_check)
            deadline = time.monotonic()+2
            while not self.check._started and time.monotonic() < deadline: time.sleep(.002)
            with self.assertRaises(channel.LiveChannelCheckError): self.run_check()
            with self.assertRaises(channel.LiveChannelCheckError): future.result(timeout=3)
        self.terminal()

    def test_success_cannot_be_replayed_or_turned_into_delivery_permission(self):
        result = self.run_check(); self.assertEqual(result.released_bytes, 0)
        self.reject(self.run_check)
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()

    def test_retired_check_detects_post_return_mutation_without_restoring_authority(self):
        self.run_check(); self.check._ack = replace(self.check._ack)
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.terminal()

    def test_original_sources_remain_closed_if_retired_state_is_rolled_back(self):
        self.run_check(); self.lifecycle._state = 'cleaned'; self.recipient._state = 'bound'
        with self.assertRaises(channel.LiveChannelCheckError): self.run_check()
        self.assertIs(self.lifecycle._publication_attempted, True)
        self.assertIs(self.recipient._terminal, True)
        self.assertIsNone(self.recipient._claim)
        self.assertEqual(self.retained, bytearray())
        # The original one-use model also rejects its own state rollback and
        # performs terminal disposal. Retired metadata never restores permission.
        with self.assertRaises(PublicationLifecycleError):
            self.lifecycle.coordinator.check_publication('app', self.credential, self.proposal, self.descriptor)
        self.terminal()

    def test_helper_exposes_no_byte_acquisition_or_delivery_port(self):
        self.prepare()
        for name in ('reserve', 'read', 'stage', 'acquire', 'publish', 'release', 'deliver', 'data'):
            self.assertFalse(hasattr(self.check, name))

    def test_constructor_requires_exact_live_retained_quarantine_owner(self):
        for value in (self.lifecycle.coordinator, self.descriptor, {'approved': True}):
            with self.subTest(value=type(value)), self.assertRaises(TypeError): channel.LiveChannelPublicationCheck(value)


if __name__ == '__main__': unittest.main()
