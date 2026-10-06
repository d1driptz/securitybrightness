"""Inactive native recipient-channel witness tests; no protected byte delivery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_recipient_channel as channel
from core import broker_recipient_process as process
from core import broker_transport as transport
from core import test_broker_live_review as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_protocol import _canonical
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.broker_publication_recipient import LogicalPublicationRecipient
from core.file_read_schema import make_file_read_proposal


class RecipientChannelTests(unittest.TestCase):
    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.addCleanup(self.pool.shutdown, wait=True)
        self.install()

    def install(self, recipient_app='app', timeout=5):
        self.acquisition = AcquisitionDraft(self.model)
        self.recipient = LogicalPublicationRecipient(recipient_app)
        self.addCleanup(self.recipient.close)
        self.descriptor = self.recipient.descriptor
        self.probe = channel.RecipientChannelProbe(self.acquisition, self.recipient, timeout=timeout)
        self.addCleanup(self.probe.close)

    def fresh(self, timeout=5):
        self.probe.close()
        helpers.LiveReviewMappingTests.setUp(self)
        self.install(timeout=timeout)

    begin = helpers.LiveReviewMappingTests.begin
    observe = helpers.LiveReviewMappingTests.observe
    review = helpers.LiveReviewMappingTests.review

    def reserve(self):
        self.review()
        return self.probe.coordinator.reserve()

    def run_probe(self, token=None, **overrides):
        token = self.reserve() if token is None else token
        values = dict(app='app', credential=self.credential, proposal=self.proposal)
        values.update(overrides)
        return self.probe.worker.run(token, **values)

    def terminal(self):
        self.assertEqual(self.model._state, 'closed')
        self.assertTrue(self.recipient._terminal)
        self.assertEqual(self.recipient._state, 'closed')
        self.assertIsNone(self.recipient._claim)

    def reject(self, operation):
        with self.assertRaises(channel.RecipientChannelError): operation()
        self.terminal()

    def helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'witness-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_recipient_entry as entry\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(process._RecipientWitnessChild, '_entry_path', return_value=path)

    def test_real_channel_returns_only_terminal_zero_release_metadata(self):
        original = self.registry.get('app')
        result = self.run_probe()
        self.assertIs(type(result), channel.RetiredRecipientChannelWitness)
        self.assertEqual((result.lifecycle, result.released_bytes), ('retired', 0))
        self.assertIs(type(result.process_id), int)
        self.assertGreater(result.process_id, 0)
        self.assertIs(type(result.process_creation_time), int)
        self.assertGreater(result.process_creation_time, 0)
        self.assertEqual(result.recipient_digest, hashlib.sha256(_canonical(asdict(self.descriptor))).hexdigest())
        self.assertEqual(result.binding_digest, hashlib.sha256(self.probe._binding_snapshot).hexdigest())
        for name in ('data', 'token', 'frame', 'approval', 'permission'):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(TypeError): bool(result)
        self.assertNotIn(self.credential, repr(result))
        self.assertIs(self.registry.get('app'), original)
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)
        self.terminal()

    def test_operator_and_worker_capabilities_remain_separate(self):
        for name in ('record', 'display', 'run'):
            self.assertFalse(hasattr(self.probe.coordinator, name))
        for name in ('reserve', 'record', 'display'):
            self.assertFalse(hasattr(self.probe.worker, name))
        for name in ('stage', 'publish', 'release', 'read', 'deliver'):
            self.assertFalse(hasattr(self.probe, name))
            self.assertFalse(hasattr(self.probe.worker, name))

    def test_application_authority_without_human_review_cannot_reserve(self):
        self.observe()
        self.reject(self.probe.coordinator.reserve)

    def test_human_denial_cannot_reserve_or_launch(self):
        self.review('DENY')
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(self.probe.coordinator.reserve)
            launch.assert_not_called()

    def test_review_evidence_cannot_restore_revoked_application(self):
        self.review(); self.registry.revoke('app')
        self.reject(self.probe.coordinator.reserve)

    def test_review_evidence_cannot_survive_credential_rotation(self):
        self.review(); self.registry.rotate_credential('app')
        self.reject(self.probe.coordinator.reserve)

    def test_review_evidence_cannot_survive_scope_removal(self):
        self.review(); self.registry.update_permissions('app', scopes=[])
        self.reject(self.probe.coordinator.reserve)

    def test_review_evidence_cannot_survive_draft_version_change(self):
        self.review(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.reject(self.probe.coordinator.reserve)

    def test_wrong_recipient_application_cannot_claim_review(self):
        self.probe.close()
        helpers.LiveReviewMappingTests.setUp(self)
        self.install(recipient_app='other')
        self.review()
        self.reject(self.probe.coordinator.reserve)

    def test_bad_credential_is_spent_without_launch(self):
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, credential='wrong'))
            launch.assert_not_called()
        self.reject(lambda: self.run_probe(token))

    def test_wrong_application_cannot_transfer_recipient_or_review(self):
        token = self.reserve()
        credential = self.registry.register('other', ['files.read'])
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, app='other', credential=credential))
            launch.assert_not_called()

    def test_copied_reservation_is_not_the_live_issued_capability(self):
        token = self.reserve()
        self.reject(lambda: self.run_probe(replace(token)))

    def test_mutated_reservation_cannot_change_resource(self):
        token = self.reserve()
        object.__setattr__(token, 'canonical_context', token.canonical_context.replace(b'untrusted label', b'changed label'))
        # Mutate a binding field even when the descriptive label is absent.
        object.__setattr__(token, 'display_digest', 'f'*64)
        self.reject(lambda: self.run_probe(token))

    def test_malformed_reservation_is_spent(self):
        self.reserve()
        self.reject(lambda: self.run_probe({'reservation': 'requester-controlled'}))

    def test_changed_proposal_cannot_use_existing_reservation(self):
        token = self.reserve()
        proposal = make_file_read_proposal('changed request', max_bytes=128)
        self.reject(lambda: self.run_probe(token, proposal=proposal))

    def test_changed_effect_cannot_use_existing_reservation(self):
        token = self.reserve()
        self.reject(lambda: self.run_probe(token, proposal=make_file_read_proposal('untrusted label', max_bytes=127)))

    def test_revocation_after_reserve_prevents_launch(self):
        token = self.reserve(); self.registry.revoke('app')
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token)); launch.assert_not_called()

    def test_rotation_after_reserve_prevents_launch(self):
        token = self.reserve(); self.registry.rotate_credential('app')
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token)); launch.assert_not_called()

    def test_revoked_recipient_cannot_be_reused(self):
        token = self.reserve(); self.recipient.close()
        self.reject(lambda: self.run_probe(token))

    def test_recipient_descriptor_mutation_fails_closed(self):
        token = self.reserve(); object.__setattr__(self.descriptor, 'recipient_id', 'f'*64)
        self.reject(lambda: self.run_probe(token))

    def test_equal_copied_recipient_owner_descriptor_fails_closed(self):
        token = self.reserve(); self.recipient._descriptor = replace(self.descriptor)
        self.reject(lambda: self.run_probe(token))

    def test_success_cannot_be_replayed(self):
        token = self.reserve(); self.run_probe(token)
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token)); launch.assert_not_called()

    def test_duplicate_reservation_burns_current_attempt(self):
        token = self.reserve()
        self.reject(self.probe.coordinator.reserve)
        self.reject(lambda: self.run_probe(token))

    def test_cancel_before_launch_is_terminal_and_confirmed(self):
        token = self.reserve(); self.probe.close()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token)); launch.assert_not_called()
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_expiry_before_launch_fails_closed(self):
        token = self.reserve(); self.probe._deadline = 0
        self.reject(lambda: self.run_probe(token))

    def test_shared_slot_prevents_launch(self):
        token = self.reserve(); transport._slot.acquire()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token)); launch.assert_not_called()

    def test_launch_failure_closes_owners_and_releases_slot(self):
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild', side_effect=process.BrokerProcessError('launch_failed')):
            self.reject(lambda: self.run_probe(token))
        self.assertTrue(transport._slot.acquire(blocking=False)); transport._slot.release()
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_uncertain_launch_cleanup_poisons_slot(self):
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild', side_effect=process.BrokerProcessError('process_cleanup_failed')):
            self.reject(lambda: self.run_probe(token))
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.probe.shutdown_status().cleanup_confirmed)

    def cleanup_fault(self, effect):
        original = process._RecipientWitnessChild.close
        entered = []
        def close(child):
            original(child)
            self.assertIsNotNone(self.probe._proof, 'race must follow a valid proof')
            entered.append(True); effect()
        with patch.object(process._RecipientWitnessChild, 'close', close):
            self.reject(self.run_probe)
        self.assertTrue(entered, 'race must execute in native cleanup')

    def test_revocation_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(lambda: self.registry.revoke('app'))

    def test_rotation_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(lambda: self.registry.rotate_credential('app'))

    def test_draft_replacement_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))

    def test_recipient_revocation_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(self.recipient.close)

    def test_cancellation_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(self.probe.close)

    def test_expiry_during_child_cleanup_withholds_witness(self):
        self.cleanup_fault(lambda: setattr(self.probe, '_deadline', 0))

    def test_registry_lookup_failure_after_child_cleanup_withholds_witness(self):
        self.cleanup_fault(self.registry.close)

    def test_process_cleanup_uncertainty_poisons_slot(self):
        def fail(): raise process.BrokerProcessError('process_cleanup_failed')
        self.cleanup_fault(fail)
        self.assertFalse(transport._slot.acquire(blocking=False))
        self.assertFalse(self.probe.shutdown_status().cleanup_confirmed)

    def slot_fault(self, effect):
        slot = transport._slot; original = slot.release
        entered = []
        def release():
            original()
            self.assertIsNotNone(self.probe._proof, 'race must follow a valid proof')
            self.assertIsNotNone(self.probe._ack, 'race must follow confirmed child cleanup')
            entered.append(True); effect()
        with patch.object(slot, 'release', release): self.reject(self.run_probe)
        self.assertEqual(entered, [True], 'race must execute at the final slot release')

    def test_revocation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: self.registry.revoke('app'))

    def test_cancel_at_slot_release_withholds_witness(self):
        self.slot_fault(self.probe.close)

    def test_recipient_substitution_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.recipient, '_descriptor', replace(self.descriptor)))

    def test_decision_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.model, '_decision', 'deny'))

    def test_ticket_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: object.__setattr__(self.model._ticket.review, 'proposal_id', 'sbp2_sha256_'+'f'*64))

    def test_slot_release_failure_reports_finished_uncertain_cleanup(self):
        with patch.object(transport._slot, 'release', side_effect=ValueError('release failed')):
            self.reject(self.run_probe)
        self.assertIsNotNone(self.probe.shutdown_status())
        self.assertFalse(self.probe.shutdown_status().cleanup_confirmed)

    def test_valid_ack_then_nonzero_exit_is_rejected(self):
        with self.helper(ending='os._exit(9)'): self.reject(self.run_probe)

    def test_valid_ack_then_trailing_output_is_rejected(self):
        with self.helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"): self.reject(self.run_probe)

    def test_valid_ack_then_hang_is_bounded(self):
        self.fresh(timeout=1)
        token = self.reserve()
        with self.helper(ending='time.sleep(30)'): self.reject(lambda: self.run_probe(token))

    def test_startup_hang_is_bounded_and_cleanup_confirmed(self):
        self.fresh(timeout=1)
        token = self.reserve()
        with self.helper(prefix='time.sleep(30)'): self.reject(lambda: self.run_probe(token))
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_cancel_blocked_child_joins_before_confirming_cleanup(self):
        token = self.reserve()
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        marker = Path(directory.name)/'child-entered.txt'
        prefix = 'from pathlib import Path\nPath('+repr(str(marker))+').write_text("entered")\ntime.sleep(30)'
        with self.helper(prefix=prefix):
            future = self.pool.submit(self.run_probe, token)
            deadline = time.monotonic()+2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.002)
            self.assertTrue(marker.exists(), 'child must enter the blocked bootstrap')
            self.assertIsNotNone(self.probe._issued_child)
            self.assertIsNone(self.probe.shutdown_status())
            self.probe.close()
            with self.assertRaises(channel.RecipientChannelError): future.result(timeout=3)
        self.terminal()
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_forged_startup_never_becomes_native_witness(self):
        with self.helper(prefix="sys.stdout.buffer.write(b'x'*32);sys.stdout.buffer.flush();os._exit(0)"):
            self.reject(self.run_probe)

    def proof_fault(self, effect):
        original = RecipientWitnessExchange.accept_proof
        entered = []
        def proof(wire, frame):
            result = original(wire, frame); entered.append(True); effect(); return result
        with patch.object(RecipientWitnessExchange, 'accept_proof', proof): self.reject(self.run_probe)
        self.assertEqual(entered, [True], 'race must occur after a valid child proof')

    def test_revocation_after_proof_withholds_witness(self):
        self.proof_fault(lambda: self.registry.revoke('app'))

    def test_credential_rotation_after_proof_withholds_witness(self):
        self.proof_fault(lambda: self.registry.rotate_credential('app'))

    def test_scope_removal_after_proof_withholds_witness(self):
        self.proof_fault(lambda: self.registry.update_permissions('app', scopes=[]))

    def test_draft_version_change_after_proof_withholds_witness(self):
        self.proof_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))

    def test_recipient_revocation_after_proof_withholds_witness(self):
        self.proof_fault(self.recipient.close)

    def test_proposal_mutation_after_proof_withholds_witness(self):
        self.proof_fault(lambda: object.__setattr__(self.proposal, '_body',
            make_file_read_proposal('changed', max_bytes=128).canonical_bytes()))

    def test_cancel_after_proof_withholds_witness(self):
        self.proof_fault(self.probe.close)

    def test_expiry_after_proof_withholds_witness(self):
        self.proof_fault(lambda: setattr(self.probe, '_deadline', 0))

    def test_native_observation_mutation_after_proof_fails_closed(self):
        self.proof_fault(lambda: object.__setattr__(self.probe._native_observation, 'pid', 1))

    def test_native_observation_copy_after_proof_fails_closed(self):
        self.proof_fault(lambda: setattr(self.probe, '_native_observation', replace(self.probe._native_observation)))

    def test_native_observation_type_confusion_after_proof_fails_closed(self):
        self.proof_fault(lambda: object.__setattr__(self.probe._native_observation, 'pid', True))

    def test_closed_pipe_after_proof_fails_closed(self):
        self.proof_fault(lambda: self.probe._child.close_input())

    def test_native_observation_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: object.__setattr__(self.probe._native_observation, 'creation_time', 1))

    def test_copied_native_observation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.probe, '_native_observation', replace(self.probe._native_observation)))

    def test_recipient_deadline_extension_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.recipient, '_deadline', self.recipient._deadline+1000))

    def test_source_deadline_extension_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.model, '_deadline', self.model._deadline+1000))

    def test_equal_valued_decision_subclass_at_slot_release_withholds_witness(self):
        class Decision(str): pass
        self.slot_fault(lambda: setattr(self.model, '_decision', Decision('allow_once')))

    def test_equal_display_copy_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.model, '_shown', replace(self.model._shown)))

    def test_wire_substitution_after_proof_fails_closed(self):
        self.proof_fault(lambda: setattr(self.probe, '_wire', object()))

    def test_duplicate_worker_cancels_and_joins_original(self):
        token = self.reserve()
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        marker = Path(directory.name)/'child-entered.txt'
        prefix = 'from pathlib import Path\nPath('+repr(str(marker))+').write_text("entered")\ntime.sleep(30)'
        with self.helper(prefix=prefix):
            future = self.pool.submit(self.run_probe, token)
            deadline = time.monotonic()+2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.002)
            self.assertTrue(marker.exists(), 'original child must be active before duplicate run')
            self.assertIsNotNone(self.probe._issued_child)
            with self.assertRaises(channel.RecipientChannelError): self.run_probe(token)
            with self.assertRaises(channel.RecipientChannelError): future.result(timeout=3)
        self.terminal()

    def test_public_result_mutation_cannot_report_false_release(self):
        original = channel.RetiredRecipientChannelWitness
        # Preserve the class used by exact-type checks while changing initialization.
        original_init = original.__init__
        def initialize(value, *args, **kwargs):
            original_init(value, *args, **kwargs); object.__setattr__(value, 'released_bytes', 1)
        with patch.object(original, '__init__', initialize): self.reject(self.run_probe)

    def test_copied_native_observation_cannot_be_sealed_as_trusted(self):
        original = process._RecipientWitnessChild._observe
        def observe(child): return replace(original(child))
        with patch.object(process._RecipientWitnessChild, '_observe', observe): self.reject(self.run_probe)

    def test_fabricated_native_observation_cannot_be_sealed_as_trusted(self):
        original = process._RecipientWitnessChild._observe
        def observe(child):
            value = original(child)
            return process.ProcessChannelObservation(value.pid, value.creation_time+1)
        with patch.object(process._RecipientWitnessChild, '_observe', observe): self.reject(self.run_probe)

    def test_requester_dictionary_cannot_become_native_observation(self):
        original = process._RecipientWitnessChild._observe
        def observe(child): return asdict(original(child))
        with patch.object(process._RecipientWitnessChild, '_observe', observe): self.reject(self.run_probe)

    def test_equal_integer_subclass_native_observation_is_rejected(self):
        class Pid(int): pass
        original = process._RecipientWitnessChild._observe
        def observe(child):
            value = original(child); object.__setattr__(value, 'pid', Pid(value.pid)); return value
        with patch.object(process._RecipientWitnessChild, '_observe', observe): self.reject(self.run_probe)

    def test_invalid_lifetimes_are_rejected(self):
        for value in (True, 0, -1, 6, float('inf'), float('nan'), '5', None):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                channel.RecipientChannelProbe(self.acquisition, self.recipient, timeout=value)

    def test_requester_objects_cannot_be_used_as_trusted_owners(self):
        with self.assertRaises(TypeError): channel.RecipientChannelProbe(object(), self.recipient)
        with self.assertRaises(TypeError): channel.RecipientChannelProbe(self.acquisition, self.descriptor)

    def test_result_metadata_construction_mutation_cannot_extend_claim(self):
        original = channel.RetiredRecipientChannelWitness
        original_init = original.__init__
        def initialize(value, *args, **kwargs):
            original_init(value, *args, **kwargs); object.__setattr__(value, 'process_id', 1)
        with patch.object(original, '__init__', initialize): self.reject(self.run_probe)

    def test_cleanup_failure_before_worker_cannot_report_confirmed_cleanup(self):
        with patch.object(self.acquisition, 'close', side_effect=ValueError('source cleanup failed')):
            with self.assertRaises(Exception): self.probe.close()
        status = self.probe.shutdown_status()
        self.assertIsNotNone(status)
        self.assertFalse(status.cleanup_confirmed)
        self.assertTrue(self.recipient._terminal)

    def test_oversized_credential_burns_attempt_without_launch(self):
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, credential='x'*513)); launch.assert_not_called()

    def test_non_string_credential_burns_attempt_without_launch(self):
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, credential=True)); launch.assert_not_called()

    def test_credential_subclass_burns_attempt_without_launch(self):
        class Credential(str): pass
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, credential=Credential(self.credential))); launch.assert_not_called()

    def test_application_subclass_burns_attempt_without_launch(self):
        class Application(str): pass
        token = self.reserve()
        with patch.object(channel, '_RecipientWitnessChild') as launch:
            self.reject(lambda: self.run_probe(token, app=Application('app'))); launch.assert_not_called()

    def test_recipient_revision_injection_fails_closed(self):
        token = self.reserve(); object.__setattr__(self.descriptor, 'recipient_revision', 2)
        self.reject(lambda: self.run_probe(token))

    def test_independent_child_watchdog_terminates_abandoned_bootstrap(self):
        child = process._RecipientWitnessChild(); self.addCleanup(child.close)
        deadline = time.monotonic()+13
        while child.poll() is None and time.monotonic() < deadline: time.sleep(.02)
        self.assertIsNotNone(child.poll(), 'independent child watchdog must end a blocked bootstrap')
        self.assertNotEqual(child.poll(), 0)
        child.close()

    def final_result_fault(self, effect):
        original = channel._values
        entered = []
        def values(value):
            snapshot = original(value)
            if (type(value) is channel.RetiredRecipientChannelWitness
                    and self.probe._finished is True and not entered):
                self.assertIsNotNone(self.probe._proof, 'final result race must follow valid proof')
                self.assertIsNotNone(self.probe._ack, 'final result race must follow valid cleanup ACK')
                self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)
                entered.append(True); effect()
            return snapshot
        with patch.object(channel, '_values', values): self.reject(self.run_probe)
        self.assertEqual(entered, [True], 'race must occur during terminal result comparison')

    def test_cancel_during_final_result_comparison_withholds_witness(self):
        self.final_result_fault(self.probe.close)

    def test_expiry_during_final_result_comparison_withholds_witness(self):
        self.final_result_fault(lambda: setattr(self.probe, '_deadline', 0))

    def test_revocation_during_final_result_comparison_withholds_witness(self):
        self.final_result_fault(lambda: self.registry.revoke('app'))

    def test_equal_valued_initial_state_subclass_is_rejected(self):
        class State(str): pass
        self.review(); self.probe._state = State('new')
        self.reject(self.probe.coordinator.reserve)

    def test_closed_wire_role_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.probe._wire, '_role', 'broker'))

    def test_closed_wire_session_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.probe._wire, '_session', 'f'*64))

    def test_closed_wire_phase_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.probe._wire, '_phase_snapshot', (4, 'f'*64, 'closed')))

    def test_closed_wire_key_hash_mutation_at_slot_release_withholds_witness(self):
        self.slot_fault(lambda: setattr(self.probe._wire, '_key_snapshot', 'f'*64))

    def test_equal_integer_phase_type_confusion_at_slot_release_withholds_witness(self):
        class Step(int): pass
        def change():
            wire = self.probe._wire
            wire._phase_snapshot = (Step(4), wire._phase_snapshot[1], 'closed')
        self.slot_fault(change)

    def test_native_uncertainty_after_slot_release_poisons_admission_and_status(self):
        self.slot_fault(lambda: setattr(self.probe._issued_child, '_cleanup_failed', True))
        self.assertFalse(self.probe.shutdown_status().cleanup_confirmed)
        self.assertFalse(transport._slot.acquire(blocking=False), 'native uncertainty must poison free admission')

    def test_clearing_cancellation_event_after_close_cannot_restore_channel(self):
        original = self.probe._cancel
        def cancel_then_clear():
            self.probe.close(); original.clear()
        self.proof_fault(cancel_then_clear)
        self.assertTrue(self.probe._cancelled, 'irreversible cancellation tombstone must survive event clearing')

    def test_replacing_cancellation_event_after_proof_cannot_restore_channel(self):
        self.proof_fault(lambda: setattr(self.probe, '_cancel', threading.Event()))
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_foreign_timer_after_proof_is_rejected_without_dispatching_its_cancel(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.probe, '_timer', foreign))
        foreign.cancel.assert_not_called()
        self.assertTrue(self.probe.shutdown_status().cleanup_confirmed)

    def test_original_timer_cleanup_failure_still_retires_sources_and_reports_uncertainty(self):
        token = self.reserve()
        entered = []
        def fail():
            self.assertIsNotNone(self.probe._proof, 'cleanup fault must follow valid proof')
            self.assertIsNotNone(self.probe._ack, 'cleanup fault must follow confirmed child ACK')
            entered.append(True)
            raise ValueError('timer cancellation failed')
        with patch.object(self.probe._issued_timer, 'cancel', side_effect=fail):
            self.reject(lambda: self.run_probe(token))
        self.assertEqual(entered, [True])
        self.assertFalse(self.probe.shutdown_status().cleanup_confirmed)
        self.assertEqual(self.probe._wire._state, 'closed')
        self.assertEqual(self.probe._wire._key, b'')
        self.assertTrue(self.acquisition._closed)


if __name__ == '__main__': unittest.main()
