"""Inactive coordinated association: two real workers, metadata, zero delivery.

Resources and reviewed acquisition data are synthetic trusted test fixtures.
The witness and association children are genuine Windows metadata-only peers.
Neither a historical association fact nor a human review becomes permission.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_source_rendezvous as rendezvous
from core import broker_source_native_association as association
from core import broker_source_association_peer as process
from core import broker_transport as transport
from core import test_broker_live_channel_check as helpers
from core.broker_live_channel_check import LiveChannelPublicationCheck
from core.broker_publication_commit_draft import PublicationCommitDraft
from core.broker_source_association_protocol import SourceRecipientAssociationExchange
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class SourceAssociationRendezvousTests(unittest.TestCase):
    DATA = helpers.LiveChannelPublicationCheckTests.DATA
    setUp = helpers.LiveChannelPublicationCheckTests.setUp
    install = helpers.LiveChannelPublicationCheckTests.install
    begin = helpers.LiveChannelPublicationCheckTests.begin
    observe = helpers.LiveChannelPublicationCheckTests.observe
    review = helpers.LiveChannelPublicationCheckTests.review
    reserve = helpers.LiveChannelPublicationCheckTests.reserve
    start = helpers.LiveChannelPublicationCheckTests.start
    stage = helpers.LiveChannelPublicationCheckTests.stage
    retirement = helpers.LiveChannelPublicationCheckTests.retirement
    terminal = helpers.LiveChannelPublicationCheckTests.terminal

    def prepare(self, **options):
        self.retirement()
        self.retained = self.lifecycle._owned_buffer
        self.slot = transport._slot
        self.gate = rendezvous.SourceAssociationRendezvousDryRun(self.lifecycle, **options)
        self.addCleanup(self.gate.close)
        return self.gate

    def run_gate(self, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal,
                      descriptor=self.descriptor)
        values.update(overrides)
        return self.gate.run(**values)

    def reject(self, **overrides):
        with self.assertRaises(rendezvous.SourceRendezvousError):
            self.run_gate(**overrides)
        self.assertEqual(self.retained, bytearray())
        self.assertIsNone(self.gate._issued_result)
        self.terminal()

    def before_fault(self, action, **overrides):
        self.prepare(); action(); self.reject(**overrides)

    def protocol_fault(self, phase, action):
        self.prepare(); reached = []
        original = getattr(SourceRecipientAssociationExchange, phase)
        def accept(wire, frame):
            result = original(wire, frame)
            self.assertIsNot(threading.current_thread(), threading.main_thread())
            self.assertIsNotNone(self.gate._issued_association)
            self.assertFalse(self.slot.acquire(blocking=False), 'shared admission must remain held')
            reached.append(True); action(result); return result
        with patch.object(SourceRecipientAssociationExchange, phase, accept): self.reject()
        self.assertEqual(reached, [True], 'fault must follow the genuine native protocol phase')

    def proof_fault(self, action): self.protocol_fault('accept_proof', lambda _: action())
    def ack_fault(self, action): self.protocol_fault('accept_ack', action)

    def final_fault(self, action, *, after=False):
        self.prepare(); reached, acted = [], []
        original = self.gate._final_current
        def final(candidate):
            self.assertEqual(self.retained, bytearray())
            # The host intentionally owns the semaphore's non-reentrant guard
            # through the final fence, so testing acquire here would deadlock.
            self.assertTrue(self.slot._cond._lock.locked(), 'final validation still excludes new admission')
            reached.append(True)
            if not after: action(candidate); acted.append(True)
            result = original(candidate)
            if after: action(candidate); acted.append(True)
            return result
        with patch.object(self.gate, '_final_current', side_effect=final): self.reject()
        self.assertTrue(reached, 'fault must follow both joined workers')
        self.assertTrue(acted, 'the selected fault must actually execute')

    def ready_fault(self, action):
        self.prepare(); reached = []
        original = self.gate._ready_helper
        def ready():
            result = original()
            if result is None: return None
            self.assertFalse(self.slot.acquire(blocking=False), 'ready handoff must retain admission')
            reached.append(True); action(); return result
        with patch.object(self.gate, '_ready_helper', side_effect=ready): self.reject()
        self.assertEqual(reached, [True], 'fault must follow genuine source readiness')

    def child_fault(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'source-rendezvous-association-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_source_association_entry as entry\n'+prefix+
            '\nentry.run()\n'+ending, encoding='utf-8')
        return patch.object(process._SourceAssociationPeer, '_entry_path', return_value=path)

    def test_two_real_workers_and_native_peers_retire_before_admission_release(self):
        self.prepare(); reached = []
        original = self.gate._release_admission
        def release():
            self.assertFalse(self.slot.acquire(blocking=False))
            self.assertEqual(self.retained, bytearray())
            self.assertFalse(self.gate._issued_association_thread.is_alive())
            witness = self.gate._issued_witness
            self.assertFalse(witness._issued_thread.is_alive())
            witness._original().helper._issued_child._retired()
            self.gate._issued_association._issued_child._retired()
            reached.append(True); return original()
        with patch.object(self.gate, '_release_admission', side_effect=release): result = self.run_gate()
        self.assertEqual(reached, [True])
        self.assertIs(type(result), association.SourceNativeAssociationEvidence)
        self.assertEqual((result.outcome, result.released_bytes), ('associated_discarded', 0))
        self.assertEqual(result.binding_digest, hashlib.sha256(result.canonical_binding).hexdigest())
        view = result.inspect(); source = loads(view['source_commit_json'])
        self.assertNotEqual(source['channel']['pid'], view['recipient_channel']['pid'])
        self.assertEqual(source['staged_bytes'], len(self.DATA))
        self.assertEqual(source['staged_digest'], hashlib.sha256(self.DATA).hexdigest())
        status = self.gate.inspect()
        self.assertEqual(set(status), {'state', 'cleanup_confirmed', 'admission_held',
                                       'source_joined', 'association_joined'})
        self.assertTrue(status['cleanup_confirmed'])
        self.assertFalse(status['admission_held'])
        self.assertTrue(status['source_joined'])
        self.assertTrue(status['association_joined'])
        self.assertTrue(self.slot.acquire(blocking=False)); self.slot.release()
        self.assertNotIn('data', asdict(result))
        with self.assertRaises(TypeError): bool(result)
        self.terminal()

    def test_old_publication_run_is_never_selected_as_resumable_host(self):
        self.prepare()
        with patch.object(LiveChannelPublicationCheck, 'run', side_effect=AssertionError('old active run forbidden')) as old_run:
            result = self.run_gate()
        old_run.assert_not_called(); self.assertEqual(result.released_bytes, 0)
        self.terminal()

    def test_detached_fact_has_no_delivery_or_authorization_port(self):
        self.prepare(); result = self.run_gate()
        result.inspect()['grant_id'] = 'forged'
        self.assertNotEqual(result.inspect()['grant_id'], 'forged')
        for name in ('read', 'write', 'acquire', 'publish', 'deliver', 'release', 'execute', 'authorize', 'allow', 'data'):
            self.assertFalse(hasattr(self.gate, name))
        with self.assertRaises(TypeError): rendezvous.SourceAssociationRendezvousDryRun(result)
        self.terminal()

    def test_application_authority_is_not_an_original_reviewed_source(self):
        for value in (self.registry.get('app'), self.model, self.descriptor, {'approved': True}):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                rendezvous.SourceAssociationRendezvousDryRun(value)
        self.assertFalse(self.lifecycle._publication_attempted)

    def test_unreviewed_or_unretired_lifecycle_cannot_create_rendezvous(self):
        self.observe()
        with self.assertRaises(Exception): rendezvous.SourceAssociationRendezvousDryRun(self.lifecycle)
        self.assertEqual(self.lifecycle._owned_buffer, None)

    def test_replay_after_success_cannot_launch_another_worker(self):
        self.prepare(); result = self.run_gate()
        with patch.object(threading.Thread, 'start', side_effect=AssertionError('replay cannot start')) as start:
            with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        start.assert_not_called(); self.assertIs(self.gate._issued_result, result)
        self.assertEqual(result.released_bytes, 0); self.terminal()

    def test_success_close_is_idempotent_and_never_restores_review(self):
        self.prepare(); result = self.run_gate()
        self.gate.close(); self.gate.close()
        self.assertIs(self.gate._issued_result, result)
        with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.terminal()

    def test_wrong_application_cannot_transfer_reviewed_source(self): self.before_fault(lambda: None, app='other')
    def test_wrong_credential_cannot_use_review(self): self.before_fault(lambda: None, credential='wrong')
    def test_boolean_credential_is_not_permission(self): self.before_fault(lambda: None, credential=True)
    def test_oversized_credential_is_bounded(self): self.before_fault(lambda: None, credential='x'*513)
    def test_boolean_proposal_is_not_permission(self): self.before_fault(lambda: None, proposal=True)
    def test_approval_mapping_cannot_supply_source_authority(self): self.before_fault(lambda: None, proposal={'approved': True})
    def test_descriptor_mapping_is_not_trusted_recipient(self): self.before_fault(lambda: None, descriptor=asdict(self.descriptor))
    def test_equal_descriptor_copy_cannot_transfer_original_recipient(self): self.before_fault(lambda: None, descriptor=replace(self.descriptor))
    def test_changed_effect_requires_new_review(self): self.before_fault(lambda: None, proposal=make_file_read_proposal('untrusted label', max_bytes=127))
    def test_changed_reference_requires_new_review(self): self.before_fault(lambda: None, proposal=make_file_read_proposal('changed', max_bytes=128))
    def test_subclass_application_cannot_impersonate_original_owner(self):
        class Application(str): pass
        self.before_fault(lambda: None, app=Application('app'))

    def test_revocation_before_start_denies(self): self.before_fault(lambda: self.registry.revoke('app'))
    def test_rotation_before_start_denies(self): self.before_fault(lambda: self.registry.rotate_credential('app'))
    def test_permission_removal_before_start_denies(self): self.before_fault(lambda: self.registry.update_permissions('app', scopes=[]))
    def test_version_change_before_start_denies(self): self.before_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_superseding_review_before_start_denies(self): self.before_fault(lambda: self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1))
    def test_source_buffer_mutation_before_start_is_wiped(self): self.before_fault(lambda: self.retained.extend(b'x'))
    def test_cancel_before_start_spends_source_without_launch(self): self.before_fault(lambda: self.gate.close())

    def test_deadline_extension_cannot_prolong_original_source(self): self.before_fault(lambda: setattr(self.gate, '_deadline', time.monotonic()+60))
    def test_deadline_replacement_cannot_skip_lifetime_check(self): self.before_fault(lambda: setattr(self.gate, '_deadline', 0))

    def test_fabricated_ready_owner_is_not_used_or_closed(self):
        self.prepare(); foreign = Mock()
        with patch.object(self.gate, '_ready_helper', return_value=foreign): self.reject()
        foreign.close.assert_not_called(); foreign._current.assert_not_called()

    def test_revocation_at_ready_handoff_prevents_association(self): self.ready_fault(lambda: self.registry.revoke('app'))
    def test_rotation_at_ready_handoff_prevents_association(self): self.ready_fault(lambda: self.registry.rotate_credential('app'))
    def test_version_change_at_ready_handoff_prevents_association(self): self.ready_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancel_at_ready_handoff_prevents_association(self): self.ready_fault(lambda: self.gate.close())
    def test_buffer_mutation_at_ready_handoff_is_wiped(self): self.ready_fault(lambda: self.retained.extend(b'x'))

    def test_revocation_after_new_native_proof_denies(self): self.proof_fault(lambda: self.registry.revoke('app'))
    def test_rotation_after_new_native_proof_denies(self): self.proof_fault(lambda: self.registry.rotate_credential('app'))
    def test_permission_removal_after_new_native_proof_denies(self): self.proof_fault(lambda: self.registry.update_permissions('app', scopes=[]))
    def test_version_change_after_new_native_proof_denies(self): self.proof_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_superseding_review_after_native_proof_denies(self): self.proof_fault(lambda: self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1))
    def test_cancel_after_new_native_proof_denies(self): self.proof_fault(lambda: self.gate.close())
    def test_descriptor_mutation_after_native_proof_denies(self): self.proof_fault(lambda: object.__setattr__(self.descriptor, 'recipient_revision', 2))
    def test_buffer_substitution_after_native_proof_denies(self): self.proof_fault(lambda: setattr(self.lifecycle, '_owned_buffer', bytearray(self.DATA)))
    def test_foreign_association_owner_is_not_called_or_closed(self):
        foreign = Mock(); self.proof_fault(lambda: setattr(self.gate, '_association', foreign))
        foreign.close.assert_not_called(); foreign.run.assert_not_called()
    def test_foreign_witness_owner_is_not_called_or_closed(self):
        foreign = Mock(); self.proof_fault(lambda: setattr(self.gate, '_witness', foreign))
        foreign.close.assert_not_called()

    def test_revocation_after_acknowledgment_withholds_fact(self): self.ack_fault(lambda _: self.registry.revoke('app'))
    def test_rotation_after_acknowledgment_withholds_fact(self): self.ack_fault(lambda _: self.registry.rotate_credential('app'))
    def test_cancel_after_acknowledgment_withholds_fact(self): self.ack_fault(lambda _: self.gate.close())
    def test_reintroduced_bytes_after_acknowledgment_are_wiped(self): self.ack_fault(lambda _: self.retained.extend(self.DATA))
    def test_mutated_ack_cannot_claim_delivery(self): self.ack_fault(lambda value: object.__setattr__(value, 'released_bytes', 1))

    def test_revocation_after_both_workers_joined_withholds_fact(self): self.final_fault(lambda _: self.registry.revoke('app'))
    def test_rotation_after_both_workers_joined_withholds_fact(self): self.final_fault(lambda _: self.registry.rotate_credential('app'))
    def test_version_change_after_both_workers_joined_withholds_fact(self): self.final_fault(lambda _: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancel_after_both_workers_joined_withholds_fact(self): self.final_fault(lambda _: self.gate.close())
    def test_reintroduced_bytes_after_both_workers_joined_are_wiped(self): self.final_fault(lambda _: self.retained.extend(self.DATA))
    def test_changed_final_candidate_cannot_claim_delivery(self): self.final_fault(lambda value: object.__setattr__(value, 'released_bytes', 37))
    def test_boolean_final_candidate_byte_count_is_rejected(self): self.final_fault(lambda value: object.__setattr__(value, 'released_bytes', False))
    def test_changed_final_binding_is_rejected(self): self.final_fault(lambda value: object.__setattr__(value, 'canonical_binding', b'{}'))
    def test_completed_revocation_during_final_validation_never_seals_fact(self): self.final_fault(lambda _: self.registry.revoke('app'), after=True)
    def test_cancellation_during_final_validation_never_seals_fact(self): self.final_fault(lambda _: self.gate.close(), after=True)

    def test_close_during_association_signals_without_releasing_live_admission(self):
        self.prepare(); entered, resume = threading.Event(), threading.Event()
        original = SourceRecipientAssociationExchange.accept_proof
        def proof(wire, frame):
            result = original(wire, frame)
            entered.set(); self.assertTrue(resume.wait(2)); return result
        with patch.object(SourceRecipientAssociationExchange, 'accept_proof', proof):
            future = self.pool.submit(self.run_gate)
            try:
                self.assertTrue(entered.wait(2))
                started = time.monotonic(); self.gate.close()
                self.assertLess(time.monotonic()-started, .5, 'caller cancellation must not join paused workers')
                self.assertFalse(self.slot.acquire(blocking=False))
                self.assertFalse(future.done())
            finally:
                resume.set()
            with self.assertRaises(rendezvous.SourceRendezvousError): future.result(timeout=3)
        self.assertEqual(self.retained, bytearray()); self.terminal()
        self.assertIsNone(self.gate._issued_result)

    def test_concurrent_duplicate_attempt_cancels_first_and_never_acquires_twice(self):
        self.prepare(); entered, resume = threading.Event(), threading.Event()
        original = SourceRecipientAssociationExchange.accept_proof
        def proof(wire, frame):
            result = original(wire, frame)
            entered.set(); self.assertTrue(resume.wait(2)); return result
        with patch.object(SourceRecipientAssociationExchange, 'accept_proof', proof):
            future = self.pool.submit(self.run_gate)
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
                self.assertFalse(self.slot.acquire(blocking=False))
            finally:
                resume.set()
            with self.assertRaises(rendezvous.SourceRendezvousError): future.result(timeout=3)
        self.assertEqual(self.retained, bytearray()); self.assertIsNone(self.gate._issued_result)
        self.terminal()

    def test_busy_global_slot_cannot_be_released_by_unadmitted_source(self):
        self.prepare(); self.assertTrue(self.slot.acquire(blocking=False))
        try:
            with patch.object(threading.Thread, 'start', side_effect=AssertionError('busy admission cannot launch')) as start:
                self.reject()
            start.assert_not_called()
            self.assertFalse(self.slot.acquire(blocking=False), 'foreign existing owner keeps its slot')
        finally: self.slot.release()

    def test_caller_holding_authority_cannot_start_worker_or_native_io(self):
        self.prepare()
        with self.registry._lock, patch.object(threading.Thread, 'start', side_effect=AssertionError('authority held across launch')) as start:
            self.reject()
        start.assert_not_called()

    def test_foreign_association_thread_cannot_be_joined_as_original(self):
        foreign = Mock(); self.proof_fault(lambda: setattr(self.gate, '_association_thread', foreign))
        foreign.join.assert_not_called(); foreign.is_alive.assert_not_called()

    def test_foreign_source_thread_cannot_be_joined_as_original(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.gate._issued_witness, '_thread', foreign))
        foreign.join.assert_not_called(); foreign.is_alive.assert_not_called()

    def test_native_cleanup_uncertainty_retains_shared_admission(self):
        self.prepare(); original = process._SourceAssociationPeer.close
        with patch.object(process._SourceAssociationPeer, 'close', return_value=None): self.reject()
        self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
        self.assertTrue(self.gate.inspect()['admission_held'])
        self.assertFalse(self.slot.acquire(blocking=False))
        original(self.gate._issued_association._issued_child)
        self.gate._issued_association._issued_child._retired()
        self.assertFalse(self.slot.acquire(blocking=False), 'late manual disposal cannot restore poisoned admission')

    def test_foreign_registry_lease_is_never_invoked_as_authority(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.model, '_lease', foreign))
        foreign.assert_not_called()

    def test_cancel_does_not_wait_for_busy_original_witness_condition(self):
        self.prepare(); proved, resume = threading.Event(), threading.Event()
        held, release = threading.Event(), threading.Event()
        original = SourceRecipientAssociationExchange.accept_proof
        def proof(wire, frame):
            result = original(wire, frame)
            proved.set(); self.assertTrue(resume.wait(2)); return result
        def hold():
            lock = self.gate._issued_witness._original().lock
            with lock:
                held.set(); self.assertTrue(release.wait(2))
        with patch.object(SourceRecipientAssociationExchange, 'accept_proof', proof):
            future = self.pool.submit(self.run_gate)
            holder = None
            try:
                self.assertTrue(proved.wait(2))
                holder = self.pool.submit(hold); self.assertTrue(held.wait(1))
                started = time.monotonic(); self.gate.close()
                self.assertLess(time.monotonic()-started, .5)
                self.assertFalse(self.slot.acquire(blocking=False))
            finally:
                release.set(); resume.set()
                if holder is not None: holder.result(timeout=1)
            with self.assertRaises(rendezvous.SourceRendezvousError): future.result(timeout=3)
        self.assertEqual(self.retained, bytearray()); self.assertIsNone(self.gate._issued_result)
        self.terminal()

    def test_association_child_crash_rejects_and_requires_guarded_disposal(self):
        self.prepare()
        with self.child_fault(prefix='os._exit(7)'): self.reject()
        self.assertIsNone(self.gate._issued_result)
        self.assertIsNotNone(self.gate._issued_association._issued_child)
        self.assertFalse(self.gate._issued_association_thread.is_alive())

    def test_association_child_hang_expires_without_returning_metadata_fact(self):
        self.prepare(timeout=5); started = time.monotonic()
        deadline = self.gate._original().deadline
        self.assertLessEqual(deadline, started+5, 'the original deadline is never prolonged')
        with self.child_fault(prefix='time.sleep(10)'): self.reject()
        elapsed = time.monotonic()-started
        self.assertGreaterEqual(elapsed, deadline-started, 'the live peer must reach the unchanged expiry')
        self.assertLess(elapsed, 8, 'expiry and native cleanup must remain bounded')
        self.assertIs(type(self.gate._issued_association._issued_child), process._SourceAssociationPeer)
        self.assertIsNone(self.gate._issued_result)

    def test_new_peer_extra_output_cannot_be_reported_as_success(self):
        self.prepare()
        with self.child_fault(ending="os.write(1,b'extra')"): self.reject()

    def test_new_peer_nonzero_exit_after_acknowledgment_withholds_fact(self):
        self.prepare()
        with self.child_fault(ending='os._exit(7)'): self.reject()

    def test_final_key_restoration_poison_cannot_reopen_review(self):
        self.final_fault(lambda _: setattr(self.model._exchange, '_key', b'k'*32))
        self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_final_worker_finished_flag_is_not_cleanup_evidence(self):
        def change(_):
            worker = self.gate._issued_witness
            worker._history = worker._history._replace(cleanup=False)
        self.final_fault(change)
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_final_thread_substitution_cannot_manufacture_join(self):
        foreign = Mock()
        self.final_fault(lambda _: setattr(self.gate, '_association_thread', foreign))
        foreign.join.assert_not_called(); foreign.is_alive.assert_not_called()

    def test_native_shape_mutation_after_real_retirement_is_not_trusted_cleanup(self):
        self.prepare(); original = self.gate._final_current; reached = []
        child = None
        def final(candidate):
            nonlocal child
            child = self.gate._issued_witness._original().helper._issued_child
            retired = child._retired
            def changed():
                result = retired(); child._process = object(); reached.append(True); return result
            child._retired = changed
            return original(candidate)
        try:
            with patch.object(self.gate, '_final_current', side_effect=final): self.reject()
            self.assertTrue(reached, 'mutation must follow genuine first native retirement')
            self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
            self.assertFalse(self.slot.acquire(blocking=False))
        finally:
            if child is not None:
                child.__dict__.pop('_retired', None)
                child._process = None

    def test_replaced_shared_slot_is_never_invoked_and_original_remains_poisoned(self):
        foreign = Mock()
        try:
            self.proof_fault(lambda: setattr(transport, '_slot', foreign))
            foreign.acquire.assert_not_called(); foreign.release.assert_not_called()
            self.assertFalse(self.slot.acquire(blocking=False))
        finally:
            if hasattr(self, 'slot'): transport._slot = self.slot

    def test_unexpected_source_exit_after_association_is_not_normal_worker_retirement(self):
        self.prepare(); original = association.SourceNativeAssociationDryRun.run
        reached = []
        def run(gate, *args, **kwargs):
            result = original(gate, *args, **kwargs)
            self.assertEqual(result.released_bytes, 0)
            child = self.gate._issued_witness._native_original().child
            child._ownership.check(child._ownership.k.TerminateProcess(child._owned[4], 7))
            deadline = time.monotonic()+1
            while child.poll() is None and time.monotonic() < deadline: time.sleep(.002)
            self.assertEqual(child.poll(), 7); reached.append(True); return result
        with patch.object(association.SourceNativeAssociationDryRun, 'run', run): self.reject()
        self.assertEqual(reached, [True], 'exit must follow genuine association completion')

    def test_archived_byte_count_mutation_is_rejected_without_replay(self):
        self.prepare(); result = self.run_gate()
        object.__setattr__(result, 'released_bytes', 1)
        with self.assertRaises(rendezvous.SourceRendezvousError): self.gate.inspect()
        with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.assertEqual(self.retained, bytearray()); self.terminal()

    def test_archived_binding_mutation_is_rejected_without_replay(self):
        self.prepare(); result = self.run_gate()
        object.__setattr__(result, 'canonical_binding', b'{}')
        with self.assertRaises(rendezvous.SourceRendezvousError): self.gate.inspect()
        with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.assertEqual(self.retained, bytearray()); self.terminal()

    def test_archived_history_substitution_cannot_manufacture_fresh_fact(self):
        self.prepare(); result = self.run_gate()
        self.gate._history = self.gate._history._replace(result=replace(result))
        with self.assertRaises(rendezvous.SourceRendezvousError): self.gate.inspect()
        with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.assertEqual(self.retained, bytearray()); self.terminal()

    def test_archived_owner_alias_deletion_is_not_restored_authority(self):
        self.prepare(); result = self.run_gate()
        del self.gate._issued_origin
        with self.assertRaises(rendezvous.SourceRendezvousError): self.gate.inspect()
        with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.assertEqual(result.released_bytes, 0); self.terminal()

    def test_first_witness_codec_session_mutation_after_join_poison_is_not_freshness(self):
        self.final_fault(lambda _: setattr(self.gate._issued_witness._wire_original().codec, '_session', b'x'*32))
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_first_witness_proof_mutation_after_association_cannot_survive_join(self):
        self.final_fault(lambda _: object.__setattr__(self.gate._issued_witness._original().helper._issued_proof,
            'binding_digest', 'f'*64))
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_retired_association_codec_key_restoration_poison_is_not_authority(self):
        self.final_fault(lambda _: setattr(self.gate._issued_association._channel_original().wire, '_key', b'k'*32))
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_foreign_commit_timer_event_is_not_invoked_as_cleanup_evidence(self):
        foreign, captured = Mock(), {}
        def change(_):
            timer = self.gate._worker_original().commit_timer
            captured['timer'], captured['finished'] = timer, timer.finished
            timer.finished = foreign
        try:
            self.final_fault(change)
            foreign.is_set.assert_not_called(); foreign.set.assert_not_called()
            self.assertFalse(self.slot.acquire(blocking=False))
        finally:
            if captured: captured['timer'].finished = captured['finished']

    def test_cleared_native_archive_cannot_erase_existing_child_ownership(self):
        def change(_):
            gate = self.gate._issued_association
            self.assertIsNotNone(gate._issued_child)
            gate._channel = gate._issued_channel = gate._recovery_channel = None
        self.final_fault(change)
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_all_witness_native_capsules_cleared_after_join_cannot_claim_no_child(self):
        def change(_):
            worker = self.gate._issued_witness
            self.assertIsNotNone(worker._original().helper._issued_child)
            worker._native = worker._issued_native = worker._recovery_native = None
        self.final_fault(change)
        self.assertFalse(self.slot.acquire(blocking=False))

    def test_replaced_terminal_history_after_release_cannot_return_copied_evidence(self):
        self.prepare(); original = self.gate._release_admission; reached = []
        def release():
            value = original()
            history = self.gate._status()
            result = replace(history.result)
            forged = history._replace(result=result, snapshot=association._facts(result))
            self.gate._history = self.gate._issued_history = self.gate._recovery_history = forged
            self.gate._result = self.gate._issued_result = result
            reached.append(True); return value
        with patch.object(self.gate, '_release_admission', side_effect=release):
            with self.assertRaises(rendezvous.SourceRendezvousError): self.run_gate()
        self.assertEqual(reached, [True], 'substitution must follow real retirement and release')
        self.assertEqual(self.retained, bytearray()); self.terminal()

    def test_unadmitted_condition_substitution_is_not_restored_or_invoked(self):
        self.prepare(); original, foreign = self.slot._cond, Mock()
        self.slot._cond = foreign
        try:
            self.reject()
            self.assertIs(self.slot._cond, foreign, 'unadmitted cleanup cannot overwrite shared synchronization')
            foreign.acquire.assert_not_called(); foreign.release.assert_not_called()
            foreign.notify.assert_not_called(); self.assertEqual(foreign.mock_calls, [])
        finally: self.slot._cond = original
        self.assertTrue(self.slot.acquire(blocking=False)); self.slot.release()

    def test_buffer_reintroduced_after_final_validation_is_wiped_before_rejection(self):
        self.final_fault(lambda _: self.retained.extend(self.DATA), after=True)
        self.assertEqual(self.retained, bytearray())

    def test_cancellation_at_commit_constructor_return_disposes_original_key_and_timer(self):
        self.prepare(); original = PublicationCommitDraft.__init__; captured = []
        def construct(commit, *args, **kwargs):
            result = original(commit, *args, **kwargs)
            captured.append(commit); self.gate.close(); return result
        def closed():
            self.assertEqual(len(captured), 1, 'cancellation must follow a constructed original commit')
            commit = captured[0]
            self.assertIs(self.gate._worker_original().commit, commit)
            self.assertEqual(commit._issued_wire._key, b'')
            self.assertEqual(commit._issued_wire._state, 'closed')
            self.assertTrue(commit._issued_timer.finished.is_set())
            self.assertTrue(commit._issued_cancel.is_set())
            self.assertEqual(self.retained, bytearray())
        release = self.gate._release_admission; retired = []
        def release_after_cleanup():
            closed(); retired.append(True); return release()
        with patch.object(PublicationCommitDraft, '__init__', construct), patch.object(
                self.gate, '_release_admission', side_effect=release_after_cleanup): self.reject()
        closed()
        if self.gate.inspect()['cleanup_confirmed']: self.assertEqual(retired, [True])

    def test_cancellation_at_association_constructor_return_disposes_private_model(self):
        self.prepare(); original = association.SourceNativeAssociationDryRun.__init__; captured = []
        def construct(gate, *args, **kwargs):
            result = original(gate, *args, **kwargs)
            captured.append(gate); self.gate.close(); return result
        def closed():
            self.assertEqual(len(captured), 1, 'cancellation must follow a constructed original association')
            gate = captured[0]; origin = gate._original()
            self.assertIs(self.gate._worker_original().association, gate)
            self.assertEqual(origin.peer._key, b'')
            self.assertEqual(origin.peer._state, 'closed')
            self.assertIs(origin.source.model_ledger._closed, True)
            self.assertTrue(origin.source.timer.finished.is_set())
            self.assertTrue(gate.inspect()['cleanup_confirmed'])
            self.assertIsNone(gate._issued_child, 'cancelled bootstrap cannot launch the second native child')
            self.assertEqual(self.retained, bytearray())
        release = self.gate._release_admission; retired = []
        def release_after_cleanup():
            closed(); retired.append(True); return release()
        with patch.object(association.SourceNativeAssociationDryRun, '__init__', construct), patch.object(
                self.gate, '_release_admission', side_effect=release_after_cleanup): self.reject()
        closed()
        if self.gate.inspect()['cleanup_confirmed']: self.assertEqual(retired, [True])


if __name__ == '__main__': unittest.main()
