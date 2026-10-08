"""Inactive native association of a genuine live dry source; metadata only.

The original witness worker is paused outside authority leases. The new gate
must acquire fresh authority itself, discard the synthetic quarantined bytes,
and retire its separate original Windows peer. No test publishes a payload.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import broker_source_native_association as association
from core import broker_source_association_peer as process
from core import test_broker_live_channel_check as helpers
from core.broker_live_channel_check import LiveChannelCheckError
from core.broker_publication_commit_draft import PublicationCommitDraft
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_source_association_protocol import SourceRecipientAssociationExchange
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class SourceNativeAssociationTests(unittest.TestCase):
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
    prepare_check = helpers.LiveChannelPublicationCheckTests.prepare
    terminal = helpers.LiveChannelPublicationCheckTests.terminal
    terminate_child = helpers.LiveChannelPublicationCheckTests.terminate_child

    def create_ready_commit(self):
        self.commit = PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)
        self.addCleanup(self.commit.close)
        peer = PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(peer.close)
        peer.accept_prepare(self.commit.prepare())
        self.commit.accept_ready(peer.ready())

    def create_gate(self, **options):
        self.gate = association.SourceNativeAssociationDryRun(self.commit, **options)
        self.addCleanup(self.gate.close)

    def run_gate(self, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal,
                      descriptor=self.descriptor)
        values.update(overrides)
        return self.gate.run(**values)

    def independent(self, operation, *, options=None, create_gate=True):
        """Original source is genuine, alive and outside another thread's leases."""
        self.prepare_check()
        entered, resume = threading.Event(), threading.Event()
        original = self.check._native_current
        def native():
            original()
            if self.check._proof is not None and self.check._state == 'prepared' and not entered.is_set():
                self.check._state = 'witnessed'
                entered.set()
                if not resume.wait(6): raise LiveChannelCheckError('test_pause_timeout')
        with patch.object(self.check, '_native_current', side_effect=native):
            future = self.pool.submit(self.check.run, 'app', self.credential, self.proposal, self.descriptor)
            try:
                self.assertTrue(entered.wait(2), 'must reach an original native proof without authority leases')
                self.create_ready_commit()
                if create_gate: self.create_gate(**(options or {}))
                operation()
            finally:
                resume.set()
                with self.assertRaises(LiveChannelCheckError): future.result(timeout=3)
        self.terminal()
        self.assertTrue(self.check.shutdown_status().cleanup_confirmed)

    def reject(self, **overrides):
        with self.assertRaises(association.SourceNativeAssociationError): self.run_gate(**overrides)
        self.assertEqual(self.retained, bytearray())
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertTrue(self.commit._attempted)
        self.assertIsNone(self.gate._issued_result)

    def before_run_fault(self, action, **overrides):
        def operation():
            action()
            self.reject(**overrides)
        self.independent(operation)

    def proof_fault(self, action):
        reached = []
        def operation():
            original = SourceRecipientAssociationExchange.accept_proof
            def proof(wire, frame):
                value = original(wire, frame)
                self.assertEqual(value.outcome, 'associated_ready')
                self.assertIsNone(self.gate._issued_child.poll())
                self.assertEqual(bytes(self.retained), self.DATA)
                reached.append(True); action(); return value
            with patch.object(SourceRecipientAssociationExchange, 'accept_proof', proof): self.reject()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must follow the genuine new native proof')

    def consumption_fault(self, action, *, after=False):
        reached = []
        def operation():
            original = self.gate._reservation.reserve_and_discard
            def consume(*args, **kwargs):
                self.assertIsNone(self.gate._issued_child.poll())
                reached.append(True)
                if not after: action()
                value = original(*args, **kwargs)
                if after: action()
                return value
            with patch.object(self.gate._reservation, 'reserve_and_discard', side_effect=consume): self.reject()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must reach original one-use discard')

    def ack_fault(self, action):
        reached = []
        def operation():
            original = SourceRecipientAssociationExchange.accept_ack
            def ack(wire, frame):
                value = original(wire, frame)
                self.assertEqual(self.gate._issued_child.poll(), 0)
                self.assertEqual(self.retained, bytearray())
                reached.append(True); action(value); return value
            with patch.object(SourceRecipientAssociationExchange, 'accept_ack', ack): self.reject()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must follow the exited native peer acknowledgment')

    def joined_fault(self, action):
        reached = []
        def operation():
            original = self.gate._source_current
            def current(*args, **kwargs):
                value = original(*args, **kwargs)
                child = self.gate._issued_child
                if child is not None and child._closed is True and not reached:
                    child._retired()
                    self.assertEqual(self.retained, bytearray())
                    reached.append(True); action()
                return value
            with patch.object(self.gate, '_source_current', side_effect=current): self.reject()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must follow original native cleanup and join')

    def retirement_fault(self, action):
        reached = []
        def operation():
            original = self.gate._reservation.close
            def close():
                value = original()
                if not reached:
                    self.gate._issued_child._retired()
                    self.assertTrue(self.lifecycle._publication_attempted)
                    reached.append(True); action()
                return value
            with patch.object(self.gate._reservation, 'close', side_effect=close): self.reject()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must follow source model retirement and native join')

    def archive_fault(self, action, *, verify=None):
        reached = []
        def operation():
            original = self.gate._save
            def save(state, *args, **kwargs):
                value = original(state, *args, **kwargs)
                if state == 'associated_discarded':
                    self.gate._issued_child._retired()
                    self.assertEqual(self.retained, bytearray())
                    reached.append(True); action(kwargs['result'])
                return value
            with patch.object(self.gate, '_save', side_effect=save): self.reject()
            if verify is not None: verify()
        self.independent(operation)
        self.assertEqual(reached, [True], 'fault must occur during final successful archive publication')

    def terminal_field_fault(self, field, transform, *, delete=False):
        def operation():
            result = self.run_gate()
            original = getattr(self.gate, field)
            try:
                if delete: delattr(self.gate, field)
                else: setattr(self.gate, field, transform(original))
                with self.assertRaises(association.SourceNativeAssociationError): self.gate.inspect()
                self.assertEqual(result.released_bytes, 0)
                self.assertEqual(self.retained, bytearray())
            finally:
                # Restore only the deliberately faulted historical mirror for
                # test disposal. The original source remains irreversibly spent.
                setattr(self.gate, field, original)
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
        self.independent(operation)

    def terminate_new_child(self):
        child = self.gate._issued_child
        child._ownership.check(child._ownership.k.TerminateProcess(child._owned[4], 7))
        deadline = time.monotonic()+1
        while child.poll() is None and time.monotonic() < deadline: time.sleep(.002)
        self.assertEqual(child.poll(), 7)

    def child_fault(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'source-native-association-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_source_association_entry as entry\n'+prefix+
            '\nentry.run()\n'+ending, encoding='utf-8')
        return patch.object(process._SourceAssociationPeer, '_entry_path', return_value=path)

    def test_real_source_consumption_separate_native_association_and_join_release_zero_bytes(self):
        def operation():
            source_child = self.check._issued_child
            result = self.run_gate()
            self.assertIs(type(result), association.SourceNativeAssociationEvidence)
            self.assertEqual((result.outcome, result.released_bytes), ('associated_discarded', 0))
            self.assertIsNot(self.gate._issued_child, source_child)
            self.gate._issued_child._retired()
            self.assertEqual(self.gate._issued_child._exit, 0)
            source_child._validate()
            value = result.inspect()
            source = loads(value['source_commit_json'])
            self.assertEqual(source['binding'], loads(self.check._binding_snapshot))
            self.assertEqual(source['staged_bytes'], len(self.DATA))
            self.assertEqual(source['staged_digest'], hashlib.sha256(self.DATA).hexdigest())
            self.assertEqual(source['channel']['pid'], source_child.pid)
            self.assertEqual(value['recipient_channel']['pid'], self.gate._native_observation.pid)
            self.assertEqual(result.binding_digest, hashlib.sha256(result.canonical_binding).hexdigest())
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertTrue(self.commit._attempted)
            self.assertEqual(self.retained, bytearray())
            self.assertNotIn('data', asdict(result))
            with self.assertRaises(TypeError): bool(result)
        self.independent(operation)

    def test_binding_is_detached_metadata_and_does_not_create_a_read_port(self):
        def operation():
            result = self.run_gate()
            view = result.inspect(); view['grant_id'] = 'forged'
            self.assertNotEqual(result.inspect()['grant_id'], 'forged')
            for name in ('read', 'write', 'acquire', 'publish', 'release', 'deliver', 'execute', 'authorize', 'data', 'allow'):
                self.assertFalse(hasattr(self.gate, name))
            with self.assertRaises(TypeError): association.SourceNativeAssociationDryRun(result)
        self.independent(operation)

    def test_application_authority_or_review_record_is_not_an_original_source(self):
        self.observe()
        for value in (self.registry.get('app'), self.model, self.lifecycle, self.descriptor, {'approved': True}):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                association.SourceNativeAssociationDryRun(value)
        self.assertIs(self.lifecycle._publication_attempted, False)

    def test_one_use_source_cannot_replay_after_successful_association(self):
        def operation():
            result = self.run_gate()
            self.assertEqual(result.released_bytes, 0)
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
            self.assertIs(self.gate._issued_result, result, 'history cannot create a second association')
            with self.assertRaises(Exception): association.SourceNativeAssociationDryRun(self.commit)
        self.independent(operation)

    def test_invalid_timeouts_cannot_prolong_original_source_lifetime(self):
        def operation():
            for value in (True, False, 0, -1, 6, float('nan'), float('inf'), '5'):
                with self.subTest(timeout=repr(value)), self.assertRaises(association.SourceNativeAssociationError):
                    association.SourceNativeAssociationDryRun(self.commit, timeout=value)
            self.gate.close()
            self.reject()
        self.independent(operation)

    def test_successful_close_is_idempotent_and_cannot_reopen_source(self):
        def operation():
            result = self.run_gate()
            self.gate.close(); self.gate.close()
            self.assertEqual(result.released_bytes, 0)
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
            self.assertIs(self.gate._issued_result, result)
        self.independent(operation)

    def test_close_before_run_disposes_captured_local_model_peer_key(self):
        def operation():
            original = self.gate._original()
            peer = original.peer
            self.assertNotEqual(peer._key, b'')
            self.gate.close()
            self.assertEqual(peer._key, b'')
            self.assertEqual(peer._state, 'closed')
            self.assertEqual(self.retained, bytearray())
            self.assertTrue(self.lifecycle._publication_attempted)
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
            self.assertIsNone(self.gate._issued_child)
            self.assertIsNone(self.gate._issued_result)
        self.independent(operation)

    def test_constructor_failure_with_newly_busy_source_fails_promptly_and_spends_originals(self):
        def operation():
            entered, release = threading.Event(), threading.Event()
            captured = {}
            def hold():
                with self.registry._lock:
                    entered.set(); self.assertTrue(release.wait(2))
            def fail_bootstrap(owner, *args, **kwargs):
                captured['owner'] = owner
                captured['future'] = self.pool.submit(hold)
                self.assertTrue(entered.wait(1))
                raise association.SourceNativeAssociationError('synthetic_bootstrap_fault')
            try:
                started = time.monotonic()
                with patch.object(association.SourceNativeAssociationDryRun, '_source_current', fail_bootstrap):
                    with self.assertRaisesRegex(association.SourceNativeAssociationError, '^association_bootstrap_cleanup_failed$'):
                        association.SourceNativeAssociationDryRun(self.commit)
                self.assertLess(time.monotonic()-started, 1)
                self.assertFalse(captured['future'].done(), 'failed bootstrap cannot wait for busy source release')
                self.assertEqual(self.retained, bytearray())
                self.assertTrue(self.lifecycle._publication_attempted)
                self.assertTrue(self.commit._attempted)
                self.assertTrue(self.check._issued_cancel.is_set())
                self.assertEqual(captured['owner']._original().peer._key, b'')
                self.assertEqual(captured['owner']._original().peer._state, 'closed')
            finally:
                release.set()
                if 'future' in captured: captured['future'].result(timeout=1)
                if 'owner' in captured: captured['owner'].close()
        self.independent(operation, create_gate=False)

    def test_invalid_inputs_burn_source_before_any_native_launch(self):
        bad = dict(credential='wrong')
        def operation():
            with patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('must not launch')) as launch:
                self.reject(**bad)
                launch.assert_not_called()
        self.independent(operation)

    def test_wrong_application_cannot_transfer_source(self): self.before_run_fault(lambda: None, app='other')
    def test_wrong_credential_cannot_use_review(self): self.before_run_fault(lambda: None, credential='wrong')
    def test_boolean_credential_is_not_permission(self): self.before_run_fault(lambda: None, credential=True)
    def test_oversized_credential_is_rejected(self): self.before_run_fault(lambda: None, credential='x'*513)
    def test_descriptor_mapping_is_not_original_recipient(self): self.before_run_fault(lambda: None, descriptor=asdict(self.descriptor))
    def test_changed_effect_or_proposal_cannot_inherit_review(self):
        self.before_run_fault(lambda: None, proposal=make_file_read_proposal('changed', max_bytes=4096))
    def test_boolean_proposal_cannot_supply_source_authority(self): self.before_run_fault(lambda: None, proposal=True)
    def test_requester_approval_mapping_cannot_supply_source_authority(self): self.before_run_fault(lambda: None, proposal={'approved': True, 'operation': 'files.read'})
    def test_revocation_before_native_launch_denies(self): self.before_run_fault(lambda: self.registry.revoke('app'))
    def test_credential_rotation_before_native_launch_denies(self): self.before_run_fault(lambda: self.registry.rotate_credential('app'))
    def test_permission_removal_before_native_launch_denies(self): self.before_run_fault(lambda: self.registry.update_permissions('app', scopes=[]))
    def test_stale_draft_version_before_native_launch_denies(self): self.before_run_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_superseding_review_before_native_launch_denies(self): self.before_run_fault(lambda: self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1))
    def test_registry_close_before_native_launch_denies(self): self.before_run_fault(lambda: self.registry.close())
    def test_gate_cancellation_before_native_launch_denies(self): self.before_run_fault(lambda: self.gate.close())
    def test_source_child_death_before_native_launch_denies(self): self.before_run_fault(lambda: self.terminate_child())

    def test_copied_descriptor_cannot_transfer_original_recipient(self):
        self.independent(lambda: self.reject(descriptor=replace(self.descriptor)))
    def test_equal_application_subclass_cannot_create_association(self):
        class Application(str): pass
        self.before_run_fault(lambda: None, app=Application('app'))

    def test_caller_holding_registry_lease_cannot_launch_native_io(self):
        def operation():
            with self.registry._lock, patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('native I/O inside authority lease')) as launch:
                self.reject(); launch.assert_not_called()
        self.independent(operation)
    def test_caller_holding_review_ledger_cannot_launch_native_io(self):
        def operation():
            with self.ledger._lock, patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('native I/O inside authority lease')) as launch:
                self.reject(); launch.assert_not_called()
        self.independent(operation)
    def test_caller_holding_review_coordinator_cannot_launch_native_io(self):
        def operation():
            with self.model._reviews._lock, patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('native I/O inside authority lease')) as launch:
                self.reject(); launch.assert_not_called()
        self.independent(operation)
    def test_caller_holding_source_native_ownership_cannot_launch_native_io(self):
        def operation():
            with self.check._issued_child._ownership_lock, patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('native I/O inside ownership lease')) as launch:
                self.reject(); launch.assert_not_called()
        self.independent(operation)

    def test_other_thread_holding_original_registry_denies_without_waiting(self):
        def operation():
            entered, release = threading.Event(), threading.Event()
            def hold():
                with self.registry._lock:
                    entered.set(); self.assertTrue(release.wait(2))
            future = self.pool.submit(hold)
            self.assertTrue(entered.wait(1))
            try:
                started = time.monotonic()
                with patch.object(process._SourceAssociationPeer, '__init__', side_effect=AssertionError('busy authority must not launch')) as launch:
                    self.reject(); launch.assert_not_called()
                self.assertLess(time.monotonic()-started, 1)
                self.assertFalse(future.done(), 'rejection cannot require release of busy authority')
                self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
            finally:
                release.set(); future.result(timeout=1)
        self.independent(operation)

    def test_revocation_after_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.registry.revoke('app'))
    def test_rotation_after_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.registry.rotate_credential('app'))
    def test_permission_change_after_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.registry.update_permissions('app', scopes=[]))
    def test_completed_concurrent_revocation_after_native_proof_withholds_retirement(self):
        self.proof_fault(lambda: self.pool.submit(self.registry.revoke, 'app').result(timeout=1))
    def test_version_change_after_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancel_after_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.gate.close())
    def test_quarantine_mutation_after_native_proof_wipes_source(self): self.proof_fault(lambda: self.retained.extend(b'x'))
    def test_copied_native_observation_cannot_replace_original_channel(self): self.proof_fault(lambda: setattr(self.gate, '_native_observation', replace(self.gate._native_observation)))
    def test_source_child_death_after_new_native_proof_withholds_retirement(self): self.proof_fault(lambda: self.terminate_child())
    def test_new_native_child_death_after_proof_withholds_retirement(self): self.proof_fault(lambda: self.terminate_new_child())
    def test_foreign_native_child_cannot_supply_retirement_or_be_closed(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.gate, '_child', foreign))
        foreign.close.assert_not_called(); foreign._validate.assert_not_called()
    def test_foreign_reservation_cannot_supply_authority_or_be_closed(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.gate, '_reservation', foreign))
        foreign.close.assert_not_called(); foreign.reserve_and_discard.assert_not_called()

    def test_native_observation_pid_mutation_cannot_redirect_recipient(self):
        self.proof_fault(lambda: object.__setattr__(self.gate._native_observation, 'pid', self.gate._native_observation.pid+1))
    def test_association_state_rollback_cannot_reopen_ready_source(self): self.proof_fault(lambda: setattr(self.gate, '_state', 'new'))
    def test_integer_started_flag_is_not_a_boolean_transition(self): self.proof_fault(lambda: setattr(self.gate, '_started', 1))
    def test_deadline_rollback_cannot_prolong_authority(self): self.proof_fault(lambda: setattr(self.gate, '_deadline', time.monotonic()+60))
    def test_deleted_origin_alias_rejects_but_recovers_only_original_cleanup(self):
        def change(): del self.gate._issued_origin
        self.proof_fault(change)
    def test_foreign_cancel_event_cannot_restore_or_cancel_original_authority(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.gate, '_cancel', foreign))
        foreign.is_set.assert_not_called(); foreign.set.assert_not_called()
    def test_foreign_native_api_is_not_invoked_or_used_for_cleanup(self):
        foreign = Mock()
        self.proof_fault(lambda: setattr(self.gate._issued_child, '_ownership', foreign))
        foreign.check.assert_not_called(); foreign.identity.assert_not_called()

    def test_native_cleanup_exception_withholds_success_and_reports_uncertainty(self):
        def operation():
            original = process._SourceAssociationPeer.close
            reached = []
            def close(child):
                original(child); reached.append(True); raise OSError('synthetic cleanup uncertainty')
            with patch.object(process._SourceAssociationPeer, 'close', close): self.reject()
            self.assertEqual(reached, [True])
            self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
            self.gate._issued_child._retired()
        self.independent(operation)

    def test_native_noop_cleanup_cannot_count_as_joined_success(self):
        def operation():
            original = process._SourceAssociationPeer.close
            with patch.object(process._SourceAssociationPeer, 'close', return_value=None): self.reject()
            self.assertFalse(self.gate.inspect()['cleanup_confirmed'])
            original(self.gate._issued_child)
            self.gate._issued_child._retired()
            self.assertIsNone(self.gate._issued_result)
        self.independent(operation)

    def test_revocation_before_original_consumption_denies(self): self.consumption_fault(lambda: self.registry.revoke('app'))
    def test_revocation_after_original_consumption_withholds_success(self): self.consumption_fault(lambda: self.registry.revoke('app'), after=True)
    def test_rotation_after_original_consumption_withholds_success(self): self.consumption_fault(lambda: self.registry.rotate_credential('app'), after=True)
    def test_cancellation_after_original_consumption_withholds_success(self): self.consumption_fault(lambda: self.gate.close(), after=True)
    def test_reintroduced_bytes_after_original_consumption_are_rejected_and_wiped(self): self.consumption_fault(lambda: self.retained.extend(self.DATA), after=True)
    def test_source_death_after_original_consumption_withholds_success(self): self.consumption_fault(lambda: self.terminate_child(), after=True)
    def test_new_peer_death_after_original_consumption_withholds_success(self): self.consumption_fault(lambda: self.terminate_new_child(), after=True)

    def test_mutated_source_reservation_result_cannot_claim_delivery(self):
        def action():
            object.__setattr__(self.gate._reservation._issued_evidence, 'released_bytes', 37)
        self.consumption_fault(action, after=True)

    def test_revocation_after_native_acknowledgment_withholds_success(self): self.ack_fault(lambda _: self.registry.revoke('app'))
    def test_rotation_after_native_acknowledgment_withholds_success(self): self.ack_fault(lambda _: self.registry.rotate_credential('app'))
    def test_version_change_after_native_acknowledgment_withholds_success(self): self.ack_fault(lambda _: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancellation_after_native_acknowledgment_withholds_success(self): self.ack_fault(lambda _: self.gate.close())
    def test_reintroduced_bytes_after_native_acknowledgment_are_rejected_and_wiped(self): self.ack_fault(lambda _: self.retained.extend(self.DATA))
    def test_ack_mutation_cannot_claim_protected_delivery(self): self.ack_fault(lambda value: object.__setattr__(value, 'released_bytes', 1))
    def test_boolean_ack_byte_count_is_rejected(self): self.ack_fault(lambda value: object.__setattr__(value, 'released_bytes', False))
    def test_changed_ack_binding_is_rejected(self): self.ack_fault(lambda value: object.__setattr__(value, 'canonical_binding', b'{}'))

    def test_revocation_after_native_join_withholds_success(self): self.joined_fault(lambda: self.registry.revoke('app'))
    def test_rotation_after_native_join_withholds_success(self): self.joined_fault(lambda: self.registry.rotate_credential('app'))
    def test_version_change_after_native_join_withholds_success(self): self.joined_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancel_after_native_join_withholds_success(self): self.joined_fault(lambda: self.gate.close())
    def test_reintroduced_bytes_after_native_join_are_rejected_and_wiped(self): self.joined_fault(lambda: self.retained.extend(self.DATA))

    def test_revocation_after_source_model_retirement_withholds_final_success(self): self.retirement_fault(lambda: self.registry.revoke('app'))
    def test_rotation_after_source_model_retirement_withholds_final_success(self): self.retirement_fault(lambda: self.registry.rotate_credential('app'))
    def test_version_change_after_source_model_retirement_withholds_final_success(self): self.retirement_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_cancel_after_source_model_retirement_withholds_final_success(self): self.retirement_fault(lambda: self.gate.close())
    def test_bytes_reintroduced_after_source_model_retirement_are_wiped(self): self.retirement_fault(lambda: self.retained.extend(self.DATA))

    def test_same_thread_revocation_during_final_archive_withholds_success(self): self.archive_fault(lambda _: self.registry.revoke('app'))
    def test_candidate_mutation_during_final_archive_withholds_success(self): self.archive_fault(lambda value: object.__setattr__(value, 'released_bytes', 37))
    def test_new_channel_mutation_during_final_archive_withholds_success(self):
        self.archive_fault(lambda _: setattr(self.gate, '_native_observation', replace(self.gate._native_observation)))
    def test_model_peer_key_restoration_during_final_archive_withholds_success(self):
        def verify():
            peer = self.gate._original().peer
            self.assertIs(type(peer._key), bytes)
            self.assertEqual(peer._key, b'')
            self.assertEqual(peer._state, 'closed')
            self.assertIs(type(peer._step), int)
            self.assertEqual(peer._step, 4)
            self.assertEqual(self.gate.inspect(), dict(state='failed', cleanup_confirmed=True, source_consumed=True))
        self.archive_fault(lambda _: setattr(self.gate._original().peer, '_key', b'r'*32), verify=verify)
    def test_native_codec_key_restoration_during_final_archive_withholds_success(self):
        captured = []
        original = SourceRecipientAssociationExchange.accept_ack
        def ack(wire, frame):
            value = original(wire, frame); captured.append(wire); return value
        def verify():
            self.assertEqual(len(captured), 1)
            wire = captured[0]
            self.assertIs(type(wire._key), bytes)
            self.assertEqual(wire._key, b'')
            self.assertEqual(wire._state, 'closed')
            self.assertIs(type(wire._step), int)
            self.assertEqual(wire._step, 4)
            self.assertEqual(self.gate.inspect(), dict(state='failed', cleanup_confirmed=True, source_consumed=True))
        with patch.object(SourceRecipientAssociationExchange, 'accept_ack', ack):
            self.archive_fault(lambda _: setattr(captured[0], '_key', b'r'*32), verify=verify)
        self.assertEqual(len(captured), 1)

    def test_terminal_state_mirror_rollback_cannot_report_a_valid_archive(self): self.terminal_field_fault('_state', lambda _: 'new')
    def test_terminal_started_mirror_rollback_cannot_report_a_valid_archive(self): self.terminal_field_fault('_started', lambda _: False)
    def test_terminal_finished_mirror_rollback_cannot_report_a_valid_archive(self): self.terminal_field_fault('_finished', lambda _: False)
    def test_terminal_source_consumed_mirror_rollback_cannot_report_a_valid_archive(self): self.terminal_field_fault('_source_consumed', lambda _: False)
    def test_terminal_cleanup_mirror_rollback_cannot_report_a_valid_archive(self): self.terminal_field_fault('_cleanup_confirmed', lambda _: False)
    def test_terminal_boolean_mirror_type_confusion_cannot_report_a_valid_archive(self): self.terminal_field_fault('_cleanup_confirmed', lambda _: 1)
    def test_terminal_history_copy_cannot_replace_original_journal(self): self.terminal_field_fault('_history', lambda old: old._replace(cleanup=False))
    def test_terminal_issued_history_copy_cannot_replace_original_journal(self): self.terminal_field_fault('_issued_history', lambda old: old._replace(state='new'))
    def test_terminal_origin_copy_cannot_replace_original_owner(self): self.terminal_field_fault('_origin', lambda old: old._replace(deadline=old.deadline+60))
    def test_terminal_deleted_origin_alias_cannot_report_a_valid_archive(self): self.terminal_field_fault('_issued_origin', lambda old: old, delete=True)
    def test_terminal_result_copy_cannot_replace_original_fact(self): self.terminal_field_fault('_result', lambda old: replace(old))

    def test_historical_archive_remains_history_after_revocation_and_never_reauthorizes(self):
        def operation():
            result = self.run_gate()
            self.registry.revoke('app')
            value = self.gate.inspect()
            self.assertEqual(value, dict(state='associated_discarded', cleanup_confirmed=True, source_consumed=True))
            self.assertEqual(result.released_bytes, 0)
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
        self.independent(operation)

    def test_extra_native_output_withholds_success_despite_valid_ack(self):
        def operation():
            with self.child_fault(ending="sys.stdout.buffer.write(b'X'); sys.stdout.buffer.flush()"):
                self.reject()
        self.independent(operation)
    def test_nonzero_native_exit_withholds_success_despite_valid_ack(self):
        def operation():
            with self.child_fault(ending='sys.exit(7)'): self.reject()
        self.independent(operation)
    def test_crash_before_native_proof_spends_and_wipes_source(self):
        def operation():
            with self.child_fault(prefix='sys.exit(7)'): self.reject()
        self.independent(operation)

    def test_each_native_read_and_write_is_outside_original_authority_leases(self):
        def operation():
            original = self.gate._reservation._original()
            locks = (original.registry_lock, original.review_ledger_lock,
                     original.reviews_lock, original.native_lock)
            original_read, original_write = association.os.read, association.os.write
            events = []
            def outside(call, *args):
                self.assertTrue(all(not lock._is_owned() for lock in locks),
                    'native transport must not wait inside original authority leases')
                events.append(call.__name__)
                return call(*args)
            with patch.object(association.os, 'read', side_effect=lambda *args: outside(original_read, *args)), \
                    patch.object(association.os, 'write', side_effect=lambda *args: outside(original_write, *args)):
                self.assertEqual(self.run_gate().released_bytes, 0)
            self.assertIn('read', events); self.assertIn('write', events)
        self.independent(operation)

    def test_mutated_historical_result_cannot_be_reported_as_fresh_or_released(self):
        def operation():
            result = self.run_gate()
            object.__setattr__(result, 'released_bytes', 37)
            with self.assertRaises(association.SourceNativeAssociationError): self.gate.inspect()
            with self.assertRaises(association.SourceNativeAssociationError): self.run_gate()
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)


if __name__ == '__main__': unittest.main()
