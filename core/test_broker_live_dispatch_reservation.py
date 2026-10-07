"""Inactive live reservation: original witness and synthetic observed bytes only.

The original fixed witness worker remains the native owner. Dispatch metadata is
exchanged with a synthetic test peer; no model visibility frame or byte payload
is sent to the native child and no delivery operation is introduced.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch

from core import broker_live_dispatch_reservation as reservation
from core import broker_publication_commit_draft as commit
from core import broker_publication_commit_protocol as commit_protocol
from core import broker_dispatch_model_protocol as model_protocol
from core import test_broker_live_channel_check as helpers
from core.broker_live_channel_check import LiveChannelCheckError
from core.broker_live_review import LiveBrokerReview
from core.broker_live_protocol import LiveMetadataExchange
from core.authority_store import SQLiteAuthorityStore
from core.broker_protocol import _canonical
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads
from core.registry import ApplicationRegistry


class LiveDispatchReservationTests(unittest.TestCase):
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
        self.commit = commit.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)
        self.addCleanup(self.commit.close)
        self.commit_peer = commit_protocol.PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(self.commit_peer.close)
        self.commit_peer.accept_prepare(self.commit.prepare())
        self.commit_ready_frame = self.commit_peer.ready()
        self.commit.accept_ready(self.commit_ready_frame)

    def create_gate(self, **options):
        self.gate = reservation.LiveDispatchReservationDryRun(self.commit, key=b'd'*32, session=b'p'*32, **options)
        self.addCleanup(self.cleanup_gate)
        self.model_peer = model_protocol.PublicationDispatchExchange(role='broker', key=b'd'*32, session=b'p'*32)
        self.addCleanup(self.model_peer.close)

    def cleanup_gate(self):
        try: self.gate.close()
        except reservation.LiveDispatchReservationError as error:
            # This explicitly injected model-binding corruption keeps reporting
            # uncertainty. It is never accepted as successful retirement.
            self.assertEqual(str(error), 'live_reservation_cleanup_failed')
            self.assertIs(getattr(self, 'expected_cleanup_uncertainty', False), True)
            original = self.gate._original()
            self.assertIs(original.model_ledger._closed, True)
            self.assertEqual(original.attempt._issued_wire._state, 'closed')
            self.assertEqual(original.attempt._issued_wire._key, b'')
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertEqual(self.retained, bytearray())

    def replace_before_gate(self, owner, name, value):
        original = getattr(owner, name)
        setattr(owner, name, value)
        return lambda: setattr(owner, name, original)

    def ready_gate(self):
        self.prepare_frame = self.gate.prepare()
        self.prepared_claim = self.model_peer.accept_prepare(self.prepare_frame)
        self.ready_frame = self.model_peer.ready()
        self.gate.accept_ready(self.ready_frame)

    def consume(self, **inputs):
        values = dict(app='app', credential=self.credential, proposal=self.proposal, descriptor=self.descriptor)
        values.update(inputs)
        return self.gate.reserve_and_discard(**values)

    def finish_original_commit(self):
        self.commit_peer.accept_dry_commit(self.gate._commit_notice)
        self.commit_receipt = self.commit_peer.receipt()
        self.commit.finish(self.commit_receipt)
        return self.gate._issued_result

    def exercise(self, *, phase=None, action=None, inputs=None, expected=True):
        self.prepare_check(); self.reached = []
        def at(name):
            if phase == name:
                self.reached.append(name); action(self.gate)
        def final(app, credential, proposal, descriptor):
            self.assertIsNotNone(self.check._proof)
            self.check._child._validate()
            self.assertEqual(bytes(self.retained), self.DATA)
            self.create_ready_commit()
            if phase == 'before_gate':
                self.reached.append('before_gate'); restore = action(self.commit)
                try: self.create_gate()
                finally:
                    if restore is not None: restore()
            else: self.create_gate()
            at('new')
            self.prepare_frame = self.gate.prepare()
            self.prepared_claim = self.model_peer.accept_prepare(self.prepare_frame)
            self.ready_frame = self.model_peer.ready()
            at('prepared'); self.gate.accept_ready(self.ready_frame)
            at('ready')
            values = dict(app=app, credential=credential, proposal=proposal, descriptor=descriptor)
            values.update(inputs or {})
            self.evidence = self.gate.reserve_and_discard(**values)
            self.assertEqual(self.retained, bytearray())
            self.check._child._validate()
            at('consumed')
            return self.finish_original_commit()
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final):
            if expected:
                result = self.check.run('app', self.credential, self.proposal, self.descriptor)
                self.assertEqual(result.released_bytes, 0)
            else:
                with self.assertRaises(LiveChannelCheckError): self.check.run('app', self.credential, self.proposal, self.descriptor)
        self.terminal()
        if phase is not None: self.assertEqual(self.reached, [phase], 'fault must reach original live witness and requested phase')

    def fault(self, phase, action): self.exercise(phase=phase, action=action, expected=False)

    def test_original_live_source_is_consumed_once_with_zero_bytes_released(self):
        self.exercise()
        self.assertIs(type(self.evidence), reservation.LiveDispatchReservationEvidence)
        self.assertEqual(self.evidence.released_bytes, 0)
        self.assertEqual(self.evidence.disposition, 'reserved_discarded')
        self.assertEqual(self.evidence.model_outcome, 'outcome_unknown')
        self.assertEqual(self.evidence.staged_bytes, 37)
        self.assertEqual(self.evidence.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertTrue(self.commit._attempted)
        self.assertEqual(self.commit._state, 'retired')
        self.assertEqual(self.retained, bytearray())
        with self.assertRaises(TypeError): bool(self.evidence)
        self.assertNotIn('data', asdict(self.evidence))

    def test_model_binding_is_derived_from_exact_original_resource_effect_and_recipient(self):
        self.exercise()
        envelope = self.prepared_claim.inspect()
        original = envelope['commit']
        self.assertEqual(original['binding'], loads(self.check._binding_snapshot))
        self.assertEqual(original['binding']['recipient'], asdict(self.descriptor))
        self.assertEqual(original['staged_bytes'], len(self.DATA))
        self.assertEqual(original['staged_digest'], hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(self.evidence.attempt_id, envelope['attempt_id'])
        self.assertEqual(self.evidence.binding_digest, hashlib.sha256(_canonical(envelope)).hexdigest())
        self.assertEqual(self.evidence.source_binding_digest, hashlib.sha256(self.check._binding_snapshot).hexdigest())
        self.assertEqual(self.evidence.recipient_digest, hashlib.sha256(_canonical(asdict(self.descriptor))).hexdigest())

    def test_inspected_model_metadata_cannot_mutate_original_binding(self):
        self.exercise()
        before = self.prepared_claim.inspect()
        before['commit']['binding']['context']['max_bytes'] = 4096
        self.assertEqual(self.prepared_claim.inspect()['commit']['binding']['context']['max_bytes'], 128)

    def test_no_read_release_authorize_or_delivery_port_exists(self):
        self.exercise()
        for name in ('read', 'write', 'acquire', 'publish', 'release', 'deliver', 'execute', 'authorize', 'data', 'allow'):
            self.assertFalse(hasattr(self.gate, name))

    def test_constructor_rejects_requester_claims_and_non_original_owners(self):
        for value in ({'approved': True}, self.lifecycle, self.descriptor, self.model):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                reservation.LiveDispatchReservationDryRun(value, key=b'd'*32, session=b'p'*32)

    def test_constructor_rejects_application_authority_without_human_review(self):
        self.observe()
        with self.assertRaises(TypeError):
            reservation.LiveDispatchReservationDryRun(self.model, key=b'd'*32, session=b'p'*32)
        self.assertIs(self.lifecycle._publication_attempted, False)

    def test_constructor_cannot_turn_human_review_evidence_into_permission(self):
        display = self.review()
        self.registry.revoke('app')
        with self.assertRaises(TypeError):
            reservation.LiveDispatchReservationDryRun(display, key=b'd'*32, session=b'p'*32)
        self.assertIs(self.lifecycle._publication_attempted, False)

    def test_success_evidence_is_not_accepted_as_a_new_original_source(self):
        self.exercise()
        with self.assertRaises(TypeError):
            reservation.LiveDispatchReservationDryRun(self.evidence, key=b'd'*32, session=b'p'*32)

    def test_wrong_credential_burns_reservation_and_original_source(self):
        self.exercise(inputs=dict(credential='wrong'), expected=False)
        with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.assertEqual(self.retained, bytearray())

    def test_oversized_credential_is_rejected(self): self.exercise(inputs=dict(credential='x'*513), expected=False)
    def test_boolean_credential_is_not_permission(self): self.exercise(inputs=dict(credential=True), expected=False)
    def test_wrong_application_cannot_transfer_source(self): self.exercise(inputs=dict(app='other'), expected=False)
    def test_equal_application_subclass_cannot_transfer_source(self):
        class Application(str): pass
        self.exercise(inputs=dict(app=Application('app')), expected=False)
    def test_copied_recipient_cannot_transfer_reservation(self): self.exercise(inputs=dict(descriptor=replace(self.descriptor)), expected=False)
    def test_requester_recipient_mapping_cannot_transfer_reservation(self): self.exercise(inputs=dict(descriptor=asdict(self.descriptor)), expected=False)
    def test_changed_proposal_or_effect_cannot_inherit_reservation(self):
        self.exercise(inputs=dict(proposal=make_file_read_proposal('changed', max_bytes=4096)), expected=False)

    def test_revocation_before_prepare_withholds_frame(self): self.fault('new', lambda _: self.registry.revoke('app'))
    def test_revocation_before_ready_withholds_acceptance(self): self.fault('prepared', lambda _: self.registry.revoke('app'))
    def test_revocation_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.registry.revoke('app'))
    def test_credential_rotation_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.registry.rotate_credential('app'))
    def test_permission_removal_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.registry.update_permissions('app', scopes=[]))
    def persistent_registry(self):
        self.lifecycle.close(); self.registry.close()
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(directory.name)/'authority.db'))
        self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', ['files.read'])
        self.grant = self.registry.get('app').grant_id
        self.assertTrue(self.registry.operator_unlock('app', self.grant))
        self.model = LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
        self.addCleanup(self.model.close)
        self.peer = LiveMetadataExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(self.peer.close)
        self.install()

    def test_application_lock_before_reservation_withholds_evidence(self):
        self.persistent_registry()
        self.fault('ready', lambda _: self.registry.lock_all())
    def test_application_lock_and_reunlock_cannot_revive_old_review(self):
        self.persistent_registry()
        def change(_):
            self.registry.lock_all()
            self.assertTrue(self.registry.operator_unlock('app', self.grant))
        self.fault('ready', change)
    def test_registry_close_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.registry.close())
    def test_draft_version_change_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.ledger.replace(self.draft.draft_id, 1, self.constraint))
    def test_superseding_review_before_reservation_withholds_evidence(self): self.fault('ready', lambda _: self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1))
    def test_registry_lookup_failure_before_reservation_fails_closed(self):
        def change(_):
            active = patch.object(self.registry, '_is_active', side_effect=OSError('registry unavailable'))
            active.start(); self.addCleanup(active.stop)
        self.fault('ready', change)

    def test_cancel_before_prepare_wipes_original_without_delivery(self): self.fault('new', lambda g: g.close())
    def test_cancel_before_reservation_wipes_original_without_delivery(self): self.fault('ready', lambda g: g.close())
    def test_duplicate_prepare_cannot_reopen_attempt(self): self.fault('prepared', lambda g: g.prepare())
    def test_ready_frame_replay_cannot_reopen_attempt(self): self.fault('ready', lambda g: g.accept_ready(self.ready_frame))
    def test_malformed_ready_frame_is_terminal(self): self.fault('prepared', lambda g: g.accept_ready(b'x'))
    def test_oversized_ready_frame_is_terminal(self): self.fault('prepared', lambda g: g.accept_ready(b'x'*9000))
    def test_wrong_domain_ready_frame_is_terminal(self): self.fault('prepared', lambda g: g.accept_ready(self.commit_ready_frame))
    def test_consumed_reservation_cannot_replay_with_valid_credentials(self): self.fault('consumed', lambda _: self.consume())
    def test_success_metadata_cannot_be_reused_after_native_worker_cleanup(self):
        self.exercise()
        with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.assertEqual(self.retained, bytearray())

    def test_successful_close_is_idempotent_without_cancelling_original_native_owner(self):
        def close(g):
            original_result, original_notice = g._issued_result, g._commit_notice
            g.close(); g.close()
            self.assertIs(g._issued_result, original_result)
            self.assertIs(g._commit_notice, original_notice)
            self.assertIs(self.check._cancelled, False)
            self.assertIs(self.check._issued_cancel.is_set(), False)
            self.check._child._validate()
            self.assertEqual(self.retained, bytearray())
        self.exercise(phase='consumed', action=close)
        self.assertTrue(self.check.shutdown_status().cleanup_confirmed)

    def test_mutated_success_evidence_cannot_be_archived_as_released_bytes(self):
        def change(g):
            original = g._issued_evidence
            object.__setattr__(original, 'released_bytes', 37)
            with self.assertRaisesRegex(reservation.LiveDispatchReservationError, '^live_reservation_cleanup_failed$'):
                g.close()
            self.assertIsNone(g._issued_evidence); self.assertIsNone(g._issued_result); self.assertIsNone(g._commit_notice)
            self.assertIsNone(g._original_history()[-1][6])
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertTrue(self.commit._attempted)
            self.assertEqual(self.retained, bytearray())
            object.__setattr__(original, 'released_bytes', 0)
            with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.fault('consumed', change)

    def test_mutated_success_result_cannot_be_resnapshotted_as_archive(self):
        def change(g):
            original = g._issued_result
            object.__setattr__(original, 'staged_bytes', 4096)
            object.__setattr__(original, 'staged_digest', 'f'*64)
            with self.assertRaisesRegex(reservation.LiveDispatchReservationError, '^live_reservation_cleanup_failed$'):
                g.close()
            self.assertIsNone(g._issued_evidence); self.assertIsNone(g._issued_result); self.assertIsNone(g._commit_notice)
            self.assertIsNone(g._original_history()[-1][3])
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertTrue(self.commit._attempted)
            self.assertEqual(self.retained, bytearray())
            object.__setattr__(original, 'staged_bytes', len(self.DATA))
            object.__setattr__(original, 'staged_digest', hashlib.sha256(self.DATA).hexdigest())
            with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.fault('consumed', change)

    def test_original_commit_cancellation_cannot_be_restored_by_gate(self): self.fault('ready', lambda _: self.commit.close())
    def test_original_helper_cancellation_cannot_be_restored_by_gate(self): self.fault('ready', lambda _: self.check.close())
    def test_original_child_death_before_reservation_fails_closed(self): self.fault('ready', lambda _: self.terminate_child())
    def test_original_quarantine_mutation_is_rejected_and_wiped(self): self.fault('ready', lambda _: self.retained.extend(b'x'))
    def test_original_proof_copy_cannot_substitute_native_witness(self): self.fault('ready', lambda _: setattr(self.check, '_proof', replace(self.check._proof)))
    def test_native_observation_mutation_cannot_transfer_child(self): self.fault('ready', lambda _: object.__setattr__(self.check._native_observation, 'pid', 1))
    def test_original_recipient_mutation_cannot_widen_effect(self): self.fault('ready', lambda _: object.__setattr__(self.descriptor, 'recipient_revision', 2))
    def test_source_deadline_extension_cannot_prolong_authority(self): self.fault('ready', lambda _: setattr(self.model, '_deadline', self.model._deadline+60))
    def test_original_commit_deadline_extension_cannot_prolong_reservation(self): self.fault('ready', lambda _: setattr(self.commit, '_deadline', self.commit._deadline+60))

    def test_invalid_lifetimes_cannot_create_or_extend_reservation(self):
        def change(_):
            for timeout in (True, 0, -1, 6, float('nan'), float('inf'), '5'):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    reservation.LiveDispatchReservationDryRun(self.commit, key=b'd'*32, session=b'p'*32, timeout=timeout)
        self.exercise(phase='new', action=change)

    def test_gate_deadline_extension_is_rejected(self): self.fault('ready', lambda g: setattr(g, '_deadline', g._deadline+60))
    def test_gate_deadline_expiry_is_rejected(self): self.fault('ready', lambda g: setattr(g, '_deadline', 0.0))
    def test_cleared_cancel_event_cannot_restore_reservation(self):
        def change(g): g.close(); g._cancel.clear()
        self.fault('ready', change)
    def test_replaced_cancel_event_cannot_restore_reservation(self): self.fault('ready', lambda g: setattr(g, '_cancel', threading.Event()))
    def test_equal_quarantine_copy_cannot_replace_original_owned_buffer(self): self.fault('ready', lambda g: setattr(g, '_owned_buffer', bytearray(self.DATA)))
    def test_deleted_issued_origin_fails_closed_and_cannot_restore_source(self):
        def change(g): del g._issued_origin
        self.fault('ready', change)
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertEqual(self.retained, bytearray())
    def test_deleted_draft_alias_fails_closed_and_cannot_restore_source(self):
        def change(g): del g._issued_draft
        self.fault('ready', change)
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertEqual(self.retained, bytearray())
    def test_foreign_draft_is_not_cleaned_as_original_owner(self):
        foreign = Mock()
        self.fault('ready', lambda g: setattr(g, '_draft', foreign))
        foreign.close.assert_not_called()
    def test_foreign_model_ledger_is_not_cleaned_as_original_owner(self):
        foreign = Mock()
        self.fault('ready', lambda g: setattr(g, '_ledger', foreign))
        foreign.close.assert_not_called()
    def test_foreign_model_attempt_cannot_supply_reservation(self):
        foreign = Mock()
        self.fault('ready', lambda g: setattr(g, '_attempt', foreign))
        foreign.inspect.assert_not_called(); foreign.close.assert_not_called()
    def test_foreign_timer_is_not_cancelled_as_original_owner(self):
        foreign = Mock()
        self.fault('ready', lambda g: setattr(g, '_timer', foreign))
        foreign.cancel.assert_not_called()
    def test_gate_state_rollback_cannot_reopen_original_source(self): self.fault('ready', lambda g: setattr(g, '_state', 'new'))
    def test_model_envelope_mutation_cannot_transfer_original_source(self):
        def change(g):
            self.expected_cleanup_uncertainty = True
            value = loads(g._attempt._envelope)
            value['commit']['binding']['context']['resource_token'] = 'f'*64
            g._attempt._envelope = _canonical(value)
        self.fault('ready', change)

    def test_forged_issued_retirement_cannot_skip_original_cleanup(self):
        self.fault('ready', lambda g: setattr(g, '_issued_status', ('retired', True, True, None, None, None, None, None)))
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertTrue(self.commit._attempted)
        self.assertEqual(self.retained, bytearray())
        with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        with self.assertRaises(Exception):
            reservation.LiveDispatchReservationDryRun(self.commit, key=b'a'*32, session=b'b'*32)
    def test_integer_attempted_flag_cannot_count_as_boolean_state(self): self.fault('ready', lambda g: setattr(g, '_attempted', 0))
    def test_integer_terminal_flag_cannot_count_as_boolean_state(self): self.fault('ready', lambda g: setattr(g, '_terminal', 0))

    def test_foreign_review_lease_is_not_invoked_or_cleaned(self):
        foreign = Mock()
        self.fault('ready', lambda _: setattr(self.model, '_lease', foreign))
        foreign.assert_not_called()
    def test_foreign_review_ledger_is_not_invoked_or_cleaned(self):
        foreign = Mock()
        self.fault('ready', lambda _: setattr(self.model, '_ledger', foreign))
        foreign.close.assert_not_called(); foreign.discard_review.assert_not_called()
    def test_foreign_review_registry_is_not_invoked_or_cleaned(self):
        foreign = Mock()
        self.fault('ready', lambda _: setattr(self.model, '_registry', foreign))
        foreign.close.assert_not_called(); foreign.authorization_guard.assert_not_called()
    def test_foreign_review_manager_is_not_invoked_or_cleaned(self):
        foreign = Mock()
        self.fault('ready', lambda _: setattr(self.model, '_reviews', foreign))
        foreign.close.assert_not_called(); foreign.discard_review.assert_not_called()
    def test_foreign_registry_lock_is_not_used_as_original_authority_lock(self):
        foreign = MagicMock()
        self.fault('ready', lambda _: setattr(self.registry, '_lock', foreign))
        foreign.__enter__.assert_not_called()

    def test_evidence_creation_cannot_claim_released_bytes(self):
        original = reservation.LiveDispatchReservationEvidence.__init__
        reached = []
        def change(_):
            def initialize(value, *args, **kwargs):
                original(value, *args, **kwargs); reached.append(True)
                object.__setattr__(value, 'released_bytes', 1)
            alteration = patch.object(reservation.LiveDispatchReservationEvidence, '__init__', initialize)
            alteration.start(); self.addCleanup(alteration.stop)
        self.fault('ready', change)
        self.assertTrue(reached, 'must reach candidate retired evidence after original consumption')
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_noop_gate_timer_cancel_withholds_success_and_wipes(self):
        def change(g):
            alteration = patch.object(g._issued_timer, 'cancel', return_value=None)
            alteration.start(); self.addCleanup(alteration.stop)
        self.fault('ready', change)
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_cleanup_error_after_model_barrier_withholds_evidence(self):
        reached = []
        def change(g):
            original = g._ledger.close
            def close():
                original(); reached.append(True); raise OSError('model cleanup uncertain')
            alteration = patch.object(g._ledger, 'close', side_effect=close)
            alteration.start(); self.addCleanup(alteration.stop)
        self.fault('ready', change)
        self.assertTrue(reached)
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_preconstructor_foreign_registry_cannot_bless_wrong_credential(self):
        foreign = Mock()
        foreign.authenticate.return_value = self.registry.get('app')
        self.fault('before_gate', lambda _: self.replace_before_gate(self.model, '_registry', foreign))
        foreign.authenticate.assert_not_called(); foreign.close.assert_not_called()
        self.assertEqual(self.retained, bytearray())

    def test_preconstructor_foreign_review_manager_ledger_is_not_invoked(self):
        foreign = Mock()
        self.fault('before_gate', lambda _: self.replace_before_gate(self.model._reviews, '_ledger', foreign))
        foreign.check_review.assert_not_called(); foreign.discard_review.assert_not_called()
        self.assertEqual(self.retained, bytearray())

    def test_preconstructor_foreign_review_manager_registry_is_not_invoked(self):
        foreign = Mock()
        self.fault('before_gate', lambda _: self.replace_before_gate(self.model._reviews, '_registry', foreign))
        foreign.authenticate.assert_not_called(); foreign.close.assert_not_called()
        self.assertEqual(self.retained, bytearray())

    def test_preconstructor_foreign_review_manager_lock_is_not_entered(self):
        foreign = MagicMock()
        self.fault('before_gate', lambda _: self.replace_before_gate(self.model._reviews, '_lock', foreign))
        foreign.__enter__.assert_not_called()
        self.assertEqual(self.retained, bytearray())

    def test_preconstructor_foreign_native_api_is_not_invoked(self):
        foreign = Mock()
        self.fault('before_gate', lambda _: self.replace_before_gate(self.check._child, '_ownership', foreign))
        foreign.check.assert_not_called(); foreign.observe.assert_not_called()
        self.assertEqual(self.retained, bytearray())

    def held_codec_lock_fault(self, phase, target):
        foreign = threading.RLock()
        entered, release, fallback = threading.Event(), threading.Event(), threading.Event()
        def hold():
            with foreign:
                entered.set(); release.wait(2)
        future = self.pool.submit(hold)
        self.assertTrue(entered.wait(1))
        def recover(): fallback.set(); release.set()
        timer = threading.Timer(1, recover); timer.daemon = True; timer.start()
        try:
            def change(_):
                if phase == 'before_gate': return self.replace_before_gate(target(), '_lock', foreign)
                setattr(target(), '_lock', foreign)
            self.fault(phase, change)
            self.assertFalse(fallback.is_set(), 'must reject captured codec lock substitution without waiting for the foreign lock')
        finally:
            release.set(); timer.cancel(); future.result(timeout=1)

    def test_held_foreign_commit_codec_lock_before_constructor_does_not_block(self):
        self.held_codec_lock_fault('before_gate', lambda: self.commit._wire)

    def test_held_foreign_model_codec_lock_after_constructor_does_not_block(self):
        self.held_codec_lock_fault('ready', lambda: self.gate._attempt._wire)

    def test_expiry_after_original_consume_withholds_model_evidence(self):
        reached, escaped = [], []
        def change(g):
            original = g._attempt.begin_model_visibility
            def begin():
                result = original(); reached.append(True); g._deadline = 0.0; return result
            alteration = patch.object(g._attempt, 'begin_model_visibility', side_effect=begin)
            alteration.start(); self.addCleanup(alteration.stop)
            original_reserve = g.reserve_and_discard
            def reserve(*args, **kwargs):
                value = original_reserve(*args, **kwargs); escaped.append(value); return value
            g.reserve_and_discard = reserve
        self.fault('ready', change)
        self.assertEqual(reached, [True]); self.assertEqual(escaped, [])
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_reintroduced_bytes_after_model_barrier_are_rejected_and_wiped(self):
        reached = []
        def change(g):
            original = g._attempt.begin_model_visibility
            def begin():
                result = original(); reached.append(True); self.retained.extend(self.DATA); return result
            alteration = patch.object(g._attempt, 'begin_model_visibility', side_effect=begin)
            alteration.start(); self.addCleanup(alteration.stop)
        self.fault('ready', change)
        self.assertEqual(reached, [True])
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_proof_substitution_after_model_barrier_withholds_evidence(self):
        reached = []
        def change(g):
            original = g._attempt.begin_model_visibility
            def begin():
                result = original(); reached.append(True); self.check._proof = replace(self.check._proof); return result
            alteration = patch.object(g._attempt, 'begin_model_visibility', side_effect=begin)
            alteration.start(); self.addCleanup(alteration.stop)
        self.fault('ready', change)
        self.assertEqual(reached, [True])

    def independent(self, operation):
        """Pause original native worker after proof outside authority leases.

        The gate uses its own current leases on the caller thread. The unchanged
        old worker must subsequently reject its consumed source, then join/clean
        its own native child; no new host route is supplied by these tests.
        """
        self.prepare_check(); entered, resume = threading.Event(), threading.Event()
        original = self.check._native_current
        def native():
            original()
            if self.check._proof is not None and self.check._state == 'prepared' and not entered.is_set():
                self.check._state = 'witnessed'
                entered.set()
                if not resume.wait(3): raise LiveChannelCheckError('test_pause_timeout')
        with patch.object(self.check, '_native_current', side_effect=native):
            future = self.pool.submit(self.check.run, 'app', self.credential, self.proposal, self.descriptor)
            try:
                self.assertTrue(entered.wait(2), 'must reach genuine original proof without a held authority lease')
                self.create_ready_commit(); self.create_gate(); self.ready_gate()
                operation()
            finally:
                resume.set()
                with self.assertRaises(LiveChannelCheckError): future.result(timeout=3)
        self.terminal()
        self.assertTrue(self.check.shutdown_status().cleanup_confirmed)

    def test_independent_reservation_uses_own_fresh_authority_lease(self):
        def operation():
            value = self.consume()
            self.assertEqual((value.released_bytes, value.disposition), (0, 'reserved_discarded'))
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_completed_concurrent_revocation_before_reservation_denies(self):
        def operation():
            self.pool.submit(self.registry.revoke, 'app').result(timeout=1)
            with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_completed_concurrent_cancellation_before_reservation_denies(self):
        def operation():
            self.pool.submit(self.gate.close).result(timeout=1)
            with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.independent(operation)

    def test_authority_guard_failure_under_independent_lease_denies(self):
        def operation():
            with patch.object(self.registry, 'authorization_guard', side_effect=OSError('guard unavailable')):
                with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
        self.independent(operation)

    def test_held_original_review_manager_lock_denies_without_waiting(self):
        def operation():
            manager, original_lock = self.model._reviews, self.model._reviews._lock
            acquired, release, fallback = threading.Event(), threading.Event(), threading.Event()
            def hold():
                with original_lock:
                    acquired.set(); release.wait(2)
            future = self.pool.submit(hold)
            self.assertTrue(acquired.wait(1))
            def recover(): fallback.set(); release.set()
            timer = threading.Timer(1, recover); timer.daemon = True; timer.start()
            try:
                with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
                self.assertFalse(fallback.is_set(), 'busy original manager must deny before the safety release')
                self.assertFalse(future.done(), 'the original manager remains owned by the other thread')
                self.assertIs(manager._lock, original_lock)
                self.assertTrue(self.lifecycle._publication_attempted)
                self.assertTrue(self.commit._attempted)
                self.assertIsNone(self.gate._issued_evidence)
                self.assertEqual(self.retained, bytearray())
            finally:
                release.set(); timer.cancel(); future.result(timeout=1)
        self.independent(operation)

    def test_manager_to_registry_inversion_denies_without_deadlocking_original_lease(self):
        def operation():
            manager_lock, registry_lock = self.model._reviews._lock, self.registry._lock
            acquired, waiting, acquired_registry, fallback = (threading.Event() for _ in range(4))
            def contend():
                with manager_lock:
                    acquired.set(); waiting.set()
                    if not registry_lock.acquire(timeout=1):
                        fallback.set(); return
                    try: acquired_registry.set()
                    finally: registry_lock.release()
            with self.model._lease():
                future = self.pool.submit(contend)
                self.assertTrue(acquired.wait(1)); self.assertTrue(waiting.wait(1))
                with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
                self.assertFalse(fallback.is_set(), 'reservation must reject before the inversion safety timeout')
                self.assertFalse(acquired_registry.is_set(), 'the main thread still owns the original authority lease')
                self.assertFalse(future.done(), 'the contending manager owner must still wait for that lease')
                self.assertIs(self.registry._lock, registry_lock)
                self.assertIs(self.model._reviews._lock, manager_lock)
                self.assertTrue(self.lifecycle._publication_attempted)
                self.assertTrue(self.commit._attempted)
                self.assertIsNone(self.gate._issued_evidence)
                self.assertEqual(self.retained, bytearray())
            future.result(timeout=1)
            self.assertTrue(acquired_registry.is_set(), 'only releasing the original lease lets the other thread complete')
        self.independent(operation)

    def test_revocation_during_original_consume_waits_for_locked_boundary(self):
        def operation():
            started = threading.Event(); futures = []
            original = self.lifecycle._shutdown
            def revoke(): started.set(); self.registry.revoke('app')
            def shutdown():
                futures.append(self.pool.submit(revoke))
                self.assertTrue(started.wait(1))
                self.assertFalse(futures[0].done(), 'revocation must wait for the original authority lease')
                original()
            with patch.object(self.lifecycle, '_shutdown', side_effect=shutdown): value = self.consume()
            self.assertEqual(value.released_bytes, 0)
            futures[0].result(timeout=1)
            with self.assertRaises(commit.PublicationCommitError): self.finish_original_commit()
            with self.assertRaises(reservation.LiveDispatchReservationError): self.consume()
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_original_source_cannot_be_consumed_by_two_ready_gates(self):
        def operation():
            other = reservation.LiveDispatchReservationDryRun(self.commit, key=b'a'*32, session=b'b'*32)
            self.addCleanup(other.close)
            other_peer = model_protocol.PublicationDispatchExchange(role='broker', key=b'a'*32, session=b'b'*32)
            self.addCleanup(other_peer.close)
            other_peer.accept_prepare(other.prepare()); other.accept_ready(other_peer.ready())
            self.consume()
            with self.assertRaises(reservation.LiveDispatchReservationError):
                other.reserve_and_discard('app', self.credential, self.proposal, self.descriptor)
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)


if __name__ == '__main__': unittest.main()
