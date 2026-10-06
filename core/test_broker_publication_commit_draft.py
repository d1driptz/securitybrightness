"""Inactive dry commit: real original Windows witness, synthetic commit peer.

Resource reports and operator decisions reuse model-test orchestration. Commit
frames never travel to the native peer, and no protected bytes are delivered.
"""
from dataclasses import replace
import threading
import unittest
from unittest.mock import Mock, patch
from core import broker_publication_commit_draft as draft
from core import broker_publication_commit_protocol as protocol
from core import test_broker_live_channel_check as helpers
from core.broker_live_channel_check import LiveChannelCheckError
from core.broker_protocol import _canonical
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class PublicationCommitDraftTests(unittest.TestCase):
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

    def exercise(self, *, phase=None, action=None, inputs=None, expected=True):
        self.prepare_check(); self.reached = []
        def final(app, credential, proposal, descriptor):
            self.assertIsNotNone(self.check._proof)
            self.check._child._validate()
            self.assertEqual(bytes(self.retained), self.DATA)
            self.draft = draft.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)
            self.addCleanup(self.draft.close)
            self.peer = protocol.PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
            self.addCleanup(self.peer.close)
            def at(name):
                if phase == name:
                    self.reached.append(name); action(self.draft)
            at('new')
            self.prepare_frame = self.draft.prepare()
            self.peer.accept_prepare(self.prepare_frame)
            self.ready_frame = self.peer.ready()
            at('prepared'); self.draft.accept_ready(self.ready_frame)
            at('ready')
            values = dict(app=app, credential=credential, proposal=proposal, descriptor=descriptor)
            values.update(inputs or {})
            self.notice = self.draft.commit(**values)
            self.assertEqual(self.retained, bytearray())
            self.check._child._validate()
            at('consumed'); self.peer.accept_dry_commit(self.notice)
            self.receipt_frame = self.peer.receipt()
            at('receipt'); self.evidence = self.draft.finish(self.receipt_frame)
            return self.draft._issued_result  # Trusted test composition, not a public capability API.
        with patch.object(self.lifecycle.coordinator, 'check_publication', side_effect=final):
            if expected:
                result = self.check.run('app', self.credential, self.proposal, self.descriptor)
                self.assertEqual(result.released_bytes, 0)
            else:
                with self.assertRaises(LiveChannelCheckError): self.check.run('app', self.credential, self.proposal, self.descriptor)
        self.terminal()
        if phase is not None: self.assertEqual(self.reached, [phase], 'must reach valid original native witness and requested phase')

    def fault(self, phase, action): self.exercise(phase=phase, action=action, expected=False)

    def test_live_original_channel_and_exact_quarantine_are_consumed_once_without_delivery(self):
        self.exercise()
        self.assertEqual(self.evidence.released_bytes, 0)
        self.assertEqual(self.evidence.outcome, 'dry_run_retired')
        envelope = self.evidence.inspect()
        self.assertEqual(envelope['binding'], loads(self.check._binding_snapshot))
        self.assertEqual(envelope['staged_bytes'], 37)
        self.assertEqual(envelope['channel']['pid'], self.check._native_observation.pid)
        self.assertTrue(self.lifecycle._publication_attempted)
        self.assertTrue(self.draft._attempted)
        self.assertEqual(self.draft._state, 'retired')
        with self.assertRaises(TypeError): bool(self.evidence)
        for name in ('publish', 'deliver', 'read', 'release', 'reserve', 'authorize', 'data'):
            self.assertFalse(hasattr(self.draft, name))

    def test_constructor_requires_exact_live_witness_owner(self):
        for value in (self.lifecycle, self.descriptor, {'trusted': True}):
            with self.assertRaises(TypeError): draft.PublicationCommitDraft(value, key=b'k'*32, session=b's'*32)

    def test_prepared_or_retired_helper_cannot_create_commit_authority(self):
        self.prepare_check()
        with self.assertRaises(Exception): draft.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)
        self.check.close(); self.terminal()
        with self.assertRaises(Exception): draft.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)

    def test_no_review_or_authority_can_be_manufactured_by_constructor_data(self):
        self.prepare_check()
        for timeout in (True, 0, -1, 6, float('nan'), float('inf'), '5'):
            with self.assertRaises(ValueError): draft.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32, timeout=timeout)
        self.check.close(); self.terminal()

    def test_wrong_credential_burns_attempt(self):
        self.exercise(inputs=dict(credential='wrong'), expected=False)
        self.assertTrue(self.draft._attempted)
        with self.assertRaises(draft.PublicationCommitError): self.draft.commit('app', self.credential, self.proposal, self.descriptor)

    def test_oversized_credential_burns_attempt(self): self.exercise(inputs=dict(credential='x'*513), expected=False)
    def test_boolean_credential_burns_attempt(self): self.exercise(inputs=dict(credential=True), expected=False)
    def test_wrong_application_cannot_transfer_commit(self): self.exercise(inputs=dict(app='other'), expected=False)
    def test_copied_recipient_cannot_transfer_commit(self): self.exercise(inputs=dict(descriptor=replace(self.descriptor)), expected=False)
    def test_changed_resource_or_effect_cannot_inherit_commit(self):
        self.exercise(inputs=dict(proposal=make_file_read_proposal('changed', max_bytes=4096)), expected=False)

    def test_revocation_after_prepare_withholds_ready(self): self.fault('prepared', lambda _: self.registry.revoke('app'))
    def test_revocation_before_commit_withholds_notice(self): self.fault('ready', lambda _: self.registry.revoke('app'))
    def test_revocation_after_consumption_withholds_receipt(self): self.fault('consumed', lambda _: self.registry.revoke('app'))
    def test_rotation_before_commit_withholds_notice(self): self.fault('ready', lambda _: self.registry.rotate_credential('app'))
    def test_scope_change_before_commit_withholds_notice(self): self.fault('ready', lambda _: self.registry.update_permissions('app', scopes=[]))
    def test_draft_change_before_commit_withholds_notice(self): self.fault('ready', lambda _: self.ledger.replace(self.draft_source_id(), 1, self.constraint))
    def draft_source_id(self): return self.model._ticket.review.draft_id
    def test_superseding_review_before_commit_withholds_notice(self):
        self.fault('ready', lambda _: self.ledger.begin_review('app', self.proposal, self.draft_source_id(), 1))

    def test_cancel_before_prepare_wipes_and_aborts_original_worker(self): self.fault('new', lambda d: d.close())
    def test_cancel_before_commit_wipes_and_aborts_original_worker(self): self.fault('ready', lambda d: d.close())
    def test_cancel_after_consumption_cannot_restore_source(self): self.fault('consumed', lambda d: d.close())
    def test_cleared_cancel_event_cannot_restore_commit(self):
        def change(d): d.close(); d._cancel.clear()
        self.fault('ready', change)
    def test_replaced_cancel_event_cannot_restore_commit(self): self.fault('ready', lambda d: setattr(d, '_cancel', threading.Event()))
    def test_extended_deadline_cannot_prolong_commit(self): self.fault('ready', lambda d: setattr(d, '_deadline', d._deadline+60))
    def test_expired_deadline_cannot_commit(self): self.fault('ready', lambda d: setattr(d, '_deadline', 0.0))
    def test_foreign_timer_is_not_cancelled_as_owned(self):
        foreign = Mock()
        self.fault('ready', lambda d: setattr(d, '_timer', foreign)); foreign.cancel.assert_not_called()

    def test_duplicate_prepare_is_terminal(self): self.fault('prepared', lambda d: d.prepare())
    def test_ready_replay_is_terminal(self): self.fault('ready', lambda d: d.accept_ready(self.ready_frame))
    def test_consumed_commit_cannot_replay_even_with_valid_credentials(self):
        self.fault('consumed', lambda d: d.commit('app', self.credential, self.proposal, self.descriptor))
    def test_final_receipt_cannot_restore_any_later_operation(self):
        self.exercise()
        with self.assertRaises(draft.PublicationCommitError): self.draft.finish(self.receipt_frame)
        self.assertEqual(self.retained, bytearray())
        self.assertTrue(self.lifecycle._publication_attempted)

    def test_changed_commit_id_is_rejected(self):
        def change(d):
            value = loads(d._envelope); value['commit_id'] = 'f'*64; d._envelope = _canonical(value)
        self.fault('new', change)
    def test_foreign_source_does_not_dispatch_cleanup(self):
        foreign = Mock()
        self.fault('ready', lambda d: setattr(d, '_source', foreign)); foreign.close.assert_not_called()
    def test_buffer_copy_cannot_replace_original_quarantine(self): self.fault('ready', lambda d: setattr(d, '_buffer', bytearray(self.DATA)))
    def test_mutated_quarantine_before_commit_is_rejected(self): self.fault('ready', lambda _: self.retained.extend(b'x'))
    def test_reinserted_bytes_after_consumption_are_rejected_and_wiped(self): self.fault('consumed', lambda _: self.retained.extend(self.DATA))
    def test_replaced_commit_codec_is_terminal(self): self.fault('ready', lambda d: setattr(d, '_wire', {'allow': True}))
    def test_native_channel_death_before_commit_is_rejected(self): self.fault('ready', lambda _: self.terminate_child())
    def test_native_channel_death_after_consumption_is_rejected(self): self.fault('consumed', lambda _: self.terminate_child())
    def test_native_observation_mutation_before_commit_is_rejected(self):
        self.fault('ready', lambda _: object.__setattr__(self.check._native_observation, 'pid', 1))
    def test_changed_original_proof_is_rejected(self): self.fault('ready', lambda _: setattr(self.check, '_proof', replace(self.check._proof)))
    def test_receipt_malformed_or_wrong_domain_is_terminal(self): self.fault('receipt', lambda d: d.finish(self.ready_frame))
    def test_copied_final_result_cannot_be_sealed_as_original(self): self.fault('consumed', lambda d: setattr(d, '_result', replace(d._result)))
    def test_false_release_in_final_result_is_rejected(self): self.fault('consumed', lambda d: object.__setattr__(d._result, 'released_bytes', 1))
    def test_cleanup_timer_failure_still_wipes_and_withholds_success(self):
        def change(d): d._issued_timer.cancel = Mock(side_effect=OSError('timer cleanup failed'))
        self.fault('receipt', change)
        # Restore only test cleanup, after rejection and original worker join.
        self.draft._issued_timer.cancel = lambda: None

    def independent(self, operation):
        """Pause the original worker AFTER proof, outside all authority locks.

        The contract is tested on the caller thread under its own fresh leases.
        The old dry-run worker subsequently rejects the already-consumed source;
        that is expected test orchestration, not a new production host profile.
        """
        self.prepare_check(); entered, resume = threading.Event(), threading.Event()
        original = self.check._native_current
        def native():
            original()
            if self.check._proof is not None and self.check._state == 'prepared' and not entered.is_set():
                self.check._state = 'witnessed'  # The immediately following original transition.
                entered.set()
                if not resume.wait(3): raise LiveChannelCheckError('test_pause_timeout')
        with patch.object(self.check, '_native_current', side_effect=native):
            future = self.pool.submit(self.check.run, 'app', self.credential, self.proposal, self.descriptor)
            try:
                self.assertTrue(entered.wait(2), 'must have real proof without a held authority lease')
                self.draft = draft.PublicationCommitDraft(self.check, key=b'k'*32, session=b's'*32)
                self.addCleanup(self.draft.close)
                self.peer = protocol.PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
                self.addCleanup(self.peer.close)
                self.peer.accept_prepare(self.draft.prepare())
                self.draft.accept_ready(self.peer.ready())
                operation()
            finally:
                resume.set()
                with self.assertRaises(LiveChannelCheckError): future.result(timeout=3)
        self.terminal()
        self.assertTrue(self.check.shutdown_status().cleanup_confirmed)

    def consume_independent(self):
        notice = self.draft.commit('app', self.credential, self.proposal, self.descriptor)
        self.peer.accept_dry_commit(notice)
        return self.peer.receipt()

    def test_independent_draft_uses_its_own_authority_lease(self):
        def operation():
            result = self.draft.finish(self.consume_independent())
            self.assertEqual(result.released_bytes, 0)
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_concurrent_revocation_completed_before_commit_denies_and_wipes(self):
        def operation():
            self.pool.submit(self.registry.revoke, 'app').result(timeout=1)
            with self.assertRaises(draft.PublicationCommitError): self.consume_independent()
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_revocation_during_consume_serializes_then_invalidates_receipt(self):
        def operation():
            started = threading.Event(); futures = []
            original = self.lifecycle._shutdown
            def revoke(): started.set(); self.registry.revoke('app')
            def shutdown():
                futures.append(self.pool.submit(revoke))
                self.assertTrue(started.wait(1))
                self.assertFalse(futures[0].done(), 'revocation must wait for dry boundary lease')
                original()
            with patch.object(self.lifecycle, '_shutdown', side_effect=shutdown): frame = self.consume_independent()
            futures[0].result(timeout=1)
            with self.assertRaises(draft.PublicationCommitError): self.draft.finish(frame)
            self.assertTrue(self.lifecycle._publication_attempted)
            self.assertEqual(self.retained, bytearray())
        self.independent(operation)

    def test_concurrent_cancellation_completed_before_commit_denies(self):
        def operation():
            self.pool.submit(self.draft.close).result(timeout=1)
            with self.assertRaises(draft.PublicationCommitError): self.consume_independent()
        self.independent(operation)

    def test_two_drafts_cannot_consume_original_authority_twice(self):
        def operation():
            other = draft.PublicationCommitDraft(self.check, key=b'x'*32, session=b'z'*32)
            self.addCleanup(other.close)
            peer = protocol.PublicationCommitExchange(role='broker', key=b'x'*32, session=b'z'*32)
            self.addCleanup(peer.close)
            peer.accept_prepare(other.prepare()); other.accept_ready(peer.ready())
            frame = self.consume_independent()
            with self.assertRaises(draft.PublicationCommitError): other.commit('app', self.credential, self.proposal, self.descriptor)
            # An attempted second owner also cancels the first; it cannot retain
            # a successful receipt after the ownership interference.
            with self.assertRaises(draft.PublicationCommitError): self.draft.finish(frame)
            self.assertTrue(self.lifecycle._publication_attempted)
        self.independent(operation)

    def test_registry_guard_failure_under_own_lease_denies(self):
        def operation():
            with patch.object(self.registry, 'authorization_guard', side_effect=OSError('unavailable')):
                with self.assertRaises(draft.PublicationCommitError): self.consume_independent()
        self.independent(operation)

    def test_reentrant_envelope_mutation_during_native_query_withholds_prepare(self):
        escaped, rejected = [], []
        def change(d):
            original = self.check._native_current
            original_prepare = d.prepare
            fired = []
            def native():
                original()
                if d._state == 'prepared' and not fired:
                    fired.append(True)
                    value = loads(d._envelope); value['commit_id'] = 'f'*64; d._envelope = _canonical(value)
            def prepare():
                try:
                    value = original_prepare(); escaped.append(value); return value
                except draft.PublicationCommitError:
                    rejected.append(True); raise
            d.prepare = prepare
            d.native_patch = patch.object(self.check, '_native_current', side_effect=native)
            d.native_patch.start(); self.addCleanup(d.native_patch.stop)
        self.fault('new', change)
        self.assertEqual(escaped, [], 'no frame may escape after final native validation mutates its binding')
        self.assertEqual(rejected, [True])

    def test_proof_substitution_during_post_consume_native_query_withholds_notice(self):
        escaped, rejected, fired = [], [], []
        def change(d):
            original = self.check._native_current
            original_commit = d.commit
            def native():
                original()
                if d._state == 'consumed' and not fired:
                    fired.append(True)
                    self.assertEqual(self.retained, bytearray())
                    self.check._proof = replace(self.check._proof)
            def commit(*args, **kwargs):
                try:
                    value = original_commit(*args, **kwargs); escaped.append(value); return value
                except draft.PublicationCommitError:
                    rejected.append(True); raise
            d.commit = commit
            native_patch = patch.object(self.check, '_native_current', side_effect=native)
            native_patch.start(); self.addCleanup(native_patch.stop)
        self.fault('ready', change)
        self.assertEqual(fired, [True])
        self.assertEqual(escaped, [], 'post-consumption native validation must not hide proof substitution')
        self.assertEqual(rejected, [True])


if __name__ == '__main__': unittest.main()
