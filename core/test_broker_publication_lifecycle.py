"""Inactive final-check tests: synthetic authenticated bytes, no delivery or I/O."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core import broker_publication_lifecycle as publication
from core import test_broker_live_review as helpers
from core.authority_store import SQLiteAuthorityStore
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_live_review import LiveBrokerReview, RetiredMappedReview
from core.broker_protocol import _canonical
from core.broker_publication_protocol import PublicationCheckExchange
from core.broker_publication_recipient import LogicalPublicationRecipient
from core.broker_quarantine import QuarantinedReadExchange
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry


class LivePublicationDraftTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.install()

    def install(self, recipient_app='app'):
        self.acquisition = AcquisitionDraft(self.model)
        self.addCleanup(self.acquisition.close)
        self.recipient = LogicalPublicationRecipient(recipient_app)
        self.addCleanup(self.recipient.close)
        self.descriptor = self.recipient.descriptor
        self.lifecycle = publication.LivePublicationDraft(self.acquisition, self.recipient)
        self.addCleanup(self.lifecycle.close)
        self.quarantine_peer = PublicationCheckExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(self.quarantine_peer.close)

    def begin(self): return helpers.LiveReviewMappingTests.begin(self)
    def observe(self): return helpers.LiveReviewMappingTests.observe(self)
    def review(self, answer='ALLOW ONCE'): return helpers.LiveReviewMappingTests.review(self, answer)

    def reserve(self):
        self.review()
        return self.lifecycle.coordinator.reserve()

    def start(self, token=None, **overrides):
        token = self.reserve() if token is None else token
        values = dict(app='app', credential=self.credential, proposal=self.proposal)
        values.update(overrides)
        self.acquisition_frame = self.lifecycle.adapter.begin(token, **values)
        self.request_evidence = self.quarantine_peer.accept_request(self.acquisition_frame)
        return token

    def stage(self):
        self.start()
        self.staging_frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        return self.lifecycle.adapter.stage(self.staging_frame)

    def retirement(self):
        self.stage()
        self.quarantine_peer.accept_retirement(self.lifecycle.adapter.retire())
        self.ack = self.quarantine_peer.acknowledge_retirement()
        return self.lifecycle.adapter.confirm_retirement(self.ack)

    def final_check(self, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal,
                      recipient=self.descriptor)
        values.update(overrides)
        return self.lifecycle.coordinator.check_publication(**values)

    def terminal(self):
        self.assertEqual(self.model._state, 'closed')
        self.assertIs(self.recipient._terminal, True)
        self.assertEqual(self.recipient._state, 'closed')
        self.assertIsNone(self.recipient._claim)
        if self.lifecycle._wire is not None:
            self.assertEqual(self.lifecycle._wire._buffer, bytearray())
        if self.lifecycle._owned_buffer is not None:
            self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        with self.assertRaises(publication.PublicationLifecycleError): self.final_check()

    def reject(self, operation):
        with self.assertRaises(publication.PublicationLifecycleError): operation()
        self.terminal()

    def cleanup_hook(self, action):
        original = self.model._reviews.discard_review
        attempted = [False]
        def discard(ticket):
            original(ticket)
            if not attempted[0]:
                attempted[0] = True
                action()
        return patch.object(self.model._reviews, 'discard_review', side_effect=discard)

    def test_retained_quarantine_survives_ack_until_separate_terminal_dry_run(self):
        app = self.registry.get('app')
        receipt = self.retirement()
        self.assertEqual(bytes(self.lifecycle._wire._buffer), self.DATA)
        self.assertEqual(self.lifecycle._wire._state, 'retired_for_check')
        self.assertEqual(self.lifecycle._wire._key, b'')
        self.assertNotEqual(self.model._state, 'closed')
        self.assertTrue(self.model._reviews.check_review(self.model._ticket, 'app', self.proposal).current)
        self.assertEqual(receipt.released_bytes, 0)
        self.assertNotIn('data', asdict(receipt))
        result = self.final_check()
        self.assertEqual(result.disposition, 'eligible_discarded')
        self.assertEqual(result.released_bytes, 0)
        self.assertEqual(result.staged_bytes, len(self.DATA))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(result.recipient_digest, hashlib.sha256(_canonical(asdict(self.descriptor))).hexdigest())
        self.assertEqual(result.binding_digest, receipt.binding_digest)
        self.assertIs(self.registry.get('app'), app)
        for value in (self.descriptor, receipt, result):
            self.assertNotIn('data', asdict(value))
            with self.assertRaises(TypeError): bool(value)
        self.terminal()

    def test_wire_context_binds_distinct_trusted_recipient_and_original_proposal(self):
        self.start()
        binding = self.request_evidence.inspect()
        self.assertEqual(set(binding), {'context', 'recipient'})
        self.assertEqual(binding['recipient'], asdict(self.descriptor))
        self.assertEqual(binding['context']['application_id'], 'app')
        self.assertEqual(binding['context']['recipient'], 'requesting_application')
        self.assertEqual(binding['context']['proposal_id'], self.model._shown.proposal_id)
        self.assertEqual(binding['context']['max_bytes'], 128)
        binding['recipient']['recipient_id'] = 'f'*64
        self.assertEqual(self.request_evidence.inspect()['recipient'], asdict(self.descriptor))

    def test_requester_mapping_or_retired_review_is_not_live_acquisition(self):
        for value in ({'approved': True}, RetiredMappedReview(b'{}', 'allow_once'), self.model):
            with self.subTest(type=type(value).__name__), self.assertRaises(TypeError):
                publication.LivePublicationDraft(value, self.recipient)

    def test_requester_recipient_mapping_or_descriptor_is_not_trusted_owner(self):
        for value in (asdict(self.descriptor), self.descriptor, {'approved': True}):
            with self.subTest(type=type(value).__name__), self.assertRaises(TypeError):
                publication.LivePublicationDraft(self.acquisition, value)

    def test_application_authority_without_human_review_cannot_reserve(self):
        self.observe()
        self.reject(self.lifecycle.coordinator.reserve)

    def test_human_deny_cannot_reserve_even_with_application_authority(self):
        self.review('DENY')
        self.reject(self.lifecycle.coordinator.reserve)

    def test_human_review_after_revocation_cannot_reserve(self):
        self.review(); self.registry.revoke('app')
        self.reject(self.lifecycle.coordinator.reserve)

    def test_recipient_application_substitution_cannot_reserve(self):
        self.lifecycle.close()
        self.model = LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
        self.addCleanup(self.model.close)
        from core.broker_live_protocol import LiveMetadataExchange
        self.peer = LiveMetadataExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(self.peer.close)
        self.install('other')
        self.reject(self.reserve)

    def test_recipient_closed_after_review_cannot_reserve(self):
        self.review(); self.recipient.close()
        self.reject(self.lifecycle.coordinator.reserve)

    def test_reservation_copy_or_mutation_burns_acquisition_slot(self):
        token = self.reserve()
        self.reject(lambda: self.start(replace(token)))
        self.assertIs(self.acquisition._attempted, True)

    def test_wrong_credential_begin_burns_acquisition_and_recipient(self):
        token = self.reserve()
        self.reject(lambda: self.start(token, credential='incorrect'))
        self.assertIs(self.acquisition._attempted, True)

    def test_changed_effect_or_proposal_cannot_begin(self):
        token = self.reserve()
        self.reject(lambda: self.start(token, proposal=make_file_read_proposal('changed', max_bytes=4096)))

    def test_recipient_revision_changed_after_reservation_is_terminal(self):
        token = self.reserve(); object.__setattr__(self.descriptor, 'recipient_revision', 2)
        self.reject(lambda: self.start(token))

    def test_begin_replay_is_terminal(self):
        token = self.start()
        self.reject(lambda: self.start(token))

    def test_requester_supplied_bytes_or_observation_dictionary_cannot_stage(self):
        self.start()
        self.reject(lambda: self.lifecycle.adapter.stage({'data': self.DATA, 'approved': True}))

    def test_fabricated_adapter_frame_cannot_stage(self):
        self.start()
        with patch.object(self.quarantine_peer, '_mac', return_value=b'x'*32):
            frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_old_discard_only_profile_cannot_supply_staged_bytes(self):
        self.start()
        peer = QuarantinedReadExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(peer.close)
        binding = self.request_evidence.inspect()['context']
        coordinator = QuarantinedReadExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(coordinator.close)
        peer.accept_request(coordinator.request(binding))
        self.reject(lambda: self.lifecycle.adapter.stage(peer.reply(outcome='staged', data=self.DATA)))

    def test_signed_staging_cannot_add_authority_fields(self):
        self.start()
        message = dict(binding_digest=self.quarantine_peer._binding_digest,
                       outcome='staged', data=base64.b64encode(self.DATA).decode(), allow_once=True)
        self.reject(lambda: self.lifecycle.adapter.stage(self.quarantine_peer._frame('reply', message)))

    def test_malformed_oversized_staging_frame_is_terminal(self):
        self.start()
        self.reject(lambda: self.lifecycle.adapter.stage(b'x'*9000))

    def test_adapter_denial_is_not_final_publication_evidence(self):
        self.start()
        self.reject(lambda: self.lifecycle.adapter.stage(self.quarantine_peer.reply(outcome='denied')))

    def test_staging_replay_discards_private_buffer(self):
        self.stage()
        self.reject(lambda: self.lifecycle.adapter.stage(self.staging_frame))

    def test_registry_revoked_between_begin_and_staging_prevents_acceptance(self):
        self.start(); self.registry.revoke('app')
        frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_registry_rotation_between_staging_and_retirement_discards_bytes(self):
        self.stage(); self.registry.rotate_credential('app')
        self.reject(self.lifecycle.adapter.retire)

    def test_registry_failure_between_retirement_request_and_ack_is_terminal(self):
        self.stage()
        self.quarantine_peer.accept_retirement(self.lifecycle.adapter.retire())
        ack = self.quarantine_peer.acknowledge_retirement()
        self.registry._failed = True
        self.reject(lambda: self.lifecycle.adapter.confirm_retirement(ack))

    def test_missing_registry_application_after_ack_cannot_publish(self):
        self.retirement(); self.registry._applications.pop('app')
        self.reject(self.final_check)

    def test_draft_revocation_between_staging_and_retirement_discards_bytes(self):
        self.stage(); self.ledger.revoke(self.draft.draft_id, 1)
        self.reject(self.lifecycle.adapter.retire)

    def test_recipient_cancellation_during_signed_staging_discards_bytes(self):
        self.start(); original = self.lifecycle._wire.accept_reply
        def accept(frame):
            result = original(frame); self.recipient.close(); return result
        frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        with patch.object(self.lifecycle._wire, 'accept_reply', side_effect=accept):
            self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_registry_revocation_during_signed_ack_discards_retained_bytes(self):
        self.stage()
        self.quarantine_peer.accept_retirement(self.lifecycle.adapter.retire())
        ack = self.quarantine_peer.acknowledge_retirement()
        original = self.lifecycle._wire.accept_retirement_ack
        def accept(frame):
            result = original(frame); self.registry.revoke('app'); return result
        with patch.object(self.lifecycle._wire, 'accept_retirement_ack', side_effect=accept):
            self.reject(lambda: self.lifecycle.adapter.confirm_retirement(ack))

    def test_mutation_of_staged_summary_cannot_widen_bound(self):
        summary = self.stage(); object.__setattr__(summary, 'staged_bytes', 4096)
        self.reject(self.lifecycle.adapter.retire)

    def test_copied_staged_summary_loses_issuance_identity(self):
        summary = self.stage(); self.lifecycle._summary = replace(summary)
        self.reject(self.lifecycle.adapter.retire)

    def test_buffer_mutation_before_retirement_is_terminal(self):
        self.stage(); self.lifecycle._wire._buffer[0] ^= 1
        self.reject(self.lifecycle.adapter.retire)

    def test_equal_buffer_replacement_after_ack_is_terminal_and_original_is_wiped(self):
        self.retirement(); original = self.lifecycle._wire._buffer
        self.lifecycle._wire._buffer = bytearray(original)
        self.reject(self.final_check)
        self.assertEqual(original, bytearray())

    def test_buffer_mutation_after_ack_is_terminal(self):
        self.retirement(); self.lifecycle._wire._buffer[0] ^= 1
        self.reject(self.final_check)

    def test_missing_cleanup_ack_cannot_trigger_final_check(self):
        self.stage(); self.lifecycle.adapter.retire()
        self.reject(self.final_check)

    def test_cleanup_ack_replay_is_terminal(self):
        self.retirement()
        self.reject(lambda: self.lifecycle.adapter.confirm_retirement(self.ack))

    def test_mutated_ack_evidence_cannot_be_treated_as_zero_release(self):
        receipt = self.retirement(); object.__setattr__(receipt, 'released_bytes', False)
        self.reject(self.final_check)

    def test_copied_ack_evidence_cannot_replace_issued_receipt(self):
        receipt = self.retirement(); self.lifecycle._retirement = replace(receipt)
        self.reject(self.final_check)

    def test_cancelled_retained_codec_prevents_final_check(self):
        self.retirement(); self.lifecycle._wire.close()
        self.reject(self.final_check)

    def test_cancelled_recipient_prevents_final_check(self):
        self.retirement(); self.recipient.close()
        self.reject(self.final_check)

    def test_source_cancellation_after_ack_discards_on_final_check(self):
        self.retirement(); self.model.close()
        self.reject(self.final_check)

    def test_changed_recipient_descriptor_and_type_confusion_are_terminal(self):
        self.retirement(); object.__setattr__(self.descriptor, 'recipient_revision', True)
        self.reject(self.final_check)

    def test_copied_final_recipient_burns_final_attempt(self):
        self.retirement()
        self.reject(lambda: self.final_check(recipient=replace(self.descriptor)))
        self.assertIs(self.lifecycle._publication_attempted, True)

    def test_different_live_recipient_cannot_inherit_review(self):
        self.retirement(); other = LogicalPublicationRecipient('app'); self.addCleanup(other.close)
        self.reject(lambda: self.final_check(recipient=other.descriptor))

    def test_wrong_final_application_cannot_transfer_permission(self):
        self.retirement(); credential = self.registry.register('other', ['files.read'])
        self.reject(lambda: self.final_check(app='other', credential=credential))

    def test_bad_final_credential_burns_final_attempt(self):
        self.retirement()
        self.reject(lambda: self.final_check(credential='x'*513))
        self.assertIs(self.lifecycle._publication_attempted, True)

    def test_changed_final_resource_request_cannot_inherit_approval(self):
        self.retirement()
        self.reject(lambda: self.final_check(proposal=make_file_read_proposal('changed', max_bytes=128)))

    def test_credential_rotation_after_acquisition_invalidates_final_check(self):
        self.retirement(); self.registry.rotate_credential('app')
        self.reject(self.final_check)

    def test_permission_broadening_after_acquisition_cannot_restore_authority(self):
        self.retirement(); self.registry.update_permissions('app', scopes=['*'])
        self.reject(self.final_check)

    def test_revoke_and_register_same_application_cannot_restore_review(self):
        self.retirement(); self.registry.revoke('app')
        credential = self.registry.register('app', ['files.read'])
        self.reject(lambda: self.final_check(credential=credential))

    def test_replaced_draft_version_after_acquisition_is_terminal(self):
        self.retirement(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.reject(self.final_check)

    def test_superseding_review_after_ack_prevents_final_check(self):
        self.retirement(); self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)
        self.reject(self.final_check)

    def test_failed_registry_lookup_cannot_leave_retained_bytes_retryable(self):
        self.retirement()
        with patch.object(self.registry, 'authenticate', side_effect=OSError('unavailable')):
            self.reject(self.final_check)

    def test_source_deadline_expiry_at_final_boundary_is_terminal(self):
        self.retirement()
        with patch('core.broker_live_review.monotonic', return_value=self.model._deadline):
            self.reject(self.final_check)

    def test_quarantine_deadline_extension_cannot_prolong_final_check(self):
        self.retirement(); self.lifecycle._wire._deadline += 60
        self.reject(self.final_check)

    def test_recipient_deadline_extension_cannot_prolong_final_check(self):
        self.retirement(); self.recipient._deadline += 60
        self.reject(self.final_check)

    def test_recipient_cancel_during_final_authentication_is_terminal(self):
        self.retirement(); original = self.registry.authenticate
        def authenticate(*args):
            result = original(*args); self.recipient.close(); return result
        with patch.object(self.registry, 'authenticate', side_effect=authenticate):
            self.reject(self.final_check)

    def test_registry_revocation_during_final_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: self.registry.revoke('app')): self.reject(self.final_check)

    def test_superseding_review_during_final_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)):
            self.reject(self.final_check)

    def test_reentrant_cancellation_during_final_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(self.lifecycle.coordinator.cancel): self.reject(self.final_check)

    def test_changed_recipient_during_final_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: object.__setattr__(self.descriptor, 'recipient_id', 'f'*64)):
            self.reject(self.final_check)

    def test_quarantine_key_type_confusion_during_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.lifecycle._wire, '_key', '')):
            self.reject(self.final_check)

    def test_quarantine_state_type_confusion_during_cleanup_prevents_result(self):
        self.retirement()
        class State(str): pass
        with self.cleanup_hook(lambda: setattr(self.lifecycle._wire, '_state', State('closed'))):
            self.reject(self.final_check)

    def test_source_review_deadline_extension_after_reserve_is_terminal(self):
        token = self.reserve(); self.model._deadline += 60
        self.reject(lambda: self.start(token))

    def test_source_review_deadline_extension_during_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.model, '_deadline', self.model._deadline+60)):
            self.reject(self.final_check)

    def test_source_state_rollback_during_final_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.model, '_state', 'acquisition_inflight')):
            self.reject(self.final_check)

    def test_final_attempt_flag_type_confusion_during_cleanup_prevents_result(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.lifecycle, '_publication_attempted', 1)):
            self.reject(self.final_check)

    def test_recipient_state_type_confusion_after_cleanup_prevents_result(self):
        self.retirement(); original = self.recipient.close
        class State(str): pass
        def close():
            original(); self.recipient._state = State('closed')
        with patch.object(self.recipient, 'close', side_effect=close): self.reject(self.final_check)

    def test_reintroduced_bytes_after_recipient_cleanup_are_rejected_and_wiped(self):
        self.retirement(); original = self.recipient.close
        attempted = [False]
        def close():
            original()
            if not attempted[0]:
                attempted[0] = True
                self.lifecycle._owned_buffer.extend(self.DATA)
        with patch.object(self.recipient, 'close', side_effect=close): self.reject(self.final_check)

    def test_equal_receipt_copy_during_cleanup_cannot_bypass_issuance(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.lifecycle, '_retirement', replace(self.lifecycle._retirement))):
            self.reject(self.final_check)

    def test_equal_summary_copy_during_cleanup_cannot_bypass_issuance(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.lifecycle, '_summary', replace(self.lifecycle._summary))):
            self.reject(self.final_check)

    def test_equal_token_copy_during_cleanup_cannot_bypass_issuance(self):
        self.retirement()
        with self.cleanup_hook(lambda: setattr(self.lifecycle, '_token', replace(self.lifecycle._token))):
            self.reject(self.final_check)

    def test_codec_cleanup_failure_still_wipes_owned_buffer_and_closes_owners(self):
        self.retirement(); retained = self.lifecycle._wire._buffer
        with patch.object(self.lifecycle._wire, 'close', side_effect=OSError('cleanup failed')):
            self.reject(self.final_check)
        self.assertEqual(retained, bytearray())

    def test_recipient_cleanup_failure_withholds_result_and_wipes_bytes(self):
        self.retirement(); original = self.recipient.close
        def close():
            original(); raise OSError('cleanup uncertainty')
        with patch.object(self.recipient, 'close', side_effect=close): self.reject(self.final_check)

    def test_state_rollback_after_success_cannot_restore_live_permission(self):
        self.retirement(); self.final_check()
        self.lifecycle._state = 'cleaned'
        self.recipient._state = 'bound'
        self.reject(self.final_check)

    def test_concurrent_final_attempt_returns_at_most_one_discard_only_result(self):
        self.retirement()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.final_check) for _ in range(2)]
        results = [future.result() for future in futures if future.exception() is None]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].released_bytes, 0)
        self.terminal()

    def test_persistent_lock_reunlock_cannot_revive_live_review(self):
        self.lifecycle.close(); self.registry.close()
        with tempfile.TemporaryDirectory() as directory:
            self.registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(directory)/'authority.db'))
            self.addCleanup(self.registry.close)
            self.credential = self.registry.register('app', ['files.read'])
            grant = self.registry.get('app').grant_id
            self.assertTrue(self.registry.operator_unlock('app', grant))
            self.model = LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
            self.addCleanup(self.model.close)
            from core.broker_live_protocol import LiveMetadataExchange
            self.peer = LiveMetadataExchange(role='broker', key=self.key, session=self.session)
            self.addCleanup(self.peer.close)
            self.install()
            self.retirement(); self.registry.lock_all()
            self.assertTrue(self.registry.operator_unlock('app', grant))
            self.reject(self.final_check)
            self.lifecycle.close(); self.registry.close()

    def test_ports_and_results_expose_no_bytes_execution_or_delivery_capability(self):
        self.assertFalse(hasattr(self.lifecycle.adapter, 'reserve'))
        self.assertFalse(hasattr(self.lifecycle.coordinator, 'stage'))
        for owner in (self.recipient, self.lifecycle.adapter, self.lifecycle.coordinator):
            for name in ('read', 'execute', 'release', 'publish', 'get_buffer', 'take_buffer'):
                self.assertFalse(hasattr(owner, name))
