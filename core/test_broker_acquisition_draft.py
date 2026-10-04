"""Inactive reservation tests; authenticated synthetic peer, no I/O or reads."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest
from unittest.mock import patch
from core import broker_acquisition_draft as acquisition
from core import test_broker_live_review as helpers
from core.broker_live_review import LiveReviewError, RetiredMappedReview
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class AcquisitionDraftTests(unittest.TestCase):
    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.draft_model = acquisition.AcquisitionDraft(self.model)
        self.addCleanup(self.draft_model.close)

    def begin(self): return helpers.LiveReviewMappingTests.begin(self)
    def observe(self): return helpers.LiveReviewMappingTests.observe(self)
    def review(self, answer='ALLOW ONCE'): return helpers.LiveReviewMappingTests.review(self, answer)
    def reserve(self):
        self.review()
        return self.draft_model.coordinator.reserve()
    def consume(self, token, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal)
        values.update(overrides)
        return self.draft_model.adapter.consume(token, **values)
    def rejected(self, token, **overrides):
        with self.assertRaises(acquisition.AcquisitionDraftError): self.consume(token, **overrides)
        with self.assertRaises(acquisition.AcquisitionDraftError): self.consume(token)
        self.assertEqual(self.model._state, 'closed')

    def test_exact_fresh_review_and_grant_produce_only_inactive_consumption_evidence(self):
        before = self.registry.get('app')
        token = self.reserve(); context = loads(token.canonical_context)
        self.assertEqual(context['proposal_id'], self.model._shown.proposal_id)
        self.assertEqual(context['grant_id'], before.grant_id)
        self.assertEqual(context['file_id'], self.model._shown.file_id)
        self.assertEqual(context['max_bytes'], 128)
        result = self.consume(token)
        self.assertEqual(result.reservation_id, token.reservation_id)
        self.assertFalse(hasattr(result, 'data'))
        self.assertIn('no read or delivery authorized', result.meaning)
        self.assertIs(self.registry.get('app'), before)
        for value in (token, result):
            with self.assertRaises(TypeError): bool(value)
        self.assertNotIn(self.credential, token.canonical_context.decode()+repr(token)+repr(result))
        self.rejected(token)

    def test_authority_alone_cannot_reserve(self):
        self.observe()
        with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()
        self.assertEqual(self.model._state, 'closed')

    def test_deny_cannot_reserve(self):
        self.review('DENY')
        with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()

    def test_review_alone_after_revocation_cannot_reserve(self):
        self.review(); self.registry.revoke('app')
        with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()

    def test_retired_receipt_or_requester_dictionary_is_not_source(self):
        for value in (RetiredMappedReview(b'{}', 'allow_once'), {'approved': True}, True):
            with self.assertRaises(TypeError): acquisition.AcquisitionDraft(value)

    def test_existing_host_profile_is_not_accepted(self):
        from core.broker_review_host import _ReviewWaitMapping
        with _ReviewWaitMapping(self.registry, self.ledger, key=self.key, session=self.session) as source:
            with self.assertRaises(TypeError): acquisition.AcquisitionDraft(source)

    def test_retired_source_cannot_be_reserved(self):
        self.review()
        finish = self.peer.receive(self.model.coordinator.finish())
        self.model.coordinator.retire(self.peer.send(dict(**finish, outcome='denied', lifecycle='retired')))
        with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()

    def test_copied_token_retires_original(self):
        token = self.reserve(); self.rejected(replace(token))

    def test_mutated_token_is_rejected(self):
        token = self.reserve(); object.__setattr__(token, 'canonical_context', b'{}')
        self.rejected(token)

    def test_equal_mutable_bytes_are_not_an_immutable_reservation(self):
        token = self.reserve(); object.__setattr__(token, 'canonical_context', bytearray(token.canonical_context))
        self.rejected(token)

    def test_token_mutation_during_authentication_is_rejected(self):
        token = self.reserve(); original = self.registry.authenticate
        def authenticate(*args):
            result = original(*args); object.__setattr__(token, 'reservation_id', 'f'*64); return result
        with patch.object(self.registry, 'authenticate', side_effect=authenticate): self.rejected(token)

    def test_token_mutation_during_retirement_is_rejected(self):
        token = self.reserve(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); object.__setattr__(token, 'canonical_context', b'{}')
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard): self.rejected(token)

    def test_unknown_token_attempt_is_terminal(self):
        token = self.reserve(); self.rejected({'reservation_id': token.reservation_id})

    def test_wrong_application_cannot_transfer_reservation(self):
        token = self.reserve(); other = self.registry.register('other', ['files.read'])
        self.rejected(token, app='other', credential=other)

    def test_wrong_credential_is_terminal(self):
        self.rejected(self.reserve(), credential='wrong')

    def test_changed_proposal_or_effect_is_terminal(self):
        self.rejected(self.reserve(), proposal=make_file_read_proposal('untrusted label', max_bytes=4096))

    def test_rotation_cannot_restore_reservation(self):
        token = self.reserve(); self.credential = self.registry.rotate_credential('app')
        self.rejected(token)

    def test_permission_change_cannot_widen_reservation(self):
        token = self.reserve(); self.registry.update_permissions('app', scopes=['*'])
        self.rejected(token)

    def test_draft_replacement_invalidates_reservation(self):
        token = self.reserve(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.rejected(token)

    def test_draft_revocation_invalidates_reservation(self):
        token = self.reserve(); self.ledger.revoke(self.draft.draft_id, 1)
        self.rejected(token)

    def test_display_mutation_invalidates_reservation(self):
        token = self.reserve(); object.__setattr__(self.model._shown, 'max_bytes', 4096)
        self.rejected(token)

    def test_source_close_cannot_be_replayed(self):
        token = self.reserve(); self.model.close(); self.rejected(token)

    def test_old_metadata_finish_cannot_bypass_reservation(self):
        token = self.reserve()
        with self.assertRaises(LiveReviewError): self.model.coordinator.finish()
        self.rejected(token)

    def test_two_reservation_owners_cannot_reserve_same_review(self):
        token = self.reserve()
        other = acquisition.AcquisitionDraft(self.model)
        with self.assertRaises(acquisition.AcquisitionDraftError): other.coordinator.reserve()
        self.rejected(token)

    def test_duplicate_reservation_is_terminal(self):
        token = self.reserve()
        with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()
        self.rejected(token)

    def test_concurrent_consumption_at_most_once(self):
        token = self.reserve()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.consume, token) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.rejected(token)

    def test_expiry_cannot_be_extended_by_reserving(self):
        self.review(); deadline = self.model._deadline
        token = self.draft_model.coordinator.reserve()
        self.assertEqual(self.model._deadline, deadline)
        with patch('core.broker_live_review.monotonic', return_value=deadline): self.rejected(token)

    def test_nonce_collision_fails_closed(self):
        self.review()
        with patch.object(acquisition.secrets, 'token_hex', return_value=self.model._identity):
            with self.assertRaises(acquisition.AcquisitionDraftError): self.draft_model.coordinator.reserve()

    def test_registry_failure_is_terminal(self):
        token = self.reserve()
        with patch.object(self.registry, 'authenticate', side_effect=OSError('unavailable')):
            self.rejected(token)

    def test_oversized_credentials_are_terminal(self):
        self.rejected(self.reserve(), credential='x'*513)

    def test_application_id_reuse_cannot_restore_reservation(self):
        token = self.reserve(); self.registry.revoke('app')
        self.credential = self.registry.register('app', ['files.read'])
        self.rejected(token)

    def test_superseding_review_invalidates_reservation(self):
        token = self.reserve()
        self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)
        self.rejected(token)

    def test_lock_and_reunlock_cannot_restore_reservation(self):
        import tempfile
        from pathlib import Path
        from core.authority_store import SQLiteAuthorityStore
        from core.registry import ApplicationRegistry
        from core.broker_live_review import LiveBrokerReview
        self.draft_model.close(); self.registry.close()
        with tempfile.TemporaryDirectory() as folder:
            self.registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(folder)/'authority.db'))
            try:
                self.credential = self.registry.register('app', ['files.read'])
                grant = self.registry.get('app').grant_id
                self.assertTrue(self.registry.operator_unlock('app', grant))
                self.model = LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
                self.draft_model = acquisition.AcquisitionDraft(self.model)
                token = self.reserve()
                self.registry.lock_all(); self.assertTrue(self.registry.operator_unlock('app', grant))
                self.rejected(token)
            finally:
                self.draft_model.close(); self.registry.close()

    def test_registry_change_during_retirement_prevents_success(self):
        token = self.reserve(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); self.registry.revoke('app')
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard): self.rejected(token)

    def test_expiry_during_retirement_prevents_success(self):
        token = self.reserve(); original = self.model._reviews.discard_review
        clock = [self.model._deadline-1]
        def discard(ticket):
            original(ticket); clock[0] = self.model._deadline
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard), \
                patch.object(acquisition, 'monotonic', side_effect=lambda: clock[0]): self.rejected(token)

    def test_draft_revocation_during_retirement_prevents_success(self):
        token = self.reserve(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket)
            if not self.ledger._existing(self.draft.draft_id).revoked:
                self.ledger.revoke(self.draft.draft_id, 1)
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard): self.rejected(token)

    def test_cleanup_failure_does_not_return_consumption_evidence(self):
        token = self.reserve()
        with patch.object(self.model._reviews, 'discard_review', side_effect=OSError('cleanup unavailable')):
            with self.assertRaises((acquisition.AcquisitionDraftError, OSError)): self.consume(token)
        self.rejected(token)

    def test_roles_and_nonexecution_boundary(self):
        self.assertFalse(hasattr(self.draft_model.adapter, 'reserve'))
        self.assertFalse(hasattr(self.draft_model.coordinator, 'consume'))
        for name in ('read', 'release', 'execute', 'publish'):
            self.assertFalse(hasattr(self.draft_model.adapter, name))
