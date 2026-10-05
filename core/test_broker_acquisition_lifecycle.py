"""Inactive acquisition tests: authenticated synthetic bytes, never file reads."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

from core import broker_acquisition_lifecycle as lifecycle
from core import test_broker_live_review as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_live_review import RetiredMappedReview
from core.broker_quarantine import QuarantinedReadExchange
from core.file_read_schema import make_file_read_proposal


class LiveAcquisitionLifecycleTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.acquisition = AcquisitionDraft(self.model)
        self.addCleanup(self.acquisition.close)
        self.lifecycle = lifecycle.LiveAcquisitionLifecycle(self.acquisition)
        self.addCleanup(self.lifecycle.close)
        self.quarantine_peer = QuarantinedReadExchange(role='broker', key=self.key,
                                                      session=self.session)
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
        frame = self.lifecycle.adapter.begin(token, **values)
        self.quarantine_peer.accept_request(frame)
        return token

    def stage(self):
        self.start()
        self.staging_frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        return self.lifecycle.adapter.stage(self.staging_frame)

    def retirement(self):
        self.stage()
        discard = self.lifecycle.adapter.retire()
        self.quarantine_peer.accept_discard(discard)
        self.ack = self.quarantine_peer.acknowledge_discard()
        return self.lifecycle.adapter.confirm_retirement(self.ack)

    def publication(self, **overrides):
        values = dict(app='app', credential=self.credential, proposal=self.proposal)
        values.update(overrides)
        return self.lifecycle.coordinator.check_publication(**values)

    def terminal(self):
        self.assertEqual(self.model._state, 'closed')
        wire = self.lifecycle._wire
        if wire is not None: self.assertEqual(wire._buffer, bytearray())
        with self.assertRaises(lifecycle.AcquisitionLifecycleError): self.publication()

    def reject(self, operation):
        with self.assertRaises(lifecycle.AcquisitionLifecycleError): operation()
        self.terminal()

    def test_live_review_survives_staging_until_separate_publication_check(self):
        app = self.registry.get('app')
        summary = self.stage()
        self.assertNotEqual(self.model._state, 'closed')
        self.assertTrue(self.model._reviews.check_review(self.model._ticket, 'app', self.proposal).current)
        self.assertEqual(len(self.lifecycle._wire._buffer), len(self.DATA))
        self.assertFalse(hasattr(summary, 'data'))
        discard = self.lifecycle.adapter.retire()
        self.quarantine_peer.accept_discard(discard)
        receipt = self.lifecycle.adapter.confirm_retirement(self.quarantine_peer.acknowledge_discard())
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(self.lifecycle._wire._buffer, bytearray())
        self.assertNotEqual(self.model._state, 'closed')
        result = self.publication()
        self.assertEqual(result.disposition, 'eligible_discarded')
        self.assertEqual(result.released_bytes, 0)
        self.assertEqual(result.staged_bytes, len(self.DATA))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(result.binding_digest, summary.binding_digest)
        self.assertFalse(hasattr(result, 'data'))
        self.assertIs(self.registry.get('app'), app)
        with self.assertRaises(TypeError): bool(result)
        self.terminal()

    def test_requester_dictionary_or_retired_receipt_is_not_live_source(self):
        for value in ({'approved': True}, RetiredMappedReview(b'{}', 'allow_once'), self.model):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                lifecycle.LiveAcquisitionLifecycle(value)

    def test_application_authority_without_human_review_cannot_reserve(self):
        self.observe()
        self.reject(self.lifecycle.coordinator.reserve)

    def test_deny_review_cannot_start_acquisition(self):
        self.review('DENY')
        self.reject(self.lifecycle.coordinator.reserve)

    def test_review_evidence_after_revocation_cannot_reserve(self):
        self.review(); self.registry.revoke('app')
        self.reject(self.lifecycle.coordinator.reserve)

    def test_copied_reservation_is_terminal(self):
        token = self.reserve()
        self.reject(lambda: self.start(replace(token)))

    def test_reservation_mutation_is_terminal(self):
        token = self.reserve(); object.__setattr__(token, 'canonical_context', b'{}')
        self.reject(lambda: self.start(token))

    def test_begin_application_substitution_is_terminal(self):
        token = self.reserve(); credential = self.registry.register('other', ['files.read'])
        self.reject(lambda: self.start(token, app='other', credential=credential))

    def test_begin_wrong_credential_burns_slot(self):
        token = self.reserve()
        self.reject(lambda: self.start(token, credential='wrong'))

    def test_begin_changed_effect_is_terminal(self):
        token = self.reserve()
        self.reject(lambda: self.start(token, proposal=make_file_read_proposal('untrusted label', max_bytes=4096)))

    def test_oversized_credential_is_terminal(self):
        token = self.reserve()
        self.reject(lambda: self.start(token, credential='x'*513))

    def test_begin_replay_clears_quarantine(self):
        token = self.start()
        self.reject(lambda: self.start(token))

    def test_requester_supplied_reply_dictionary_is_terminal(self):
        self.start()
        self.reject(lambda: self.lifecycle.adapter.stage({'outcome': 'staged', 'data': self.DATA}))

    def test_authenticated_wrong_length_reply_is_terminal(self):
        self.start()
        message = dict(binding_digest=self.quarantine_peer._binding_digest,
                       outcome='staged', data=base64.b64encode(self.DATA+b'x').decode())
        frame = self.quarantine_peer._frame('reply', message)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_authenticated_extra_authority_field_is_terminal(self):
        self.start()
        message = dict(binding_digest=self.quarantine_peer._binding_digest,
                       outcome='staged', data=base64.b64encode(self.DATA).decode(), approved=True)
        frame = self.quarantine_peer._frame('reply', message)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_fabricated_peer_reply_is_terminal(self):
        self.start(); self.quarantine_peer._key = b'x'*32
        frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_adapter_denial_cannot_be_publication_evidence(self):
        self.start()
        frame = self.quarantine_peer.reply(outcome='denied')
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_stage_replay_wipes_held_bytes(self):
        self.stage()
        self.reject(lambda: self.lifecycle.adapter.stage(self.staging_frame))

    def test_mutated_staging_summary_cannot_broaden_effect(self):
        summary = self.stage(); object.__setattr__(summary, 'staged_bytes', 4096)
        self.reject(self.lifecycle.adapter.retire)

    def test_mutated_quarantined_bytes_are_not_valid_staging(self):
        self.stage(); self.lifecycle._wire._buffer[0] ^= 1
        self.reject(self.lifecycle.adapter.retire)

    def test_codec_cancellation_after_staging_cannot_be_ignored(self):
        self.stage(); self.lifecycle._wire.close()
        self.reject(self.lifecycle.adapter.retire)

    def test_codec_cancellation_during_staging_clears_result(self):
        self.start(); original = self.lifecycle._wire.accept_reply
        def accept(frame):
            result = original(frame); self.lifecycle._wire.close(); return result
        frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        with patch.object(self.lifecycle._wire, 'accept_reply', side_effect=accept):
            self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_oversized_staging_frame_is_terminal(self):
        self.start()
        self.reject(lambda: self.lifecycle.adapter.stage(b'x'*9000))

    def test_revocation_between_begin_and_stage_wipes_bytes(self):
        self.start(); self.registry.revoke('app')
        frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        self.reject(lambda: self.lifecycle.adapter.stage(frame))

    def test_rotation_after_stage_invalidates_retirement(self):
        self.stage(); self.registry.rotate_credential('app')
        self.reject(self.lifecycle.adapter.retire)

    def test_mutated_display_after_stage_is_terminal(self):
        self.stage(); object.__setattr__(self.model._shown, 'file_id', 'f'*32)
        self.reject(self.lifecycle.adapter.retire)

    def test_missing_retirement_ack_cannot_reach_publication(self):
        self.stage(); self.lifecycle.adapter.retire()
        self.reject(self.publication)

    def test_retirement_ack_replay_is_terminal(self):
        self.retirement()
        self.reject(lambda: self.lifecycle.adapter.confirm_retirement(self.ack))

    def test_mutated_retirement_receipt_is_not_zero_release_evidence(self):
        receipt = self.retirement(); object.__setattr__(receipt, 'released_bytes', True)
        self.reject(self.publication)

    def test_cancellation_after_staging_erases_buffer(self):
        self.stage(); self.lifecycle.close(); self.terminal()

    def test_source_cancellation_prevents_final_check(self):
        self.retirement(); self.model.close(); self.reject(self.publication)

    def test_publication_wrong_application_is_terminal(self):
        self.retirement(); credential = self.registry.register('other', ['files.read'])
        self.reject(lambda: self.publication(app='other', credential=credential))

    def test_publication_changed_request_is_terminal(self):
        self.retirement()
        self.reject(lambda: self.publication(proposal=make_file_read_proposal('changed', max_bytes=128)))

    def test_permission_broadening_cannot_revive_prior_review(self):
        self.retirement(); self.registry.update_permissions('app', scopes=['*'])
        self.reject(self.publication)

    def test_draft_replacement_before_publication_is_terminal(self):
        self.retirement(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.reject(self.publication)

    def test_expiry_at_final_boundary_is_terminal(self):
        self.retirement()
        with patch('core.broker_live_review.monotonic', return_value=self.model._deadline):
            self.reject(self.publication)

    def test_codec_deadline_remains_required_after_acknowledgement(self):
        self.retirement(); self.lifecycle._wire._deadline = 0
        self.reject(self.publication)

    def test_superseding_review_before_publication_is_terminal(self):
        self.retirement(); self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)
        self.reject(self.publication)

    def test_registry_failure_cannot_leave_retryable_publication(self):
        self.retirement()
        with patch.object(self.registry, 'authenticate', side_effect=OSError('unavailable')):
            self.reject(self.publication)

    def test_token_mutation_during_final_authentication_is_terminal(self):
        self.retirement(); original = self.registry.authenticate
        def authenticate(*args):
            result = original(*args)
            object.__setattr__(self.lifecycle._token, 'display_digest', 'f'*64)
            return result
        with patch.object(self.registry, 'authenticate', side_effect=authenticate):
            self.reject(self.publication)

    def test_registry_change_during_source_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); self.registry.revoke('app')
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_draft_revocation_during_source_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket)
            draft = self.ledger._existing(self.draft.draft_id)
            if not draft.revoked: self.ledger.revoke(draft.draft_id, draft.revision)
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_cancellation_during_source_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        cancelled = [False]
        def discard(ticket):
            original(ticket)
            if not cancelled[0]:
                cancelled[0] = True
                self.lifecycle.coordinator.cancel()
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_superseding_review_during_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        replaced = [False]
        def discard(ticket):
            original(ticket)
            if not replaced[0]:
                replaced[0] = True
                self.ledger.begin_review('app', self.proposal, self.draft.draft_id, 1)
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_expiry_during_source_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); self.model._deadline = 0
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_codec_expiry_during_source_cleanup_prevents_success(self):
        self.retirement(); original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); self.lifecycle._wire._deadline = 0
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            self.reject(self.publication)

    def test_cleanup_failure_never_returns_publication_evidence(self):
        self.retirement()
        with patch.object(self.model._reviews, 'discard_review', side_effect=OSError('cleanup failed')):
            with self.assertRaises((lifecycle.AcquisitionLifecycleError, OSError)): self.publication()
        self.terminal()

    def test_codec_cleanup_failure_still_clears_held_bytes_and_review(self):
        self.stage()
        with patch.object(self.lifecycle._wire, 'close', side_effect=OSError('codec cleanup failed')):
            with self.assertRaises(OSError): self.lifecycle.close()
        self.terminal()

    def test_concurrent_final_attempt_returns_at_most_one_result(self):
        self.retirement()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.publication) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.terminal()

    def test_concurrent_staging_returns_at_most_one_summary_then_clears(self):
        self.start(); frame = self.quarantine_peer.reply(outcome='staged', data=self.DATA)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.lifecycle.adapter.stage, frame) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.terminal()

    def test_ports_have_no_read_or_release_capability(self):
        self.assertFalse(hasattr(self.lifecycle.adapter, 'reserve'))
        self.assertFalse(hasattr(self.lifecycle.coordinator, 'stage'))
        for port in (self.lifecycle.adapter, self.lifecycle.coordinator):
            for name in ('read', 'execute', 'release', 'publish', 'get_buffer'):
                self.assertFalse(hasattr(port, name))
