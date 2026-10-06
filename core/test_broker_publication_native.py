"""Inactive native publication profile: retained quarantine, never delivery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import os
import unittest
from unittest.mock import patch

from core import broker_native_acquisition as native
from core import broker_publication_native as publication_native
from core import test_broker_live_review as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_protocol import _canonical
from core.broker_publication_lifecycle import LivePublicationDraft, PublicationLifecycleError
from core.broker_publication_protocol import PublicationCheckExchange
from core.broker_publication_recipient import LogicalPublicationRecipient
from core.broker_quarantine import QuarantinedReadExchange
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class NativePublicationProfileTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.adapter = publication_native.PublicationNativeFixtureAdapter(key=self.key, session=self.session)
        self.addCleanup(self.adapter.close)
        self.acquisition = AcquisitionDraft(self.model)
        self.recipient = LogicalPublicationRecipient('app')
        self.addCleanup(self.recipient.close)
        self.descriptor = self.recipient.descriptor
        self.lifecycle = LivePublicationDraft(self.acquisition, self.recipient)
        self.addCleanup(self.lifecycle.close)

    def opening(self):
        observed = self.adapter.open(helpers.LiveReviewMappingTests.begin(self))
        self.model.coordinator.observe(observed)
        self.display = self.model.operator.display()
        return observed

    def request(self, answer='ALLOW ONCE'):
        self.opening()
        self.model.operator.record(self.display, answer)
        self.token = self.lifecycle.coordinator.reserve()
        return self.lifecycle.adapter.begin(self.token, 'app', self.credential, self.proposal)

    def binding(self):
        return dict(context=loads(self.token.canonical_context), recipient=asdict(self.descriptor))

    def altered_request(self, binding, *, raw=False):
        self.test_peer = PublicationCheckExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.test_peer.close)
        if raw:
            return self.test_peer._frame('request', binding)
        return self.test_peer.request(binding['context'], binding['recipient'])

    def staged(self):
        self.staging_frame = self.adapter.stage(self.request())
        return self.lifecycle.adapter.stage(self.staging_frame)

    def retirement(self):
        self.staged()
        self.retirement_frame = self.lifecycle.adapter.retire()
        self.ack = self.adapter.retire(self.retirement_frame)
        return self.lifecycle.adapter.confirm_retirement(self.ack)

    def final_check(self):
        return self.lifecycle.coordinator.check_publication('app', self.credential, self.proposal, self.descriptor)

    def terminal(self):
        self.assertEqual(self.adapter._state, 'closed')
        if self.adapter._owner is not None:
            self.assertIsNone(self.adapter._owner._fd)
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.stage(b'')

    def rejected_stage(self, frame):
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.stage(frame)
        self.terminal()

    def rejected_before_read(self, frame):
        with patch.object(native.os, 'read', side_effect=AssertionError('no protected read')) as read:
            self.rejected_stage(frame)
            read.assert_not_called()

    def rejected_retirement(self, frame):
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(frame)
        self.terminal()
        self.lifecycle.close()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_native_cleanup_precedes_ack_while_parent_retains_exact_quarantine(self):
        receipt = self.retirement()
        self.assertIsNone(self.adapter._owner._fd)
        self.assertEqual(self.lifecycle._wire._state, 'retired_for_check')
        self.assertEqual(bytes(self.lifecycle._owned_buffer), self.DATA)
        self.assertEqual(receipt.released_bytes, 0)
        self.assertNotIn('data', asdict(receipt))
        result = self.final_check()
        self.assertEqual(result.released_bytes, 0)
        self.assertEqual(result.staged_bytes, 37)
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(result.recipient_digest, hashlib.sha256(_canonical(asdict(self.descriptor))).hexdigest())
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        self.assertEqual(self.recipient._state, 'closed')
        self.assertNotIn('data', asdict(result))
        with self.assertRaises(TypeError): bool(result)

    def test_opening_human_review_and_bound_request_do_not_read(self):
        with patch.object(native.os, 'read', side_effect=AssertionError('no pre-acquisition read')) as read:
            self.request()
            read.assert_not_called()

    def test_application_authority_alone_cannot_request_native_acquisition(self):
        self.opening()
        with patch.object(native.os, 'read') as read:
            with self.assertRaises(PublicationLifecycleError): self.lifecycle.coordinator.reserve()
            read.assert_not_called()

    def test_denied_review_cannot_request_native_acquisition(self):
        with patch.object(native.os, 'read') as read:
            with self.assertRaises(PublicationLifecycleError): self.request('DENY')
            read.assert_not_called()

    def test_revoked_human_review_is_not_permission_to_request_acquisition(self):
        self.opening(); self.model.operator.record(self.display, 'ALLOW ONCE')
        self.registry.revoke('app')
        with patch.object(native.os, 'read') as read:
            with self.assertRaises(PublicationLifecycleError): self.lifecycle.coordinator.reserve()
            read.assert_not_called()

    def test_requester_observation_or_approval_mapping_is_not_staging_frame(self):
        self.request(); self.rejected_before_read({'approved': True, 'file_id': self.display.file_id})

    def test_oversized_staging_input_closes_native_resource_without_read(self):
        self.request(); self.rejected_before_read(b'x'*9000)

    def test_forged_mac_closes_native_resource_without_read(self):
        frame = bytearray(self.request()); frame[-1] ^= 1
        self.rejected_before_read(bytes(frame))

    def test_old_discard_only_mac_domain_is_not_accepted(self):
        self.request()
        peer = QuarantinedReadExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(peer.close)
        self.rejected_before_read(peer.request(self.binding()['context']))

    def test_wrapper_authority_field_is_rejected_even_when_authenticated(self):
        self.request(); binding = self.binding(); binding['approved'] = True
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_recipient_authority_field_is_rejected_even_when_authenticated(self):
        self.request(); binding = self.binding(); binding['recipient']['permission'] = 'allow_once'
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_context_authority_field_is_rejected_even_when_authenticated(self):
        self.request(); binding = self.binding(); binding['context']['expires_at'] = 'never'
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_missing_recipient_claim_is_rejected_before_read(self):
        self.request(); binding = self.binding(); del binding['recipient']
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_recipient_application_mismatch_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['recipient']['application_id'] = 'other'
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_recipient_revision_boolean_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['recipient']['recipient_revision'] = True
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_recipient_id_collision_is_rejected_before_read(self):
        self.request(); binding = self.binding()
        binding['recipient']['recipient_id'] = binding['context']['resource_token']
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_signed_alternate_recipient_cannot_pass_original_parent_binding(self):
        self.request(); binding = self.binding(); binding['recipient']['recipient_id'] = 'e'*64
        frame = self.altered_request(binding)
        # The native actor verifies typed claims and its actual resource. It has
        # no independent channel identity; exact recipient ownership is parent-side.
        staged = self.adapter.stage(frame)
        with self.assertRaises(PublicationLifecycleError): self.lifecycle.adapter.stage(staged)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        self.assertEqual(self.recipient._state, 'closed')

    def test_unsupported_signed_recipient_revision_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['recipient']['recipient_revision'] = 2
        self.rejected_before_read(self.altered_request(binding))

    def test_native_resource_substitution_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['context']['file_id'] = 'f'*32
        self.rejected_before_read(self.altered_request(binding))

    def test_application_and_recipient_substitution_is_rejected_before_read(self):
        self.request(); binding = self.binding()
        binding['context']['application_id'] = binding['recipient']['application_id'] = 'other'
        self.rejected_before_read(self.altered_request(binding))

    def test_changed_read_bound_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['context']['max_bytes'] = 4096
        self.rejected_before_read(self.altered_request(binding))

    def test_changed_proposal_identity_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['context']['proposal_id'] = 'sbp2_sha256_'+'f'*64
        self.rejected_before_read(self.altered_request(binding))

    def test_unsupported_operation_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['context']['operation'] = 'files.write'
        self.rejected_before_read(self.altered_request(binding, raw=True))

    def test_changed_decision_is_rejected_before_read(self):
        self.request(); binding = self.binding(); binding['context']['decision_id'] = 'd'*64
        self.rejected_before_read(self.altered_request(binding))

    def test_signed_frame_version_mismatch_is_rejected_before_read(self):
        self.request(); peer = PublicationCheckExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(peer.close)
        frame = peer._frame('request', self.binding()); body = loads(frame[4:-32]); body['version'] = 2
        body = _canonical(body); signed = body+peer._mac('request', body)
        self.rejected_before_read(len(signed).to_bytes(4, 'big')+signed)

    def test_native_acquisition_uses_one_original_descriptor_read_of_37_bytes(self):
        frame = self.request(); fd = self.adapter._owner._fd
        original = os.read; calls = []
        def read(actual_fd, size):
            calls.append((actual_fd, size)); return original(actual_fd, size)
        with patch.object(native.os, 'read', side_effect=read):
            self.lifecycle.adapter.stage(self.adapter.stage(frame))
        self.assertEqual(calls, [(fd, 37)])

    def test_descriptor_substitution_is_rejected_before_read(self):
        frame = self.request(); self.adapter._owner._fd = self.adapter._owner._fd+10000
        self.rejected_before_read(frame)

    def test_short_native_read_emits_no_staging_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=self.DATA[:-1]): self.rejected_stage(frame)

    def test_native_read_failure_emits_no_staging_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', side_effect=OSError('failed')): self.rejected_stage(frame)

    def test_cancellation_during_read_emits_no_staging_frame(self):
        frame = self.request(); original = os.read
        def read(fd, size):
            data = original(fd, size); self.adapter.close(); return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_expiry_during_read_emits_no_staging_frame(self):
        frame = self.request(); original = os.read
        def read(fd, size):
            data = original(fd, size); self.adapter._deadline = 0; return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_proposal_mutation_during_read_emits_no_staging_frame(self):
        frame = self.request(); original = os.read
        def read(fd, size):
            data = original(fd, size)
            self.adapter._proposal = make_file_read_proposal('different request', max_bytes=128)
            return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_recipient_binding_mutation_during_frame_generation_is_terminal(self):
        frame = self.request(); original = self.adapter._wire.reply
        def reply(**kwargs):
            result = original(**kwargs); binding = loads(self.adapter._wire._binding)
            binding['recipient']['recipient_revision'] = 2
            self.adapter._wire._binding = _canonical(binding)
            return result
        with patch.object(self.adapter._wire, 'reply', side_effect=reply): self.rejected_stage(frame)

    def test_request_replay_cannot_repeat_native_read(self):
        frame = self.request(); self.adapter.stage(frame)
        self.rejected_before_read(frame)

    def test_concurrent_stage_attempts_allow_at_most_one_native_read(self):
        frame = self.request(); original = os.read; calls = []
        def read(fd, size):
            calls.append((fd, size)); return original(fd, size)
        with patch.object(native.os, 'read', side_effect=read):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.adapter.stage, frame) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.assertEqual(len(calls), 1)
        self.terminal()

    def test_revocation_after_native_read_prevents_acceptance_and_clears_parent(self):
        frame = self.request(); staged = self.adapter.stage(frame); self.registry.revoke('app')
        with self.assertRaises(PublicationLifecycleError): self.lifecycle.adapter.stage(staged)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_revocation_after_staging_discards_retained_quarantine(self):
        self.staged(); self.registry.revoke('app')
        with self.assertRaises(PublicationLifecycleError): self.lifecycle.adapter.retire()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_rotation_after_native_retirement_prevents_final_check(self):
        self.retirement(); self.registry.rotate_credential('app')
        with self.assertRaises(PublicationLifecycleError): self.final_check()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_draft_version_change_after_retirement_prevents_final_check(self):
        self.retirement(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        with self.assertRaises(PublicationLifecycleError): self.final_check()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_recipient_closed_after_native_retirement_prevents_final_check(self):
        self.retirement(); self.recipient.close()
        with self.assertRaises(PublicationLifecycleError): self.final_check()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_failed_native_cleanup_emits_no_retirement_ack(self):
        self.staged(); frame = self.lifecycle.adapter.retire(); original = self.adapter._owner.close
        def close():
            original(); raise native.NativeAcquisitionError('cleanup uncertain')
        with patch.object(self.adapter._owner, 'close', side_effect=close): self.rejected_retirement(frame)

    def test_cancel_during_native_close_emits_no_retirement_ack(self):
        self.staged(); frame = self.lifecycle.adapter.retire(); original = self.adapter._owner.close
        called = [False]
        def close():
            original()
            if not called[0]: called[0] = True; self.adapter.close()
        with patch.object(self.adapter._owner, 'close', side_effect=close): self.rejected_retirement(frame)

    def test_proposal_mutation_during_retirement_ack_emits_no_ack(self):
        self.staged(); frame = self.lifecycle.adapter.retire(); original = self.adapter._wire.acknowledge_retirement
        def acknowledge():
            result = original()
            self.adapter._proposal = make_file_read_proposal('changed after close', max_bytes=128)
            return result
        with patch.object(self.adapter._wire, 'acknowledge_retirement', side_effect=acknowledge):
            self.rejected_retirement(frame)

    def test_retirement_replay_cannot_reuse_closed_native_resource(self):
        self.retirement(); self.rejected_retirement(self.retirement_frame)

    def test_retired_check_replay_is_terminal_and_never_returns_data(self):
        self.retirement(); self.final_check()
        with self.assertRaises(PublicationLifecycleError): self.final_check()
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())

    def test_generated_fixture_deleted_before_parent_final_check(self):
        self.staged(); path = self.adapter._owner.description.display_path
        self.assertTrue(os.path.exists(path)); self.assertFalse(os.get_inheritable(self.adapter._owner._fd))
        self.lifecycle.adapter.confirm_retirement(self.adapter.retire(self.lifecycle.adapter.retire()))
        self.assertFalse(os.path.exists(path))
        self.assertEqual(bytes(self.lifecycle._owned_buffer), self.DATA)
        self.final_check()

    def test_native_profile_has_no_application_delivery_or_requester_path_api(self):
        for name in ('read', 'execute', 'release', 'publish', 'get_buffer', 'data', 'open_path'):
            self.assertFalse(hasattr(self.adapter, name))

    def test_native_owner_substitution_during_read_does_not_close_foreign_fixture(self):
        frame = self.request(); original_owner = self.adapter._owner
        foreign = native._NativeReadFixture(); self.addCleanup(foreign.close)
        original_read = os.read
        def read(fd, size):
            value = original_read(fd, size); self.adapter._owner = foreign; return value
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)
        self.assertIsNone(original_owner._fd)
        self.assertIsNotNone(foreign._fd)
        self.assertEqual(os.fstat(foreign._fd).st_size, len(self.DATA))

    def test_wire_substitution_during_frame_generation_preserves_foreign_codec(self):
        frame = self.request(); issued = self.adapter._wire
        foreign = PublicationCheckExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(foreign.close)
        original_reply = issued.reply
        def reply(**kwargs):
            result = original_reply(**kwargs); self.adapter._wire = foreign; return result
        with patch.object(issued, 'reply', side_effect=reply): self.rejected_stage(frame)
        self.assertEqual(issued._state, 'closed')
        self.assertEqual(foreign._state, 'new')
        self.assertIs(self.adapter._wire_changed, True)


if __name__ == '__main__': unittest.main()
