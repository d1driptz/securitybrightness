"""Actual generated-fixture reads stay on inactive private discard transport."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import unittest
from unittest.mock import patch

from core import broker_native_acquisition as native
from core import test_broker_live_review as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_acquisition_lifecycle import LiveAcquisitionLifecycle, AcquisitionLifecycleError
from core.broker_quarantine import QuarantinedReadExchange
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads


class NativeFixtureAcquisitionTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.adapter = native.NativeFixtureAcquisitionAdapter(key=self.key, session=self.session)
        self.addCleanup(self.adapter.close)
        self.acquisition = AcquisitionDraft(self.model)
        self.lifecycle = LiveAcquisitionLifecycle(self.acquisition)
        self.addCleanup(self.lifecycle.close)

    def opening(self):
        first = helpers.LiveReviewMappingTests.begin(self)
        observed = self.adapter.open(first)
        self.model.coordinator.observe(observed)
        self.display = self.model.operator.display()
        return observed

    def request(self, answer='ALLOW ONCE'):
        self.opening()
        self.model.operator.record(self.display, answer)
        self.token = self.lifecycle.coordinator.reserve()
        return self.lifecycle.adapter.begin(self.token, 'app', self.credential, self.proposal)

    def staged(self):
        request = self.request()
        self.staging_frame = self.adapter.stage(request)
        return self.lifecycle.adapter.stage(self.staging_frame)

    def retirement(self):
        self.staged()
        discard = self.lifecycle.adapter.retire()
        self.ack = self.adapter.retire(discard)
        return self.lifecycle.adapter.confirm_retirement(self.ack)

    def publication(self):
        return self.lifecycle.coordinator.check_publication('app', self.credential, self.proposal)

    def terminal(self):
        self.assertEqual(self.adapter._state, 'closed')
        if self.adapter._owner is not None:
            self.assertIsNone(self.adapter._owner._fd)
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.stage(b'')

    def rejected_stage(self, frame):
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.stage(frame)
        self.terminal()

    def altered_request(self, values):
        peer = QuarantinedReadExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(peer.close)
        return peer.request(values)

    def retain_uncertain_fixture_for_test_cleanup(self):
        owner, fd = self.adapter._owner, self.adapter._owner._fd
        def cleanup():
            if not owner._cleanup_failed: return
            # The fault mock is gone. Only test code may recover the deliberately
            # unconfirmed generated resource; production never resets failure.
            import msvcrt
            self.assertEqual(msvcrt.get_osfhandle(fd), owner._issued_handle)
            metadata = owner._native.metadata(owner._issued_handle, False)
            self.assertEqual(tuple(metadata[index] for index in (0, 1, 5)),
                             tuple(owner._metadata_snapshot[index] for index in (0, 1, 5)))
            os.close(fd)
            self.assertFalse(os.path.exists(owner.description.display_path))
            self.adapter._owner = None
        self.addCleanup(cleanup)
        return owner

    def test_complete_native_quarantine_and_separate_final_check_deliver_zero_bytes(self):
        original_app = self.registry.get('app')
        summary = self.staged()
        self.assertEqual(summary.staged_bytes, 37)
        self.assertEqual(summary.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertFalse(hasattr(summary, 'data'))
        self.assertIsNotNone(self.adapter._owner._fd)
        self.assertEqual(self.lifecycle._wire._buffer, bytearray(self.DATA))
        discard = self.lifecycle.adapter.retire()
        receipt = self.lifecycle.adapter.confirm_retirement(self.adapter.retire(discard))
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(self.lifecycle._wire._buffer, bytearray())
        self.assertIsNone(self.adapter._owner._fd)
        result = self.publication()
        self.assertEqual(result.released_bytes, 0)
        self.assertEqual(result.staged_bytes, 37)
        self.assertFalse(hasattr(result, 'data'))
        self.assertIs(self.registry.get('app'), original_app)
        with self.assertRaises(TypeError): bool(result)
        with self.assertRaises(AcquisitionLifecycleError): self.publication()

    def test_opening_review_reservation_and_request_do_not_read(self):
        with patch.object(native.os, 'read', side_effect=AssertionError('no native read permitted yet')) as read:
            self.request()
            read.assert_not_called()

    def test_application_authority_alone_cannot_create_acquisition_request(self):
        self.opening()
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            with self.assertRaises(AcquisitionLifecycleError): self.lifecycle.coordinator.reserve()
            read.assert_not_called()
        self.adapter.close()
        self.terminal()

    def test_human_review_after_revocation_cannot_create_acquisition_request(self):
        self.opening()
        self.model.operator.record(self.display, 'ALLOW ONCE')
        self.registry.revoke('app')
        with self.assertRaises(AcquisitionLifecycleError): self.lifecycle.coordinator.reserve()
        self.adapter.close()
        self.terminal()

    def test_denied_review_cannot_request_native_read(self):
        with self.assertRaises(AcquisitionLifecycleError): self.request('DENY')
        self.adapter.close()
        self.terminal()

    def test_staging_before_opening_is_terminal(self): self.rejected_stage(b'')

    def test_malformed_request_is_terminal_without_native_read(self):
        self.request()
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage({'approved': True})
            read.assert_not_called()

    def test_oversized_request_is_terminal(self):
        self.request()
        self.rejected_stage(b'x'*9000)

    def test_forged_request_authentication_is_terminal(self):
        request = bytearray(self.request()); request[-1] ^= 1
        self.rejected_stage(bytes(request))

    def test_resource_substitution_is_terminal_before_read(self):
        self.request()
        context = loads(self.token.canonical_context)
        context['file_id'] = 'f'*32
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(self.altered_request(context))
            read.assert_not_called()

    def test_application_substitution_is_terminal_before_read(self):
        self.request()
        context = loads(self.token.canonical_context); context['application_id'] = 'other'
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(self.altered_request(context))
            read.assert_not_called()

    def test_changed_effect_is_terminal_before_read(self):
        self.request()
        context = loads(self.token.canonical_context); context['max_bytes'] = 4096
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(self.altered_request(context))
            read.assert_not_called()

    def test_decision_substitution_is_terminal_before_read(self):
        self.request()
        context = loads(self.token.canonical_context); context['decision_id'] = 'f'*64
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(self.altered_request(context))
            read.assert_not_called()

    def test_proposal_mutation_cannot_change_exact_opening(self):
        frame = self.request()
        self.adapter._proposal = make_file_read_proposal('different', max_bytes=128)
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(frame)
            read.assert_not_called()

    def test_description_mutation_is_terminal_before_read(self):
        frame = self.request()
        object.__setattr__(self.adapter._owner.description, 'display_path', 'different label')
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(frame)
            read.assert_not_called()

    def test_equal_valued_description_type_substitution_is_rejected(self):
        class StrSubclass(str): pass
        frame = self.request()
        d = self.adapter._owner.description
        object.__setattr__(d, 'file_id', StrSubclass(d.file_id))
        with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
            self.rejected_stage(frame)
            read.assert_not_called()

    def test_equal_valued_native_identity_type_substitution_is_rejected(self):
        frame = self.request()
        owner = self.retain_uncertain_fixture_for_test_cleanup()
        metadata = list(owner._metadata); metadata[1] = bytearray(metadata[1])
        with patch.object(owner._native, 'metadata', return_value=tuple(metadata)):
            with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
                self.rejected_stage(frame)
                read.assert_not_called()
        self.assertTrue(owner._cleanup_failed)

    def test_changed_native_metadata_is_terminal_before_read(self):
        frame = self.request()
        owner = self.retain_uncertain_fixture_for_test_cleanup()
        with patch.object(self.adapter._owner._native, 'metadata', return_value=None):
            with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
                self.rejected_stage(frame)
                read.assert_not_called()
        self.assertTrue(owner._cleanup_failed)

    def test_native_metadata_failure_is_terminal(self):
        frame = self.request()
        owner = self.retain_uncertain_fixture_for_test_cleanup()
        with patch.object(self.adapter._owner._native, 'metadata', side_effect=OSError('native failed')):
            self.rejected_stage(frame)
        self.assertTrue(owner._cleanup_failed)

    def test_seek_error_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'lseek', side_effect=OSError('seek failed')):
            self.rejected_stage(frame)

    def test_nonzero_seek_result_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'lseek', return_value=1):
            with patch.object(native.os, 'read', side_effect=AssertionError('must not read')) as read:
                self.rejected_stage(frame)
                read.assert_not_called()

    def test_read_error_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', side_effect=OSError('read failed')):
            self.rejected_stage(frame)

    def test_short_read_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=self.DATA[:-1]): self.rejected_stage(frame)

    def test_oversized_read_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=self.DATA+b'x'): self.rejected_stage(frame)

    def test_non_bytes_read_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=bytearray(self.DATA)): self.rejected_stage(frame)

    def test_changed_same_size_contents_emits_no_frame(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=b'x'*37): self.rejected_stage(frame)

    def test_read_uses_same_fd_and_only_fixture_size(self):
        frame = self.request()
        fd = self.adapter._owner._fd
        real_read = os.read
        calls = []
        def read(actual_fd, bound):
            calls.append((actual_fd, bound))
            return real_read(actual_fd, bound)
        with patch.object(native.os, 'read', side_effect=read):
            self.lifecycle.adapter.stage(self.adapter.stage(frame))
        self.assertEqual(calls, [(fd, 37)])

    def test_expiry_during_read_emits_no_frame(self):
        frame = self.request(); real_read = os.read
        def read(fd, size):
            data = real_read(fd, size); self.adapter._deadline = 0; return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_cancellation_during_read_emits_no_frame(self):
        frame = self.request(); real_read = os.read
        def read(fd, size):
            data = real_read(fd, size); self.adapter.close(); return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_description_mutation_after_read_emits_no_frame(self):
        frame = self.request(); real_read = os.read
        def read(fd, size):
            data = real_read(fd, size)
            object.__setattr__(self.adapter._owner.description, 'resource_token', 'f'*64)
            return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_description_mutation_during_final_native_validation_emits_no_frame(self):
        frame = self.request()
        owner = self.adapter._owner
        real_read, real_metadata = os.read, owner._native.metadata
        read_done = [False]
        def read(fd, size):
            data = real_read(fd, size); read_done[0] = True; return data
        def metadata(*args):
            result = real_metadata(*args)
            if read_done[0]: object.__setattr__(owner.description, 'display_path', 'changed after validation')
            return result
        with patch.object(native.os, 'read', side_effect=read):
            with patch.object(owner._native, 'metadata', side_effect=metadata): self.rejected_stage(frame)

    def test_proposal_mutation_during_read_emits_no_frame(self):
        frame = self.request(); real_read = os.read
        def read(fd, size):
            data = real_read(fd, size)
            self.adapter._proposal = make_file_read_proposal('changed during read', max_bytes=128)
            return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)

    def test_description_mutation_during_frame_generation_emits_no_frame(self):
        frame = self.request(); original = self.adapter._wire.reply
        def reply(**kwargs):
            result = original(**kwargs)
            object.__setattr__(self.adapter._owner.description, 'display_path', 'changed during framing')
            return result
        with patch.object(self.adapter._wire, 'reply', side_effect=reply): self.rejected_stage(frame)

    def test_cancellation_during_frame_generation_emits_no_frame(self):
        frame = self.request(); original = self.adapter._wire.reply
        def reply(**kwargs):
            result = original(**kwargs); self.adapter.close(); return result
        with patch.object(self.adapter._wire, 'reply', side_effect=reply): self.rejected_stage(frame)

    def test_consumed_request_replay_never_reads_again(self):
        frame = self.request(); self.adapter.stage(frame)
        with patch.object(native.os, 'read', side_effect=AssertionError('no replay read')) as read:
            self.rejected_stage(frame)
            read.assert_not_called()

    def test_concurrent_staging_has_at_most_one_frame_and_one_read(self):
        frame = self.request(); real_read = os.read; calls = []
        def read(fd, size):
            calls.append((fd, size)); return real_read(fd, size)
        with patch.object(native.os, 'read', side_effect=read):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.adapter.stage, frame) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.assertEqual(len(calls), 1)
        self.terminal()

    def test_revocation_after_native_stage_invalidates_coordinator_and_clears_quarantine(self):
        frame = self.request(); staged = self.adapter.stage(frame)
        self.registry.revoke('app')
        with self.assertRaises(AcquisitionLifecycleError): self.lifecycle.adapter.stage(staged)
        self.assertEqual(self.lifecycle._wire._buffer, bytearray())
        self.adapter.close(); self.terminal()

    def test_rotation_after_native_stage_prevents_final_check(self):
        self.retirement(); self.registry.rotate_credential('app')
        with self.assertRaises(AcquisitionLifecycleError): self.publication()
        self.assertEqual(self.lifecycle._wire._buffer, bytearray())

    def test_draft_change_after_native_stage_prevents_final_check(self):
        self.retirement(); self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        with self.assertRaises(AcquisitionLifecycleError): self.publication()
        self.assertEqual(self.lifecycle._wire._buffer, bytearray())

    def test_native_change_before_discard_emits_no_ack(self):
        self.staged(); discard = self.lifecycle.adapter.retire()
        owner = self.retain_uncertain_fixture_for_test_cleanup()
        with patch.object(self.adapter._owner._native, 'metadata', return_value=None):
            with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(discard)
        self.assertTrue(owner._cleanup_failed)
        self.terminal()
        with self.assertRaises(AcquisitionLifecycleError): self.publication()

    def test_failed_native_close_emits_no_ack(self):
        self.staged(); discard = self.lifecycle.adapter.retire()
        original = self.adapter._owner.close
        def close():
            original(); raise native.NativeAcquisitionError('cleanup uncertain')
        with patch.object(self.adapter._owner, 'close', side_effect=close):
            with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(discard)
        self.terminal()

    def test_expiry_during_native_close_emits_no_ack(self):
        self.staged(); discard = self.lifecycle.adapter.retire()
        original = self.adapter._owner.close
        def close():
            original(); self.adapter._deadline = 0
        with patch.object(self.adapter._owner, 'close', side_effect=close):
            with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(discard)
        self.terminal()

    def test_proposal_mutation_during_acknowledgement_emits_no_ack(self):
        self.staged(); discard = self.lifecycle.adapter.retire()
        original = self.adapter._wire.acknowledge_discard
        def acknowledge():
            result = original()
            self.adapter._proposal = make_file_read_proposal('changed during ack', max_bytes=128)
            return result
        with patch.object(self.adapter._wire, 'acknowledge_discard', side_effect=acknowledge):
            with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(discard)
        self.terminal()

    def test_discard_replay_cannot_acknowledge_again(self):
        self.staged(); discard = self.lifecycle.adapter.retire(); self.adapter.retire(discard)
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(discard)
        self.terminal()

    def test_wrong_discard_closes_resource_and_emits_no_ack(self):
        self.staged()
        with self.assertRaises(native.NativeAcquisitionError): self.adapter.retire(b'not a discard')
        self.terminal()

    def test_fd_is_noninherited_and_deleted_after_retirement(self):
        self.staged()
        path = self.adapter._owner.description.display_path
        self.assertFalse(os.get_inheritable(self.adapter._owner._fd))
        self.assertTrue(os.path.exists(path))
        discard = self.lifecycle.adapter.retire()
        self.lifecycle.adapter.confirm_retirement(self.adapter.retire(discard))
        self.assertFalse(os.path.exists(path))

    def test_private_adapter_has_no_application_delivery_api(self):
        for name in ('read', 'execute', 'release', 'publish', 'get_buffer', 'data'):
            self.assertFalse(hasattr(self.adapter, name))


if __name__ == '__main__': unittest.main()
