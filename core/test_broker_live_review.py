"""Inactive mapping tests; synthetic peers are trusted only inside these tests."""
from dataclasses import asdict, replace
import os
from pathlib import Path
import secrets
import time
import unittest
from unittest.mock import patch
from core import broker_live_review as mapping
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_protocol import _canonical
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry
from core.test_broker_live import observed


class LiveReviewMappingTests(unittest.TestCase):
    def setUp(self):
        self.registry = ApplicationRegistry(); self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', ['files.read'])
        self.ledger = FileReadReviewLedger()
        self.constraint = FileReadConstraint('app', 'untrusted label', max_bytes=128)
        self.draft = self.ledger.create(self.constraint)
        self.proposal = make_file_read_proposal('untrusted label', max_bytes=128)
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(32)
        self.model = mapping.LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
        self.addCleanup(self.model.close)
        self.peer = LiveMetadataExchange(role='broker', key=self.key, session=self.session)
        self.addCleanup(self.peer.close)

    def begin(self):
        return self.model.coordinator.begin('app', self.credential, self.proposal, self.draft.draft_id, 1)

    def observe(self):
        self.request = self.peer.receive(self.begin())
        self.frame = self.peer.send(observed())
        self.model.coordinator.observe(self.frame)

    def review(self, answer='ALLOW ONCE'):
        self.observe()
        display = self.model.operator.display()
        self.model.operator.record(display, answer)
        return display

    def ack(self):
        finish = self.peer.receive(self.model.coordinator.finish())
        return self.peer.send(dict(**finish, outcome='denied', lifecycle='retired'))

    def assert_terminal(self):
        self.assertEqual(self.model._state, 'closed')
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.display()

    def test_allow_metadata_only_is_exact_and_terminal(self):
        before = self.registry.get('app')
        display = self.review()
        self.assertEqual(display.proposal_json, self.proposal.canonical_bytes().decode())
        self.assertEqual(display.request_id, self.request['decision_id'])
        self.assertEqual(display.file_id, observed()['observation']['file_id'])
        self.assertEqual(display.max_bytes, 128)
        result = self.model.coordinator.retire(self.ack())
        self.assertEqual(result.canonical_display, _canonical(asdict(display)))
        self.assertEqual(result.decision, 'allow_once')
        self.assertFalse(hasattr(result, 'data'))
        self.assertNotIn(self.credential, repr(result)+result.canonical_display.decode())
        self.assertIs(self.registry.get('app'), before)
        with self.assertRaises(TypeError): bool(result)
        self.assert_terminal()

    def test_deny_only_sends_cancel(self):
        self.review('DENY')
        finish = self.peer.receive(self.model.coordinator.finish())
        self.assertEqual(finish['action'], 'cancel')
        result = self.model.coordinator.retire(self.peer.send(dict(**finish, outcome='denied', lifecycle='retired')))
        self.assertEqual(result.decision, 'deny')

    def test_authority_without_review_cannot_finish(self):
        self.observe()
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_operator_and_coordinator_ports_are_separate(self):
        for name in ('record', 'display'): self.assertFalse(hasattr(self.model.coordinator, name))
        for name in ('begin', 'observe', 'finish', 'retire'): self.assertFalse(hasattr(self.model.operator, name))

    def test_missing_scope_prevents_open_frame(self):
        self.registry.update_permissions('app', scopes=[])
        with self.assertRaises(mapping.LiveReviewError): self.begin()
        self.assert_terminal()

    def test_raw_requester_observation_is_rejected(self):
        self.begin()
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(observed())
        self.assert_terminal()

    def test_wrong_peer_key_is_rejected(self):
        self.peer.receive(self.begin())
        self.peer._key = b'x'*32
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(self.peer.send(observed()))
        self.assert_terminal()

    def test_signed_observation_from_different_request_is_rejected(self):
        self.begin()
        other = LiveMetadataExchange(role='coordinator', key=self.key, session=self.session)
        request = dict(application_id='other', decision_id='d'*64, proposal_json=self.proposal.canonical_bytes().decode())
        self.peer.receive(other.send(request))
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(self.peer.send(observed()))
        self.assert_terminal()

    def test_observation_replay_is_terminal(self):
        self.observe()
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(self.frame)
        self.assert_terminal()

    def test_decision_resource_identifier_collision_rejected(self):
        request = self.peer.receive(self.begin())
        value = observed(); value['observation']['resource_token'] = request['decision_id']
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(self.peer.send(value))
        self.assert_terminal()

    def test_copied_display_cannot_record(self):
        self.observe(); display = self.model.operator.display()
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.record(replace(display), 'ALLOW ONCE')
        self.assert_terminal()

    def test_mutated_display_cannot_finish(self):
        display = self.review()
        object.__setattr__(display, 'file_id', 'f'*32)
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_duplicate_review_is_terminal(self):
        display = self.review()
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.record(display, 'ALLOW ONCE')
        self.assert_terminal()

    def test_redisplay_cannot_extend_or_reuse_review(self):
        self.observe(); self.model.operator.display()
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.display()
        self.assert_terminal()

    def test_nonexact_confirmation_rejected(self):
        self.observe(); display = self.model.operator.display()
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.record(display, True)
        self.assert_terminal()

    def test_rotation_after_observation_rejects_display(self):
        self.observe(); self.registry.rotate_credential('app')
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.display()
        self.assert_terminal()

    def test_revocation_after_review_rejects_finish(self):
        self.review(); self.registry.revoke('app')
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_permission_change_after_finish_rejects_ack(self):
        self.review(); ack = self.ack(); self.registry.update_permissions('app', scopes=[])
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(ack)
        self.assert_terminal()

    def test_draft_change_before_operator_answer_rejected(self):
        self.observe(); display = self.model.operator.display()
        self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        with self.assertRaises(mapping.LiveReviewError): self.model.operator.record(display, 'ALLOW ONCE')
        self.assert_terminal()

    def test_registry_lookup_failure_cannot_recover_review(self):
        self.review()
        with patch.object(self.registry, '_is_active', side_effect=RuntimeError('unavailable')):
            with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_expiry_before_final_ack_rejected(self):
        self.review(); ack = self.ack()
        with patch.object(mapping, 'monotonic', return_value=self.model._deadline):
            with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(ack)
        self.assert_terminal()

    def test_expiry_during_display_validation_rejected(self):
        self.observe()
        clock = [self.model._deadline-1]
        def inspect(value):
            result = asdict(value)
            if value is self.model._facts: clock[0] = self.model._deadline
            return result
        with patch.object(mapping, 'asdict', side_effect=inspect), patch.object(mapping, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(mapping.LiveReviewError): self.model.operator.display()
        self.assert_terminal()

    def test_timer_retires_idle_mapping(self):
        self.model.close()
        self.model = mapping.LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session, timeout=.03)
        self.addCleanup(self.model.close)
        self.begin()
        deadline = time.monotonic()+1
        while self.model._state != 'closed' and time.monotonic() < deadline: time.sleep(.005)
        self.assert_terminal()

    def test_signed_allow_or_data_ack_is_rejected(self):
        self.review(); finish = self.peer.receive(self.model.coordinator.finish())
        message = dict(**finish, outcome='allowed', lifecycle='retired', data='secret')
        frame = self.peer._encode('reply', dict(step=3, previous=self.peer._previous, message_json=_canonical(message).decode()))
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(frame)
        self.assert_terminal()

    def test_concurrent_finish_is_single_use(self):
        self.review()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.model.coordinator.finish) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.assert_terminal()

    def test_invalid_lifetime(self):
        for value in (True, 0, -1, 6, float('inf'), float('nan'), '5'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mapping.LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session, timeout=value)

    def test_app_state_mutation_cannot_widen_authority(self):
        self.review()
        object.__setattr__(self.registry.get('app'), 'scopes', frozenset({'*'}))
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_proposal_mutation_cannot_change_effect(self):
        self.review()
        object.__setattr__(self.proposal, '_body', make_file_read_proposal('changed', max_bytes=4096).canonical_bytes())
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_registry_change_during_retirement_is_rejected(self):
        self.review(); ack = self.ack()
        original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket); self.registry.revoke('app')
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(ack)
        self.assert_terminal()

    def test_draft_change_during_retirement_is_rejected(self):
        self.review(); ack = self.ack()
        original = self.model._reviews.discard_review
        def discard(ticket):
            original(ticket)
            if not self.ledger._existing(self.draft.draft_id).revoked:
                self.ledger.revoke(self.draft.draft_id, 1)
        with patch.object(self.model._reviews, 'discard_review', side_effect=discard):
            with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(ack)
        self.assert_terminal()

    def test_persistent_lock_and_unlock_cannot_restore_mapping(self):
        import tempfile
        from core.authority_store import SQLiteAuthorityStore
        self.model.close(); self.registry.close()
        with tempfile.TemporaryDirectory() as directory:
            self.registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(directory)/'authority.db'))
            try:
                self.credential = self.registry.register('app', ['files.read'])
                grant = self.registry.get('app').grant_id
                self.assertTrue(self.registry.operator_unlock('app', grant))
                self.model = mapping.LiveBrokerReview(self.registry, self.ledger, key=self.key, session=self.session)
                self.review()
                self.registry.lock_all()
                self.assertTrue(self.registry.operator_unlock('app', grant))
                with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
                self.assert_terminal()
            finally:
                self.model.close(); self.registry.close()

    def test_malformed_signed_observation_is_terminal(self):
        self.peer.receive(self.begin())
        value = observed(); value['observation']['size_bytes'] = True
        frame = self.peer._encode('reply', dict(step=1, previous=self.peer._previous, message_json=_canonical(value).decode()))
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(frame)
        self.assert_terminal()

    def test_oversized_frame_is_terminal(self):
        self.begin()
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.observe(b'x'*9000)
        self.assert_terminal()

    def test_ack_replay_cannot_restore_mapping(self):
        self.review(); ack = self.ack()
        self.model.coordinator.retire(ack)
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(ack)
        with self.assertRaises(mapping.LiveReviewError): self.begin()
        self.assert_terminal()

    def test_cancel_after_answer_discards_evidence(self):
        self.review(); self.model.operator.cancel()
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.finish()
        self.assert_terminal()

    def test_lost_ack_cannot_be_replaced_by_retired_receipt(self):
        self.review(); self.ack()
        from core.broker_live_transport import RetiredSessionDiagnostic
        receipt = RetiredSessionDiagnostic(b'{}', _canonical(observed()), 'verify')
        with self.assertRaises(mapping.LiveReviewError): self.model.coordinator.retire(receipt)
        self.assert_terminal()

    def test_cleanup_failure_never_returns_retired_evidence(self):
        self.review(); ack = self.ack()
        with patch.object(self.model._reviews, 'discard_review', side_effect=OSError('cleanup failed')):
            with self.assertRaises((mapping.LiveReviewError, OSError)):
                self.model.coordinator.retire(ack)
        self.assert_terminal()

    def test_real_child_metadata_mapping_retires_fixture_without_read(self):
        from core.broker_process import _LiveMetadataChild
        from core.broker_bootstrap import MAGIC, READY_SIZE, ready
        child = _LiveMetadataChild()
        self.addCleanup(child.close)
        deadline = time.monotonic()+5
        def read(size):
            output = bytearray()
            while len(output) < size:
                if time.monotonic() >= deadline: self.fail('child deadline')
                try:
                    chunk = os.read(child.stdout_fd, size-len(output))
                    if not chunk: self.fail('unexpected EOF')
                    output.extend(chunk)
                except BlockingIOError: time.sleep(.002)
            return bytes(output)
        def write(data):
            while data:
                if time.monotonic() >= deadline: self.fail('child deadline')
                try:
                    count = os.write(child.stdin_fd, data)
                    self.assertGreater(count, 0); data = data[count:]
                except BlockingIOError: time.sleep(.002)
        def frame():
            prefix = read(4); size = int.from_bytes(prefix, 'big')
            self.assertLessEqual(size, 8224)
            return prefix+read(size)
        write(MAGIC+self.key+self.session)
        self.assertEqual(read(READY_SIZE), ready(self.key, self.session, child.pid))
        write(self.begin())
        self.model.coordinator.observe(frame())
        display = self.model.operator.display()
        path = Path(display.display_path); self.assertTrue(path.exists())
        self.model.operator.record(display, 'ALLOW ONCE')
        write(self.model.coordinator.finish()); child.close_input()
        result = self.model.coordinator.retire(frame())
        while child.poll() is None and time.monotonic() < deadline: time.sleep(.002)
        self.assertEqual(child.poll(), 0)
        self.assertEqual(os.read(child.stdout_fd, 1), b'')
        child.close()
        self.assertFalse(path.exists())
        self.assertFalse(hasattr(result, 'data'))
