"""Fixed real child plus real coordinator lifecycle; generated fixtures only.

Operator input here is test orchestration, never a human demonstration.
"""
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from core import test_broker_live_review as helpers
from core.broker_process import _BindingMetadataChild
from core.broker_bootstrap import MAGIC, READY_SIZE, ready
from core.broker_protocol import MAX_BODY_BYTES, _canonical
from core.broker_binding_protocol import AcquisitionBindingExchange
from core.broker_acquisition_draft import AcquisitionDraft, AcquisitionDraftError
from core.broker_live_review import LiveReviewError
from core.json_input import loads


class BindingChildTests(unittest.TestCase):
    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        self.child = None
        self.path = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.child is not None: self.child.close()
        if self.path is not None: self.assertFalse(self.path.exists())

    def write(self, data):
        deadline = time.monotonic()+5
        while data:
            if time.monotonic() >= deadline: self.fail('write timeout')
            try:
                count = os.write(self.child.stdin_fd, data)
                if count <= 0: self.fail('write failed')
                data = data[count:]
            except BlockingIOError: time.sleep(.002)

    def read(self, size):
        result = bytearray(); deadline = time.monotonic()+5
        while len(result) < size:
            if time.monotonic() >= deadline: self.fail('read timeout')
            try:
                chunk = os.read(self.child.stdout_fd, size-len(result))
                if not chunk: raise EOFError('child closed')
                result.extend(chunk)
            except BlockingIOError: time.sleep(.002)
        return bytes(result)

    def frame(self):
        prefix = self.read(4); size = int.from_bytes(prefix, 'big')
        self.assertTrue(32 <= size <= MAX_BODY_BYTES+32)
        return prefix+self.read(size)

    def start(self):
        first = helpers.LiveReviewMappingTests.begin(self)
        self.child = _BindingMetadataChild()
        self.write(MAGIC+self.key+self.session)
        self.assertTrue(hmac.compare_digest(self.read(READY_SIZE), ready(self.key, self.session, self.child.pid)))
        self.write(first)
        self.model.coordinator.observe(self.frame())
        self.display = self.model.operator.display()
        self.path = Path(self.display.display_path)
        self.assertTrue(self.path.exists())
        self.wire = AcquisitionBindingExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.wire.close)

    def reserve(self):
        self.start()
        self.model.operator.record(self.display, 'ALLOW ONCE')
        self.acquisition = AcquisitionDraft(self.model)
        self.addCleanup(self.acquisition.close)
        self.token = self.acquisition.coordinator.reserve()
        return dict(context=loads(self.token.canonical_context), display_digest=self.token.display_digest)

    def bind(self):
        message = self.reserve()
        self.write(self.wire.send(message))
        self.digest = hashlib.sha256(_canonical(message)).hexdigest()
        self.assertEqual(self.wire.receive(self.frame()), dict(outcome='bound', binding_digest=self.digest))

    def finish(self, action='retire', trailing=b''):
        command = dict(action=action, binding_digest=self.digest)
        self.write(self.wire.send(command)+trailing)
        self.child.close_input()
        return self.frame()

    def join(self, success):
        # A reply alone is insufficient: exact EOF, exit, native job cleanup.
        with self.assertRaises(EOFError): self.read(1)
        deadline = time.monotonic()+5
        while self.child.poll() is None and time.monotonic() < deadline: time.sleep(.002)
        self.assertIsNotNone(self.child.poll())
        if success: self.assertEqual(self.child.poll(), 0)
        else: self.assertNotEqual(self.child.poll(), 0)
        self.child.close()
        if self.path is not None: self.assertFalse(self.path.exists())

    def consume(self):
        return self.acquisition.adapter.consume(self.token, 'app', self.credential, self.proposal)

    def test_real_binding_retirement_and_current_review_consumption(self):
        self.bind()
        frame = self.finish()
        self.join(True)
        receipt = self.wire.receive(frame)
        self.assertEqual(receipt['released_bytes'], 0)
        result = self.consume()
        self.assertFalse(hasattr(result, 'data'))
        with self.assertRaises(TypeError): bool(result)
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_cancel_ack_has_zero_bytes_and_review_is_discarded(self):
        self.bind(); frame = self.finish('cancel'); self.join(True)
        self.assertEqual(self.wire.receive(frame)['released_bytes'], 0)
        self.acquisition.close()
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_revocation_after_bound_invalidates_consumption(self):
        self.bind(); self.registry.revoke('app')
        frame = self.finish(); self.join(True); self.wire.receive(frame)
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_rotation_after_retirement_invalidates_consumption(self):
        self.bind(); frame = self.finish(); self.join(True); self.wire.receive(frame)
        self.credential = self.registry.rotate_credential('app')
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_draft_change_after_retirement_invalidates_consumption(self):
        self.bind(); frame = self.finish(); self.join(True); self.wire.receive(frame)
        self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_review_expiry_after_native_retirement_invalidates_consumption(self):
        self.bind(); frame = self.finish(); self.join(True); self.wire.receive(frame)
        self.model._deadline = 0
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def reject_message(self, mutate):
        message = self.reserve(); mutate(message)
        self.write(self.wire.send(message))
        with self.assertRaises(EOFError): self.frame()
        self.join(False)

    def test_other_application(self):
        self.reject_message(lambda m: m['context'].update(application_id='other'))

    def test_other_proposal(self):
        self.reject_message(lambda m: m['context'].update(proposal_id='sbp2_sha256_'+'f'*64))

    def test_other_resource(self):
        self.reject_message(lambda m: m['context'].update(file_id='f'*32))

    def test_changed_effect(self):
        self.reject_message(lambda m: m['context'].update(max_bytes=127))

    def test_other_session(self):
        self.reject_message(lambda m: m['context'].update(registry_session='f'*64))

    def test_changed_display(self):
        self.reject_message(lambda m: m.update(display_digest='f'*64))

    def test_changed_grant_without_changed_display(self):
        self.reject_message(lambda m: m['context'].update(grant_id='00000000-0000-4000-8000-000000000001'))

    def test_trailing_input_prevents_retirement_receipt(self):
        self.bind()
        with self.assertRaises(EOFError): self.finish(trailing=b'x')
        self.join(False)

    def test_replayed_binding_is_not_a_finish(self):
        message = self.reserve(); frame = self.wire.send(message)
        self.write(frame); self.wire.receive(self.frame()); self.write(frame)
        with self.assertRaises(EOFError): self.frame()
        self.join(False)

    def test_old_metadata_finish_cannot_cross_domain(self):
        self.start(); self.model.operator.record(self.display, 'ALLOW ONCE')
        self.write(self.model.coordinator.finish())
        with self.assertRaises(EOFError): self.frame()
        self.join(False)

    def test_parent_cancellation_kills_child_and_deletes_fixture(self):
        self.bind(); self.acquisition.close(); self.child.close()
        self.assertIsNotNone(self.child.poll())
        self.assertFalse(self.path.exists())
        with self.assertRaises(AcquisitionDraftError): self.consume()

    def test_truncated_binding_fails_closed(self):
        message = self.reserve(); frame = self.wire.send(message)
        self.write(frame[:-1]); self.child.close_input()
        with self.assertRaises(EOFError): self.frame()
        self.join(False)

    def test_closed_pipe_after_binding_retires_resource(self):
        self.bind(); self.child.close_input()
        with self.assertRaises(EOFError): self.frame()
        self.join(False)

    def helper(self, injected):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        entry = Path(directory.name)/'binding_fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        entry.write_text('import sys,os\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_binding_entry as entry\n'
            'from core.broker_session import BrokerResourceSession\n'+injected+'\nentry.run()\n', encoding='utf-8')
        return patch.object(_BindingMetadataChild, '_entry_path', return_value=entry)

    def test_native_verification_failure_withholds_ack(self):
        with self.helper("def fail(*args): raise OSError('native failure')\nBrokerResourceSession.verify_once=fail"):
            self.bind()
            with self.assertRaises(EOFError): self.finish()
            self.join(False)

    def test_native_cleanup_failure_withholds_ack(self):
        with self.helper("original=BrokerResourceSession.close\ndef fail(self):\n original(self)\n raise OSError('cleanup failure')\nBrokerResourceSession.close=fail"):
            self.bind()
            with self.assertRaises(EOFError): self.finish()
            self.join(False)

    def test_crash_at_native_verification_deletes_fixture(self):
        with self.helper("def crash(*args): os._exit(9)\nBrokerResourceSession.verify_once=crash"):
            self.bind()
            with self.assertRaises(EOFError): self.finish()
            self.join(False)

    def test_no_scope_prevents_launch(self):
        self.registry.update_permissions('app', scopes=[])
        with self.assertRaises(LiveReviewError): self.start()
        self.assertIsNone(self.child)

    def test_authority_without_operator_review_cannot_reserve(self):
        self.start()
        acquisition = AcquisitionDraft(self.model)
        self.addCleanup(acquisition.close)
        with self.assertRaises(AcquisitionDraftError): acquisition.coordinator.reserve()
        self.child.close()
        self.assertFalse(self.path.exists())

    def test_independent_watchdog_cleans_abandoned_resource(self):
        self.start()
        deadline = time.monotonic()+12
        while self.child.poll() is None and time.monotonic() < deadline: time.sleep(.05)
        self.assertIsNotNone(self.child.poll())
        self.join(False)
