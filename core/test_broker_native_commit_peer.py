"""Real guarded Windows dry-commit peer tests; metadata, never protected bytes."""
from dataclasses import asdict
import hashlib
import inspect
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from core import broker_native_commit_peer as native
from core.broker_bootstrap import MAGIC, READY_SIZE, ready
from core.broker_process import BrokerProcessError
from core.broker_protocol import MAX_BODY_BYTES, _canonical
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.test_broker_recipient_protocol import binding


class NativeCommitPeerTests(unittest.TestCase):
    def setUp(self):
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(32)
        self.witness = RecipientWitnessExchange(role='coordinator', key=self.key, session=self.session)
        self.commit = PublicationCommitExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.witness.close); self.addCleanup(self.commit.close)
        self.child = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.child is not None:
            try: self.child.close()
            except BrokerProcessError: pass

    def launch(self, *, prefix=''):
        if prefix:
            directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
            path = Path(directory.name)/'synthetic-metadata-fault.py'
            root = str(Path(__file__).resolve().parent.parent)
            path.write_text('import os,sys,time\nsys.path.insert(0,'+repr(root)+')\n'
                'from core import broker_native_commit_entry as entry\n'+prefix+
                '\ntry: entry.run()\nexcept BaseException: sys.exit(1)\n', encoding='utf-8')
            with patch.object(native._PublicationCommitPeer, '_entry_path', return_value=path):
                self.child = native._PublicationCommitPeer()
        else: self.child = native._PublicationCommitPeer()
        self.observation = self.child._observe()
        return self.child

    def write(self, data):
        deadline, offset = time.monotonic()+3, 0
        while offset < len(data):
            self.assertLess(time.monotonic(), deadline, 'bounded peer input')
            self.child._validate()
            try: offset += os.write(self.child.stdin_fd, data[offset:])
            except BlockingIOError: time.sleep(.002)
            self.child._validate()

    def read(self, count):
        deadline, result = time.monotonic()+3, bytearray()
        while len(result) < count:
            self.assertLess(time.monotonic(), deadline, 'bounded peer output')
            self.child._validate(retiring=self.child._input_closed)
            try:
                value = os.read(self.child.stdout_fd, count-len(result))
                if not value: raise EOFError('metadata peer stopped')
                result.extend(value)
            except BlockingIOError: time.sleep(.002)
            self.child._validate(retiring=self.child._input_closed)
        return bytes(result)

    def frame(self):
        prefix = self.read(4); size = int.from_bytes(prefix, 'big')
        self.assertTrue(32 <= size <= MAX_BODY_BYTES+32)
        return prefix+self.read(size)

    def boot(self, *, prefix=''):
        self.launch(prefix=prefix); self.write(MAGIC+self.key+self.session)
        self.assertEqual(self.read(READY_SIZE), ready(self.key, self.session, self.observation.pid))

    def witnessed(self, *, prefix=''):
        self.boot(prefix=prefix)
        self.write(self.witness.request(binding()))
        self.proof = self.witness.accept_proof(self.frame())
        self.assertEqual(self.proof.outcome, 'witnessed')

    def envelope(self):
        return dict(revision=1, mode='dry_run_discard_only', commit_id='9'*64,
            binding=binding(), staged_bytes=37,
            staged_digest=hashlib.sha256(b'SecurityBrightness synthetic fixture\n').hexdigest(),
            channel=dict(pid=self.observation.pid, creation_time=self.observation.creation_time,
                         witness_session=self.session.hex()))

    def prepared(self, *, prefix=''):
        self.witnessed(prefix=prefix)
        self.envelope_value = self.envelope()
        self.prepare_frame = self.commit.prepare(self.envelope_value)
        self.write(self.prepare_frame)
        self.ready_evidence = self.commit.accept_ready(self.frame())
        self.assertEqual(self.ready_evidence.outcome, 'prepared')

    def committed(self, *, prefix=''):
        self.prepared(prefix=prefix)
        self.commit_frame = self.commit.dry_commit(); self.write(self.commit_frame)

    def wait_exit(self):
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            value = self.child.poll()
            if value is not None: return value
            time.sleep(.002)
        self.fail('metadata peer did not exit within bound')

    def remaining_output(self):
        # Failed peers need not remain live. Original ownership still guards
        # failure-output inspection; no receipt is treated as success here.
        result = bytearray()
        self.child._fields(); self.child._objects()
        while True:
            try: value = os.read(self.child.stdout_fd, 4096)
            except BlockingIOError: time.sleep(.002); continue
            if not value: return bytes(result)
            result.extend(value)
            self.assertLessEqual(len(result), 2*(MAX_BODY_BYTES+36))

    def failed(self):
        self.assertNotEqual(self.wait_exit(), 0)
        self.assertEqual(self.remaining_output(), b'', 'failed phase emitted later metadata')
        self.child.close(); self.child._retired()

    def quiet(self):
        deadline = time.monotonic()+.05
        while time.monotonic() < deadline:
            self.child._validate()
            with self.assertRaises(BlockingIOError): os.read(self.child.stdout_fd, 1)
            time.sleep(.002)
        self.assertIsNone(self.child.poll())

    def finish(self):
        self.write(self.witness.retire()); self.child.close_input()
        receipt_frame, ack_frame = self.frame(), self.frame()
        self.assertEqual(self.read_to_eof(), b'')
        self.assertEqual(self.wait_exit(), 0)
        self.child.close(); self.child._retired()
        receipt = self.commit.accept_receipt(receipt_frame)
        ack = self.witness.accept_ack(ack_frame)
        self.assertEqual((receipt.outcome, ack.outcome), ('dry_run_retired', 'retired'))
        self.assertEqual((receipt.released_bytes, ack.released_bytes), (0, 0))
        return receipt, ack

    def read_to_eof(self):
        deadline, result = time.monotonic()+3, bytearray()
        while time.monotonic() < deadline:
            self.child._validate(retiring=True)
            try: value = os.read(self.child.stdout_fd, 4096)
            except BlockingIOError: time.sleep(.002); continue
            if not value: return bytes(result)
            result.extend(value)
        self.fail('no bounded output EOF')

    def test_real_guarded_peer_completes_zero_release_receipt_ack_and_native_join(self):
        self.committed(); receipt, ack = self.finish()
        self.assertEqual(receipt.inspect(), self.envelope_value)
        self.assertEqual(ack.inspect(), binding())
        self.assertEqual(receipt.binding_digest, hashlib.sha256(_canonical(self.envelope_value)).hexdigest())
        self.assertEqual(self.child._retired_snapshot, (0, True))
        for result in (self.ready_evidence, self.proof, receipt, ack):
            with self.assertRaises(TypeError): bool(result)
            self.assertNotIn('data', asdict(result))

    def test_fixed_profile_has_no_executable_resource_handle_or_transport_selector(self):
        self.assertEqual(list(inspect.signature(native._PublicationCommitPeer).parameters), [])
        self.launch()
        self.assertEqual(self.child._entry_path().name, 'broker_native_commit_entry.py')
        for name in ('read', 'publish', 'execute', 'release', 'authorize'):
            self.assertFalse(hasattr(self.child, name))
        with self.assertRaises(TypeError): native._PublicationCommitPeer(path='C:\\personal')

    def test_commit_request_does_not_return_receipt_before_retirement(self):
        self.committed(); self.quiet(); self.finish()

    def test_retirement_does_not_return_receipt_before_original_input_eof(self):
        self.committed(); self.write(self.witness.retire()); self.quiet()
        self.child.close_input()
        receipt, ack = self.frame(), self.frame()
        self.assertEqual(self.read_to_eof(), b''); self.assertEqual(self.wait_exit(), 0)
        self.child.close(); self.child._retired()
        self.assertEqual(self.commit.accept_receipt(receipt).released_bytes, 0)
        self.assertEqual(self.witness.accept_ack(ack).released_bytes, 0)

    def test_trailing_input_prevents_commit_receipt_and_witness_ack(self):
        self.committed(); self.write(self.witness.retire()+b'x'); self.failed()

    def test_duplicate_retirement_is_trailing_input_and_cannot_commit(self):
        self.committed(); frame = self.witness.retire(); self.write(frame+frame); self.failed()

    def test_native_pid_claim_substitution_is_independently_rejected(self):
        self.witnessed(); value = self.envelope(); value['channel']['pid'] += 1
        self.write(self.commit.prepare(value)); self.failed()

    def test_native_creation_time_claim_substitution_is_independently_rejected(self):
        self.witnessed(); value = self.envelope(); value['channel']['creation_time'] += 1
        self.write(self.commit.prepare(value)); self.failed()

    def test_witness_session_claim_substitution_is_independently_rejected(self):
        self.witnessed(); value = self.envelope(); value['channel']['witness_session'] = 'a'*64
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_resource_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope(); value['binding']['context']['resource_token'] = 'c'*64
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_effect_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope(); value['binding']['context']['max_bytes'] = 256
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_recipient_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope(); value['binding']['recipient']['recipient_id'] = 'c'*64
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_application_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope()
        value['binding']['recipient']['application_id'] = 'other'
        value['binding']['context']['application_id'] = 'other'
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_proposal_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope()
        value['binding']['context']['proposal_id'] = 'sbp2_sha256_'+'c'*64
        self.write(self.commit.prepare(value)); self.failed()

    def test_commit_decision_binding_cannot_substitute_original_witness(self):
        self.witnessed(); value = self.envelope(); value['binding']['context']['decision_id'] = 'c'*64
        self.write(self.commit.prepare(value)); self.failed()

    def test_valid_witness_domain_frame_cannot_be_commit_prepare(self):
        self.witnessed(); self.write(self.witness.retire()); self.failed()

    def test_valid_commit_domain_frame_cannot_be_initial_witness_request(self):
        self.boot(); self.write(self.commit.prepare(self.envelope())); self.failed()

    def test_witness_retirement_cannot_substitute_dry_commit(self):
        self.prepared(); self.write(self.witness.retire()); self.failed()

    def test_commit_replay_cannot_substitute_witness_retirement(self):
        self.committed(); self.write(self.commit_frame); self.failed()

    def test_prepare_replay_cannot_substitute_dry_commit(self):
        self.prepared(); self.write(self.prepare_frame); self.failed()

    def test_changed_commit_key_cannot_prepare(self):
        self.witnessed()
        foreign = PublicationCommitExchange(role='coordinator', key=b'x'*32, session=self.session)
        self.addCleanup(foreign.close); self.write(foreign.prepare(self.envelope())); self.failed()

    def test_changed_commit_session_cannot_prepare(self):
        self.witnessed()
        foreign = PublicationCommitExchange(role='coordinator', key=self.key, session=b'x'*32)
        self.addCleanup(foreign.close); self.write(foreign.prepare(self.envelope())); self.failed()

    def test_prepare_tampering_cannot_emit_ready_or_receipt(self):
        self.witnessed(); frame = self.commit.prepare(self.envelope())
        self.write(frame[:-1]+bytes([frame[-1]^1])); self.failed()

    def test_authenticated_extra_authority_field_is_rejected_by_fixed_peer(self):
        self.witnessed(); value = self.envelope(); value['permission'] = 'allow_once'
        self.write(self.commit._frame('request', value)); self.failed()

    def test_authenticated_publish_mode_is_rejected_by_fixed_peer(self):
        self.witnessed(); value = self.envelope(); value['mode'] = 'publish'
        self.write(self.commit._frame('request', value)); self.failed()

    def test_authenticated_native_handle_field_is_rejected_by_fixed_peer(self):
        self.witnessed(); value = self.envelope(); value['channel']['handle'] = 123
        self.write(self.commit._frame('request', value)); self.failed()

    def test_authenticated_boolean_native_pid_is_rejected_by_fixed_peer(self):
        self.witnessed(); value = self.envelope(); value['channel']['pid'] = True
        self.write(self.commit._frame('request', value)); self.failed()

    def test_authenticated_partial_file_summary_is_rejected_by_fixed_peer(self):
        self.witnessed(); value = self.envelope(); value['staged_bytes'] = 36
        self.write(self.commit._frame('request', value)); self.failed()

    def test_oversized_prepare_prefix_fails_without_waiting_for_large_body(self):
        self.witnessed(); self.write((MAX_BODY_BYTES+33).to_bytes(4, 'big')); self.failed()

    def test_undersized_prepare_prefix_is_rejected(self):
        self.witnessed(); self.write((31).to_bytes(4, 'big')); self.failed()

    def test_eof_before_witness_request_cannot_commit(self):
        self.boot(); self.child.close_input(); self.failed()

    def test_eof_before_prepare_cannot_commit(self):
        self.witnessed(); self.child.close_input(); self.failed()

    def test_eof_before_dry_commit_cannot_commit(self):
        self.prepared(); self.child.close_input(); self.failed()

    def test_eof_before_retirement_cannot_commit(self):
        self.committed(); self.child.close_input(); self.failed()

    def test_truncated_prepare_body_cannot_commit(self):
        self.witnessed(); frame = self.commit.prepare(self.envelope())
        self.write(frame[:-1]); self.child.close_input(); self.failed()

    def test_native_identity_query_failure_prevents_prepared_evidence(self):
        self.witnessed(prefix="def fail(self, handle): raise RuntimeError('synthetic identity fault')\nentry._OwnershipApi.identity = fail")
        self.write(self.commit.prepare(self.envelope())); self.failed()

    def test_peer_identity_query_uses_own_original_current_process_handle(self):
        prefix = "original = entry._OwnershipApi.identity\ndef identity(self, handle):\n if handle != self.k.GetCurrentProcess(): raise ValueError('foreign handle')\n return original(self, handle)\nentry._OwnershipApi.identity = identity"
        self.committed(prefix=prefix); self.finish()

    def test_child_watchdog_independently_retires_a_stalled_peer(self):
        prefix = "original_timer = entry.threading.Timer\nentry.threading.Timer = lambda seconds, callback: original_timer(.3, callback)"
        self.boot(prefix=prefix); self.failed()

    def test_invalid_boot_magic_cannot_emit_startup_or_commit_metadata(self):
        self.launch(); self.write(b'BADBoot1'+self.key+self.session); self.failed()

    def test_changed_guarded_parent_pid_is_not_current_peer_identity(self):
        self.boot(); original = self.child.pid; self.child.pid += 1
        with self.assertRaises(BrokerProcessError): self.child._validate()
        self.child.pid = original

    def test_retired_original_peer_cannot_reopen_or_reuse_receipt(self):
        self.committed(); self.finish()
        with self.assertRaises(BrokerProcessError): self.child._observe()
        with self.assertRaises(BrokerProcessError): self.child._validate()
        with self.assertRaises(ValueError): self.commit.prepare(self.envelope_value)


if __name__ == '__main__': unittest.main()
