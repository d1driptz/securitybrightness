"""Real fixed native dry-commit peer; metadata only and zero byte delivery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from core import broker_native_commit_check as channel
from core import broker_native_commit_peer as process
from core import broker_recipient_process as guarded_process
from core import broker_transport as transport
from core import test_broker_publication_lifecycle as helpers
from core.broker_publication_commit_draft import PublicationCommitError
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_publication_lifecycle import LivePublicationDraft, FinalPublicationDraftCheck
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.file_read_schema import make_file_read_proposal


class NativePublicationCommitCheckTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'
    install = helpers.LivePublicationDraftTests.install
    begin = helpers.LivePublicationDraftTests.begin
    observe = helpers.LivePublicationDraftTests.observe
    review = helpers.LivePublicationDraftTests.review
    reserve = helpers.LivePublicationDraftTests.reserve
    start = helpers.LivePublicationDraftTests.start
    stage = helpers.LivePublicationDraftTests.stage
    retirement = helpers.LivePublicationDraftTests.retirement

    def setUp(self):
        helpers.LivePublicationDraftTests.setUp(self)
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.addCleanup(self.pool.shutdown, wait=True)
        self.check = None

    def prepare(self, **options):
        self.retirement()
        self.retained = self.lifecycle._owned_buffer
        self.check = channel.NativePublicationCommitCheck(self.lifecycle, **options)
        self.addCleanup(self.check.close)
        return self.check

    def run_check(self, **overrides):
        if self.check is None: self.prepare()
        values = dict(app='app', credential=self.credential, proposal=self.proposal, descriptor=self.descriptor)
        values.update(overrides)
        return self.check.run(values['app'], values['credential'], values['proposal'], values['descriptor'])

    def terminal(self):
        self.assertEqual(self.model._state, 'closed')
        self.assertEqual(self.recipient._state, 'closed')
        self.assertIs(self.recipient._terminal, True)
        self.assertIsNone(self.recipient._claim)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        self.assertEqual(self.retained, bytearray())

    def reject(self, operation):
        with self.assertRaises(channel.LiveChannelCheckError): operation()
        self.terminal()

    def helper(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'native-commit-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_native_commit_entry as entry\n'+prefix+'\nentry.run()\n'+ending,
            encoding='utf-8')
        return patch.object(process._PublicationCommitPeer, '_entry_path', return_value=path)

    def ready_fault(self, effect):
        self.prepare(); original = PublicationCommitExchange.accept_ready; reached = []
        def ready(wire, frame):
            result = original(wire, frame)
            self.assertIs(wire, self.check._issued_commit._issued_wire)
            self.assertIsNone(self.check._issued_child.poll())
            self.assertEqual(bytes(self.retained), self.DATA)
            reached.append(True); effect(); return result
        with patch.object(PublicationCommitExchange, 'accept_ready', ready): self.reject(self.run_check)
        self.assertEqual(reached, [True], 'fault must follow genuine private native READY')

    def consume_fault(self, effect, *, after=False):
        self.prepare(); original = LivePublicationDraft._check_publication; reached = []
        def consume(source, *args):
            self.assertIs(source, self.lifecycle)
            self.assertIsNotNone(self.check._issued_commit)
            self.assertEqual(self.check._issued_commit._wire._step, 3)
            self.assertIsNone(self.check._issued_child.poll())
            reached.append(True)
            if not after: effect()
            result = original(source, *args)
            if after: effect()
            return result
        with patch.object(LivePublicationDraft, '_check_publication', consume): self.reject(self.run_check)
        self.assertEqual(reached, [True], 'fault must reach one-use consume boundary')

    def receipt_fault(self, effect):
        self.prepare(); original = PublicationCommitExchange.accept_receipt; reached = []
        def receipt(wire, frame):
            result = original(wire, frame)
            self.assertIs(wire, self.check._issued_commit._issued_wire)
            child = self.check._issued_child
            child._retired()
            self.assertIsNone(child._process)
            self.assertIsNone(child._job)
            self.assertEqual(self.retained, bytearray())
            reached.append(True); effect(result); return result
        with patch.object(PublicationCommitExchange, 'accept_receipt', receipt): self.reject(self.run_check)
        self.assertEqual(reached, [True], 'fault must follow genuine receipt and original joined peer')

    def test_native_ready_consumption_and_receipt_are_ordered_and_never_deliver_bytes(self):
        self.prepare(); events = []
        original_ready = PublicationCommitExchange.accept_ready
        original_consume = LivePublicationDraft._check_publication
        original_receipt = PublicationCommitExchange.accept_receipt
        def ready(wire, frame):
            value = original_ready(wire, frame)
            self.assertEqual(value.outcome, 'prepared')
            self.assertEqual(bytes(self.retained), self.DATA)
            self.assertIsNone(self.check._child.poll())
            events.append('private_ready'); return value
        def consume(source, *args):
            self.assertEqual(events, ['private_ready'])
            self.assertEqual(bytes(self.retained), self.DATA)
            self.assertIsNone(self.check._child.poll())
            result = original_consume(source, *args)
            self.assertEqual(self.retained, bytearray())
            self.assertIsNone(self.check._child.poll())
            events.append('consumed_and_wiped'); return result
        def receipt(wire, frame):
            self.assertEqual(events, ['private_ready', 'consumed_and_wiped'])
            child = self.check._issued_child
            child._retired()
            self.assertEqual(child._exit, 0)
            self.assertIsNone(child._process); self.assertIsNone(child._job)
            value = original_receipt(wire, frame)
            self.assertEqual((value.outcome, value.released_bytes), ('dry_run_retired', 0))
            events.append('joined_private_receipt'); return value
        with patch.object(PublicationCommitExchange, 'accept_ready', ready), \
                patch.object(LivePublicationDraft, '_check_publication', consume), \
                patch.object(PublicationCommitExchange, 'accept_receipt', receipt):
            result = self.run_check()
        self.assertEqual(events, ['private_ready', 'consumed_and_wiped', 'joined_private_receipt'])
        self.assertIs(type(result), FinalPublicationDraftCheck)
        self.assertEqual((result.staged_bytes, result.released_bytes, result.disposition), (37, 0, 'eligible_discarded'))
        self.assertEqual(result.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertIs(self.check._commit, self.check._issued_commit)
        self.assertIs(self.check._commit._terminal, True)
        self.assertEqual(self.check._commit._state, 'retired')
        self.assertIsNone(self.check.retired_check())
        self.assertIs(self.check.shutdown_status().cleanup_confirmed, True)
        self.terminal()
        with self.assertRaises(TypeError): bool(result)
        for name in ('read', 'publish', 'release', 'deliver', 'data'):
            self.assertFalse(hasattr(self.check, name))

    def test_bad_credential_burns_without_peer_launch(self):
        self.prepare()
        with patch.object(channel, '_PublicationCommitPeer') as launch:
            self.reject(lambda: self.run_check(credential='wrong')); launch.assert_not_called()
        self.reject(self.run_check)

    def test_application_substitution_cannot_transfer_review(self):
        self.prepare(); credential = self.registry.register('other', ['files.read'])
        self.reject(lambda: self.run_check(app='other', credential=credential))

    def test_changed_proposal_cannot_inherit_review(self):
        self.prepare(); self.reject(lambda: self.run_check(proposal=make_file_read_proposal('changed', max_bytes=128)))

    def test_descriptor_copy_is_not_original_recipient(self):
        self.prepare(); self.reject(lambda: self.run_check(descriptor=replace(self.descriptor)))

    def test_revoked_source_cannot_launch_native_peer(self):
        self.prepare(); self.registry.revoke('app')
        with patch.object(channel, '_PublicationCommitPeer') as launch:
            self.reject(self.run_check); launch.assert_not_called()

    def test_revocation_after_genuine_ready_withholds_commit(self):
        self.ready_fault(lambda: self.registry.revoke('app'))

    def test_rotation_after_genuine_ready_withholds_commit(self):
        self.ready_fault(lambda: self.registry.rotate_credential('app'))

    def test_permission_removal_after_genuine_ready_withholds_commit(self):
        self.ready_fault(lambda: self.registry.update_permissions('app', scopes=[]))

    def test_draft_version_change_after_genuine_ready_withholds_commit(self):
        self.ready_fault(lambda: self.ledger.replace(self.draft.draft_id, 1, self.constraint))

    def test_cancellation_after_genuine_ready_wipes_without_commit(self):
        self.ready_fault(lambda: self.check.close())

    def test_quarantine_mutation_after_genuine_ready_wipes_without_commit(self):
        self.ready_fault(lambda: self.retained.extend(b'x'))

    def test_native_observation_copy_after_genuine_ready_is_rejected(self):
        self.ready_fault(lambda: setattr(self.check, '_native_observation', replace(self.check._native_observation)))

    def test_commit_envelope_mutation_after_ready_is_rejected(self):
        self.ready_fault(lambda: setattr(self.check._issued_commit, '_envelope', b'{}'))

    def test_commit_wire_substitution_after_ready_preserves_foreign_object(self):
        foreign = Mock()
        self.ready_fault(lambda: setattr(self.check._issued_commit, '_wire', foreign))
        foreign.close.assert_not_called()

    def test_commit_owner_substitution_after_ready_preserves_foreign_object(self):
        foreign = Mock()
        self.ready_fault(lambda: setattr(self.check, '_commit', foreign))
        foreign.close.assert_not_called()

    def substituted_owner_fault(self, field, *, receipt=False):
        foreign = SimpleNamespace(_lock=MagicMock(), close=Mock())
        if receipt: self.receipt_fault(lambda result: setattr(self.check, field, foreign))
        else: self.ready_fault(lambda: setattr(self.check, field, foreign))
        foreign._lock.__enter__.assert_not_called()
        foreign.close.assert_not_called()

    def test_foreign_lifecycle_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_lifecycle')

    def test_foreign_recipient_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_recipient')

    def test_foreign_acquisition_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_acquisition')

    def test_foreign_review_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_review')

    def test_foreign_lifecycle_during_receipt_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_lifecycle', receipt=True)

    def test_foreign_recipient_during_receipt_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_recipient', receipt=True)

    def test_foreign_acquisition_during_receipt_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_acquisition', receipt=True)

    def test_foreign_review_during_receipt_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_review', receipt=True)

    def test_foreign_issued_lifecycle_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_issued_lifecycle')

    def test_foreign_issued_recipient_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_issued_recipient')

    def test_foreign_issued_acquisition_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_issued_acquisition')

    def test_foreign_issued_review_after_ready_is_rejected_before_foreign_lock(self):
        self.substituted_owner_fault('_issued_review')

    def test_foreign_draft_issued_helper_is_rejected_before_foreign_lock_or_cancel(self):
        foreign = SimpleNamespace(_lock=MagicMock(), close=Mock())
        self.ready_fault(lambda: setattr(self.check._issued_commit, '_issued_helper', foreign))
        foreign._lock.__enter__.assert_not_called()
        foreign.close.assert_not_called()
        self.assertIs(self.check._issued_commit._issued_timer.finished.is_set(), True,
            'original draft timeout worker must be cancelled even after owner substitution')
        self.assertEqual(self.check._issued_commit._issued_wire._key, b'',
            'original draft codec key must be retired even after owner substitution')
        self.assertEqual(self.check._issued_commit._issued_wire._state, 'closed')

    def test_revocation_during_consume_is_rejected(self):
        self.consume_fault(lambda: self.registry.revoke('app'))

    def test_revocation_immediately_after_consume_withholds_receipt_result(self):
        self.consume_fault(lambda: self.registry.revoke('app'), after=True)

    def test_cancel_immediately_after_consume_withholds_receipt_result(self):
        self.consume_fault(lambda: self.check.close(), after=True)

    def test_reintroduced_bytes_after_consume_are_wiped(self):
        self.consume_fault(lambda: self.retained.extend(self.DATA), after=True)

    def test_false_release_result_after_consume_is_rejected(self):
        self.prepare(); original = LivePublicationDraft._check_publication; reached = []
        def consume(source, *args):
            result = original(source, *args); reached.append(True)
            object.__setattr__(result, 'released_bytes', 1); return result
        with patch.object(LivePublicationDraft, '_check_publication', consume): self.reject(self.run_check)
        self.assertEqual(reached, [True])

    def test_revocation_during_joined_receipt_validation_withholds_result(self):
        self.receipt_fault(lambda result: self.registry.revoke('app'))

    def test_rotation_during_joined_receipt_validation_withholds_result(self):
        self.receipt_fault(lambda result: self.registry.rotate_credential('app'))

    def test_cancel_during_joined_receipt_validation_withholds_result(self):
        self.receipt_fault(lambda result: self.check.close())

    def test_reintroduced_bytes_during_joined_receipt_validation_are_wiped(self):
        self.receipt_fault(lambda result: self.retained.extend(self.DATA))

    def test_receipt_mutation_cannot_report_protected_delivery(self):
        self.receipt_fault(lambda result: object.__setattr__(result, 'released_bytes', 1))

    def test_receipt_type_confusion_cannot_report_protected_delivery(self):
        self.receipt_fault(lambda result: object.__setattr__(result, 'released_bytes', False))

    def test_commit_proof_swap_during_receipt_validation_is_rejected(self):
        self.receipt_fault(lambda result: setattr(self.check, '_proof', replace(self.check._proof)))

    def test_native_retirement_mutation_during_receipt_validation_is_rejected(self):
        self.receipt_fault(lambda result: setattr(self.check._issued_child, '_cleanup_failed', True))

    def test_helper_state_swap_during_final_retired_native_query_is_rechecked(self):
        self.prepare(); original = channel.NativePublicationCommitCheck._terminal_channel; reached = []
        def terminal(owner):
            original(owner)
            if owner._issued_commit._receipt is not None and not reached:
                self.assertEqual(owner._issued_commit._state, 'consumed')
                self.assertEqual(owner._issued_commit._wire._step, 4)
                reached.append(True); owner._state = 'prepared'
        with patch.object(channel.NativePublicationCommitCheck, '_terminal_channel', terminal):
            self.reject(self.run_check)
        self.assertEqual(reached, [True], 'state swap must follow real native retirement and receipt parser')

    def test_live_synthetic_finish_is_unavailable_for_native_draft(self):
        self.prepare(); original = PublicationCommitExchange.accept_ready; reached = []
        def ready(wire, frame):
            value = original(wire, frame); reached.append(True)
            with self.assertRaises(PublicationCommitError): self.check._issued_commit.finish(b'')
            return value
        with patch.object(PublicationCommitExchange, 'accept_ready', ready): self.reject(self.run_check)
        self.assertEqual(reached, [True])

    def test_native_success_is_one_use_and_replay_cannot_release(self):
        self.assertEqual(self.run_check().released_bytes, 0)
        self.reject(self.run_check)
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()

    def test_receipt_copy_after_return_is_rejected(self):
        self.run_check(); self.check._issued_commit._receipt = replace(self.check._issued_commit._receipt)
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.terminal()

    def test_commit_wire_rollback_after_return_is_rejected(self):
        self.run_check(); self.check._issued_commit._wire._step = 3
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.terminal()

    def test_commit_state_rollback_cannot_restore_a_consumed_source(self):
        self.run_check(); self.check._issued_commit._state = 'consumed'
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.assertIs(self.lifecycle._publication_attempted, True)
        self.terminal()

    def test_native_commit_owner_copy_after_return_cannot_replace_original(self):
        self.run_check(); foreign = Mock(); self.check._commit = foreign
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.check.close()
        foreign.close.assert_not_called(); foreign.retired_check.assert_not_called()
        self.terminal()

    def test_foreign_issued_child_after_return_is_rejected_before_native_dispatch(self):
        self.run_check(); foreign = MagicMock(); self.check._issued_child = foreign
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.check.close()
        foreign._retired.assert_not_called(); foreign.close.assert_not_called()
        self.terminal()

    def test_retired_receipt_finish_cannot_be_replayed(self):
        self.run_check(); draft = self.check._issued_commit
        with self.assertRaises(PublicationCommitError): draft.finish_retired(b'')
        with self.assertRaises(channel.LiveChannelCheckError): self.check.retired_check()
        self.terminal()

    def test_valid_native_receipts_then_nonzero_exit_are_rejected(self):
        self.prepare()
        with self.helper(ending='os._exit(9)'): self.reject(self.run_check)

    def test_valid_native_receipts_then_trailing_output_are_rejected(self):
        self.prepare()
        with self.helper(ending="sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"): self.reject(self.run_check)

    def test_valid_commit_receipt_with_invalid_witness_ack_cannot_be_sealed(self):
        self.prepare()
        prefix = ('original_ack=entry.RecipientWitnessExchange.acknowledge_retirement\n'
            'def altered_ack(wire):\n'
            ' value=bytearray(original_ack(wire));value[-1]^=1;return bytes(value)\n'
            'entry.RecipientWitnessExchange.acknowledge_retirement=altered_ack')
        with self.helper(prefix=prefix), patch.object(PublicationCommitExchange, 'accept_receipt') as parse:
            self.reject(self.run_check); parse.assert_not_called()

    def test_valid_witness_ack_cannot_restore_tampered_commit_receipt(self):
        self.prepare()
        prefix = ('original_receipt=entry.PublicationCommitExchange.receipt\n'
            'def altered_receipt(wire):\n'
            ' value=bytearray(original_receipt(wire));value[-1]^=1;return bytes(value)\n'
            'entry.PublicationCommitExchange.receipt=altered_receipt')
        with self.helper(prefix=prefix): self.reject(self.run_check)
        self.assertIsNotNone(self.check._ack, 'valid witness ACK must precede rejected commit receipt')

    def buffered_fault(self, effect):
        self.prepare(); original = channel.os.read; reached = []
        def read(fd, size):
            child = self.check._issued_child
            if (size == 1 and child is not None and fd == child.stdout_fd
                    and child._input_closed and self.check._issued_commit._state == 'consumed'
                    and not reached):
                self.assertIsNone(self.check._ack, 'both buffered frames must remain unparsed')
                self.assertIsNone(self.check._issued_commit._receipt)
                self.assertEqual(self.retained, bytearray())
                reached.append(True); effect()
            return original(fd, size)
        with patch.object(channel.os, 'read', read): self.reject(self.run_check)
        self.assertEqual(reached, [True], 'fault must follow private terminal-frame buffering')

    def test_revocation_after_terminal_frames_buffered_withholds_result(self):
        self.buffered_fault(lambda: self.registry.revoke('app'))

    def test_cancel_after_terminal_frames_buffered_withholds_result(self):
        self.buffered_fault(lambda: self.check.close())

    def test_reinserted_bytes_after_terminal_frames_buffered_are_wiped(self):
        self.buffered_fault(lambda: self.retained.extend(self.DATA))

    def test_native_startup_hang_is_bounded_and_joined(self):
        self.prepare(timeout=1)
        with self.helper(prefix='time.sleep(30)'): self.reject(self.run_check)
        self.assertIs(self.check.shutdown_status().cleanup_confirmed, True)

    def test_native_startup_forgery_is_rejected(self):
        self.prepare()
        with self.helper(prefix="sys.stdout.buffer.write(b'x'*32);sys.stdout.buffer.flush();os._exit(0)"):
            self.reject(self.run_check)

    def test_native_receipts_followed_by_hang_cannot_be_accepted(self):
        self.prepare(timeout=1)
        with self.helper(ending='time.sleep(30)'): self.reject(self.run_check)

    def test_cancel_waiting_native_worker_joins_before_cleanup_confirmation(self):
        self.prepare()
        with self.helper(prefix='time.sleep(30)'):
            future = self.pool.submit(self.run_check)
            deadline = time.monotonic()+2
            while not self.check._started and time.monotonic() < deadline: time.sleep(.002)
            self.assertIs(self.check._started, True)
            self.check.close()
            with self.assertRaises(channel.LiveChannelCheckError): future.result(timeout=3)
        self.assertIs(self.check._finished, True)
        self.assertIs(self.check.shutdown_status().cleanup_confirmed, True)
        self.terminal()

    def test_duplicate_native_worker_cancels_original_one_use_attempt(self):
        self.prepare()
        with self.helper(prefix='time.sleep(30)'):
            future = self.pool.submit(self.run_check)
            deadline = time.monotonic()+2
            while not self.check._started and time.monotonic() < deadline: time.sleep(.002)
            self.assertIs(self.check._started, True)
            with self.assertRaises(channel.LiveChannelCheckError): self.run_check()
            with self.assertRaises(channel.LiveChannelCheckError): future.result(timeout=3)
        self.assertIs(self.check.shutdown_status().cleanup_confirmed, True)
        self.terminal()

    def test_native_cleanup_failure_withholds_even_zero_byte_metadata(self):
        self.prepare(); original = guarded_process._RecipientWitnessChild.close; reached = []
        def close(child):
            original(child); reached.append(True)
            raise guarded_process.BrokerProcessError('process_cleanup_failed')
        with patch.object(guarded_process._RecipientWitnessChild, 'close', close): self.reject(self.run_check)
        self.assertTrue(reached)
        self.assertIs(self.check.shutdown_status().cleanup_confirmed, False)


if __name__ == '__main__': unittest.main()
