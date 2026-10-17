"""Adversarial inactive native-fixture composition; no application delivery.

Only generated fixtures are used. Faults follow genuine native/protocol phases;
scripted operator answers are test orchestration, never human authentication.
"""
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

from core import broker_source_admission as admission
from core import broker_source_fixture_host as host
from core import broker_source_fixture_process as process
from core import broker_transport as transport
from core import test_broker_review_host as helpers
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.broker_source_association_protocol import SourceRecipientAssociationExchange


class SourceFixtureHostAdversarialTests(unittest.TestCase):
    def setUp(self):
        helpers.BrokerReviewHostTests.setUp(self)
        self.host.close()
        self.host = host.BrokerSourceFixtureHost(self.registry, self.ledger)
        self.addCleanup(self.host.close)
        self.slot = transport._slot

    run_host = helpers.BrokerReviewHostTests.run_host
    start = helpers.BrokerReviewHostTests.start

    def original_native(self):
        stage = self.host._issued_fixture_stage
        self.assertIsNotNone(stage, 'fixed first native stage must exist')
        native = stage._native_original()
        self.assertIsNotNone(native, 'first original native child must have been captured')
        self.assertIs(type(native.child), process._SourceFixtureChild)
        return stage, native

    def assert_rejected(self, future, display):
        with self.assertRaises(host.BrokerReviewHostError):
            future.result(timeout=12)
        self.assertEqual(self.host.operator.pending(), ())
        self.assertFalse(Path(display.display_path).exists(), 'generated fixture must be deleted')
        lifecycle = self.host._issued_lifecycle
        self.assertIsNotNone(lifecycle)
        self.assertEqual(lifecycle._state, 'closed', 'original logical source must be retired')
        self.assertEqual(self.host._issued_model._state, 'closed')
        self.assertEqual(self.host._issued_recipient._state, 'closed')
        self.assertIs(self.host._issued_recipient._terminal, True)
        self.assertIsNone(self.host._issued_recipient._claim)
        if lifecycle._owned_buffer is not None:
            self.assertEqual(lifecycle._owned_buffer, bytearray(), 'private quarantine must be empty')
        custody = self.host._issued_custody
        self.assertIsNone(custody._status().result, 'no success evidence may escape')

    def entry_fault(self, *, prefix='', ending=''):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'fixed-first-fixture-fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core import broker_publication_entry as entry\n'+prefix+
            '\nentry.run()\n'+ending, encoding='utf-8')
        return patch.object(process._SourceFixtureChild, '_entry_path', return_value=path)

    def allow_fault(self, fault):
        with fault:
            future, display = self.start()
            self.host.operator.respond(display, 'ALLOW ONCE')
            self.assert_rejected(future, display)

    def proof_fault(self, phase, action):
        kind = RecipientWitnessExchange if phase == 'witness' else SourceRecipientAssociationExchange
        original = kind.accept_proof
        reached = []
        def proof(wire, frame):
            result = original(wire, frame)
            if type(wire) is not kind:
                return result
            stage, native = self.original_native()
            self.assertIs(native.child._closed, True)
            self.assertIs(native.child._cleanup_failed, False)
            self.assertEqual(native.child._retired_snapshot, (0, True))
            self.assertFalse(self.slot.acquire(blocking=False), 'one original admission spans all peers')
            reached.append(True)
            action(stage, native)
            return result
        with patch.object(kind, 'accept_proof', proof):
            future, display = self.start()
            self.host.operator.respond(display, 'ALLOW ONCE')
            self.assert_rejected(future, display)
        self.assertEqual(reached, [True], 'fault must follow the selected genuine proof')
        self.assertEqual(self.slot._value, 0, 'uncertain first-native retirement must poison admission')

    def outer_release_fault(self, action):
        original = threading.Condition.notify
        reached = []
        def notify(condition, n=1):
            result = original(condition, n)
            custody = getattr(self.host, '_issued_custody', None)
            if custody is None or condition is not custody._original().condition or reached:
                return result
            owner = custody._original()
            self.assertTrue(owner.slot_lock.locked(), 'post-notify fence must exclude later admission')
            self.assertFalse(owner.slot_lock.acquire(blocking=False))
            self.assertEqual(owner.slot._value, 1)
            gate = custody._status().gate
            self.assertFalse(gate._worker_original().association_thread.is_alive())
            self.assertFalse(gate._worker_original().witness._original().thread.is_alive())
            stage, native = self.original_native()
            self.assertEqual(native.child._retired_snapshot, (0, True))
            reached.append(True)
            action(stage, native)
            return result
        with patch.object(threading.Condition, 'notify', notify):
            future, display = self.start()
            self.host.operator.respond(display, 'ALLOW ONCE')
            self.assert_rejected(future, display)
        self.assertEqual(reached, [True], 'fault must follow the genuine outer notification')
        self.assertEqual(self.slot._value, 0, 'failure must roll back while original slot guard is held')

    def test_first_native_fixture_stays_under_admission_through_both_metadata_peers(self):
        reached = []
        original_witness = RecipientWitnessExchange.accept_proof
        original_association = SourceRecipientAssociationExchange.accept_proof
        def check(name, wire, result):
            stage, native = self.original_native()
            self.assertEqual(native.child._retired_snapshot, (0, True))
            self.assertFalse(self.slot.acquire(blocking=False))
            reached.append(name)
            return result
        def witness(wire, frame):
            result = original_witness(wire, frame)
            return check('witness', wire, result) if type(wire) is RecipientWitnessExchange else result
        def association(wire, frame):
            return check('association', wire, original_association(wire, frame))
        with patch.object(RecipientWitnessExchange, 'accept_proof', witness), \
                patch.object(SourceRecipientAssociationExchange, 'accept_proof', association):
            future, display = self.start()
            self.assertFalse(self.slot.acquire(blocking=False), 'review must retain original admission')
            self.host.operator.respond(display, 'ALLOW ONCE')
            result = future.result(timeout=12)
        self.assertEqual(reached, ['witness', 'association'])
        self.assertEqual((result.outcome, result.released_bytes), ('associated_discarded', 0))
        self.assertFalse(hasattr(result, 'data'))
        self.assertFalse(Path(display.display_path).exists())
        self.assertEqual(self.slot._value, 1)
        with self.assertRaises(TypeError): bool(result)

    def test_genuine_first_child_nonzero_exit_after_native_retirement_never_starts_rendezvous(self):
        with patch.object(admission._CustodiedRendezvous, 'run', side_effect=AssertionError('invalid first exit')) as run:
            self.allow_fault(self.entry_fault(ending='os._exit(7)\n'))
            run.assert_not_called()

    def test_genuine_first_child_extra_output_after_ack_never_starts_rendezvous(self):
        with patch.object(admission._CustodiedRendezvous, 'run', side_effect=AssertionError('trailing first output')) as run:
            self.allow_fault(self.entry_fault(ending='sys.stdout.buffer.write(b"extra");sys.stdout.buffer.flush()\n'))
            run.assert_not_called()

    def test_genuine_first_child_duplicate_retirement_ack_is_not_one_retirement(self):
        prefix = ('_retire=entry.PublicationNativeFixtureAdapter.retire\n'
            '_saved=[]\n'
            'def retire(self,frame):\n'
            '    value=_retire(self,frame);_saved.append(value);return value\n'
            'entry.PublicationNativeFixtureAdapter.retire=retire\n')
        self.allow_fault(self.entry_fault(prefix=prefix,
            ending='sys.stdout.buffer.write(_saved[0]);sys.stdout.buffer.flush()\n'))

    def test_genuine_first_child_corrupt_retirement_ack_is_rejected_after_native_cleanup(self):
        prefix = ('_retire=entry.PublicationNativeFixtureAdapter.retire\n'
            'def retire(self,frame):\n'
            '    value=_retire(self,frame);return value[:-1]+bytes([value[-1]^1])\n'
            'entry.PublicationNativeFixtureAdapter.retire=retire\n')
        self.allow_fault(self.entry_fault(prefix=prefix))

    def test_first_child_exit_before_retirement_ack_deletes_fixture_and_rejects(self):
        prefix = ('def retire(self,frame):\n'
            '    os._exit(7)\n'
            'entry.PublicationNativeFixtureAdapter.retire=retire\n')
        self.allow_fault(self.entry_fault(prefix=prefix))

    def test_first_child_hang_after_ack_is_not_completed_native_retirement(self):
        started = time.monotonic()
        self.allow_fault(self.entry_fault(ending='time.sleep(30)\n'))
        self.assertLess(time.monotonic()-started, 12, 'original expiry and bounded cleanup must stop the child')

    def test_first_native_ownership_mutation_at_review_never_becomes_approval(self):
        future, display = self.start()
        stage, native = self.original_native()
        native.child._owned = tuple(list(native.owned))
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.assert_rejected(future, display)
        self.assertEqual(self.slot._value, 0)

    def test_first_native_process_observation_mutation_at_review_is_not_requester_identity(self):
        future, display = self.start()
        stage, native = self.original_native()
        object.__setattr__(native.observation, 'creation_time', native.observation.creation_time+1)
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.assert_rejected(future, display)
        self.assertEqual(self.slot._value, 0)

    def test_foreign_review_manager_never_receives_disposal_callbacks(self):
        future, display = self.start()
        foreign = Mock()
        self.host._issued_model._reviews = foreign
        self.host.close()
        self.assert_rejected(future, display)
        self.assertEqual(foreign.mock_calls, [], 'cleanup must retire the captured original review manager')
        self.assertEqual(self.slot._value, 0)

    def test_foreign_acquisition_owner_never_receives_disposal_callbacks(self):
        future, display = self.start()
        foreign = MagicMock()
        self.host._issued_lifecycle._acquisition = foreign
        self.host.close()
        self.assert_rejected(future, display)
        self.assertEqual(foreign.mock_calls, [], 'cleanup must retire the captured original acquisition')
        self.assertEqual(self.slot._value, 0)

    def test_foreign_original_condition_lock_never_receives_pending_query_callbacks(self):
        future, display = self.start()
        self.host.operator.respond(display, 'DENY')
        self.assertEqual(future.result(timeout=12).released_bytes, 0)
        condition = self.host._original().condition
        original, foreign = condition._lock, MagicMock()
        try:
            condition._lock = foreign
            self.assertEqual(self.host.operator.pending(), ())
            self.assertEqual(foreign.mock_calls, [], 'original synchronization must be checked before entering it')
        finally:
            condition._lock = original  # Test harness disposal only; no authority is restored.

    def test_first_native_archive_erasure_at_witness_proof_poisoned(self):
        def erase(stage, native):
            stage._native = stage._issued_native = stage._recovery_native = None
        self.proof_fault('witness', erase)

    def test_first_native_archive_erasure_at_association_proof_poisoned(self):
        def erase(stage, native):
            stage._native = stage._issued_native = stage._recovery_native = None
        self.proof_fault('association', erase)

    def test_first_native_cleanup_flag_change_at_witness_proof_poisoned(self):
        self.proof_fault('witness', lambda stage, native: setattr(native.child, '_cleanup_failed', True))

    def test_first_native_cleanup_flag_change_at_association_proof_poisoned(self):
        self.proof_fault('association', lambda stage, native: setattr(native.child, '_cleanup_failed', True))

    def test_first_native_coherent_nonzero_retirement_at_witness_proof_cannot_inherit_success(self):
        def change(stage, native):
            native.child._exit = 7
            native.child._retired_snapshot = (7, True)
        self.proof_fault('witness', change)

    def test_first_native_coherent_nonzero_retirement_at_association_proof_cannot_inherit_success(self):
        def change(stage, native):
            native.child._exit = 7
            native.child._retired_snapshot = (7, True)
        self.proof_fault('association', change)

    def test_first_native_coherent_missing_input_retirement_at_association_cannot_inherit_success(self):
        def change(stage, native):
            native.child._input_closed = False
            native.child._retired_snapshot = (0, False)
        self.proof_fault('association', change)

    def test_first_native_original_handle_tuple_substitution_at_association_poisoned(self):
        self.proof_fault('association',
            lambda stage, native: setattr(native.child, '_owned', tuple(list(native.owned))))

    def test_first_native_process_observation_mutation_at_association_poisoned(self):
        self.proof_fault('association', lambda stage, native:
            object.__setattr__(native.observation, 'pid', native.observation.pid+1))

    def test_coherent_source_transcript_mutation_at_association_cannot_replace_archived_ack(self):
        def change(stage, native):
            wire = self.host._issued_lifecycle._wire
            self.assertEqual((wire._step, wire._state), (4, 'retired_for_check'))
            original = wire._previous
            wire._previous = ('1' if original[0] == '0' else '0')+original[1:]
            wire._phase_snapshot = (wire._step, wire._previous, wire._state)
            self.assertNotEqual(wire._previous, original)
        self.proof_fault('association', change)

    def test_first_native_cleanup_mutation_after_outer_notify_rolls_back_shared_admission(self):
        self.outer_release_fault(lambda stage, native: setattr(native.child, '_cleanup_failed', True))

    def test_first_native_archive_erasure_after_outer_notify_cannot_claim_never_launched(self):
        def erase(stage, native):
            stage._native = stage._issued_native = stage._recovery_native = None
        self.outer_release_fault(erase)

    def test_first_native_retirement_mutation_after_outer_notify_rolls_back(self):
        def change(stage, native):
            native.child._exit = 7
            native.child._retired_snapshot = (7, True)
        self.outer_release_fault(change)

    def test_first_native_late_mutation_after_real_release_never_reclaims_newer_admission(self):
        original = admission._SourceAdmissionCustody._retire
        reached, newer = [], []
        def retire(custody, candidate):
            sealed = original(custody, candidate)
            if custody is not self.host._issued_custody:
                return sealed
            self.assertIs(custody._original().retired.is_set(), True)
            replacement = admission._SourceAdmissionCustody()
            replacement.acquire()
            newer.append(replacement)
            self.assertEqual(self.slot._value, 0)
            stage, native = self.original_native()
            native.child._cleanup_failed = True
            reached.append(True)
            return sealed
        with patch.object(admission._SourceAdmissionCustody, '_retire', retire):
            future, display = self.start()
            self.host.operator.respond(display, 'ALLOW ONCE')
            with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=12)
        self.assertEqual(reached, [True], 'mutation must follow genuine release and later admission')
        self.assertEqual(self.slot._value, 0)
        self.assertFalse(newer[0]._original().cancel.is_set(), 'old rejection cannot cancel the newer owner')
        self.assertFalse(Path(display.display_path).exists())
        self.assertEqual(self.host._issued_lifecycle._owned_buffer, bytearray())


if __name__ == '__main__':
    unittest.main()
