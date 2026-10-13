"""Adversarial private custody tests; synthetic source, two real native peers.

The acquisition frames are deliberately synthetic. These tests establish no
native file-acquisition custody, human authentication, delivery or permission.
"""
import copy
from contextlib import contextmanager
from dataclasses import asdict
import threading
import unittest
from unittest.mock import Mock, patch

from core import broker_source_admission as admission
from core import broker_transport as transport
from core import test_broker_live_review as review_helpers
from core import test_broker_publication_lifecycle as publication_helpers
from core import test_broker_source_admission as helpers
from core.broker_publication_lifecycle import LivePublicationDraft
from core.broker_source_rendezvous import SourceAssociationRendezvousDryRun


def foreign_call(action):
    """Run only a test attempt on another real thread, retaining its failure."""
    outcome = []
    def run():
        try: outcome.append(('returned', action()))
        except BaseException as error: outcome.append(('raised', error))
    worker = threading.Thread(target=run)
    worker.start(); worker.join(1)
    if worker.is_alive(): raise AssertionError('foreign bootstrap call did not return')
    return outcome[0]


class SourceAdmissionBootstrapAdversarialTests(unittest.TestCase):
    """Malformed NEW graphs are rejected before a review or native launch."""
    def setUp(self):
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.custody = admission._SourceAdmissionCustody()
        self.custody.acquire()
        review_helpers.LiveReviewMappingTests.setUp(self)
        publication_helpers.LivePublicationDraftTests.install(self)

    def assert_held(self):
        self.assertEqual(transport._slot._value, 0)
        self.assertFalse(transport._slot.acquire(blocking=False))

    @contextmanager
    def fresh_attempt(self):
        # A rejection spends its owner irreversibly. Every table entry gets a
        # distinct admission object, so a previous poison cannot mask a case.
        with patch.object(transport, '_slot', threading.BoundedSemaphore(1)):
            custody = admission._SourceAdmissionCustody()
            custody.acquire()
            yield custody

    def bad_source(self, owner, name, value):
        original = getattr(owner, name)
        with self.fresh_attempt() as custody:
            try:
                setattr(owner, name, value)
                with self.assertRaises(admission.SourceAdmissionError):
                    custody.bind_source(self.lifecycle)
                self.assertIs(custody._status().bound, False)
                self.assert_held()
            finally: setattr(owner, name, original)

    def test_requester_mapping_and_unrelated_owners_are_not_a_new_trusted_source(self):
        for value in ({'admitted': True}, self.descriptor, self.model, self.acquisition):
            with self.subTest(kind=type(value).__name__), self.fresh_attempt() as custody:
                with self.assertRaises(admission.SourceAdmissionError): custody.bind_source(value)
        self.assert_held()

    def test_exact_source_subclass_is_not_accepted(self):
        class ForeignSource(LivePublicationDraft): pass
        value = ForeignSource(self.acquisition, self.recipient)
        with self.assertRaises(admission.SourceAdmissionError): self.custody.bind_source(value)
        self.assert_held()

    def test_source_new_label_does_not_hide_review_already_started(self):
        for state in ('await_observation', 'shown', 'recorded', 'closed'):
            with self.subTest(state=state): self.bad_source(self.model, '_state', state)

    def test_source_new_label_does_not_hide_acquisition_attempt(self):
        for name, value in (('_closed', True), ('_attempted', True), ('_issued', object())):
            with self.subTest(field=name): self.bad_source(self.acquisition, name, value)

    def test_source_new_label_does_not_hide_preexisting_quarantine_or_token(self):
        for name, value in (('_wire', object()), ('_owned_buffer', bytearray(b'old')),
                            ('_token', object()), ('_publication_attempted', True)):
            with self.subTest(field=name): self.bad_source(self.lifecycle, name, value)

    def test_new_source_cannot_carry_prior_staging_or_retirement_evidence(self):
        for name, value in (('_summary', object()), ('_retirement', object()), ('_closing', True),
                            ('_recipient_snapshot', b'old'), ('_recipient_descriptor', self.descriptor),
                            ('_source_deadline_snapshot', 1.0)):
            with self.subTest(field=name): self.bad_source(self.lifecycle, name, value)

    def test_new_review_cannot_carry_prior_display_evidence(self):
        self.bad_source(self.model, '_shown', object())

    def test_type_confused_new_flags_are_rejected(self):
        for owner, name, value in ((self.lifecycle, '_cancelled', 0),
                (self.lifecycle, '_publication_attempted', 0), (self.acquisition, '_closed', 0),
                (self.acquisition, '_attempted', 0), (self.recipient, '_ever_claimed', 0)):
            with self.subTest(field=name): self.bad_source(owner, name, value)

    def test_foreign_acquisition_or_review_manager_never_dispatches(self):
        for owner, name in ((self.lifecycle, '_acquisition'), (self.model, '_reviews'),
                            (self.model, '_exchange')):
            foreign = Mock()
            with self.subTest(field=name):
                self.bad_source(owner, name, foreign)
                self.assertEqual(foreign.mock_calls, [])

    def test_other_bootstrap_thread_cannot_bind_source(self):
        kind, result = foreign_call(lambda: self.custody.bind_source(self.lifecycle))
        self.assertEqual(kind, 'raised'); self.assertIsInstance(result, admission.SourceAdmissionError)
        self.assertFalse(self.custody._status().bound); self.assert_held()
        self.assertFalse(self.custody._status().poisoned)
        self.custody.bind_source(self.lifecycle)

    def test_private_handoff_cannot_be_constructed_from_requester_claims(self):
        for value in ({'admitted': True}, self.lifecycle, self.custody):
            with self.subTest(kind=type(value).__name__), self.assertRaises(Exception):
                admission._CustodiedRendezvous(value)
        self.assert_held()


class SourceAdmissionAdversarialTests(unittest.TestCase):
    """Reuse normal setup without inheriting and rediscovering its tests."""
    DATA = helpers.SourceAdmissionTests.DATA
    setUp = helpers.SourceAdmissionTests.setUp
    install = helpers.SourceAdmissionTests.install
    begin = helpers.SourceAdmissionTests.begin
    observe = helpers.SourceAdmissionTests.observe
    review = helpers.SourceAdmissionTests.review
    reserve = helpers.SourceAdmissionTests.reserve
    start = helpers.SourceAdmissionTests.start
    stage = helpers.SourceAdmissionTests.stage
    retirement = helpers.SourceAdmissionTests.retirement
    prepare = helpers.SourceAdmissionTests.prepare
    finish = helpers.SourceAdmissionTests.finish
    terminal = helpers.SourceAdmissionTests.terminal

    def assert_held(self):
        self.assertEqual(self.custody._original().slot._value, 0)
        self.assertFalse(self.custody._original().slot.acquire(blocking=False))

    def assert_foreign_rejected(self, action):
        kind, result = foreign_call(action)
        self.assertEqual(kind, 'raised'); self.assertIsInstance(result, admission.SourceAdmissionError)
        self.assert_held()

    def mutation_rejected(self, owner, name, value):
        original = getattr(owner, name)
        try:
            setattr(owner, name, value)
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
            self.assert_held()
            self.assertIsNone(self.custody._status().result)
        finally: setattr(owner, name, original)

    def late_fault(self, action):
        self.prepare(); reached = []
        original = admission._CustodiedRendezvous._release_admission
        def release(gate):
            sealed = original(gate)
            self.assertEqual(self.lifecycle._owned_buffer, bytearray())
            workers = gate._worker_original()
            self.assertFalse(workers.association_thread.is_alive())
            self.assertFalse(workers.witness._original().thread.is_alive())
            self.assert_held()
            reached.append(True); action(gate, sealed)
            return sealed
        with patch.object(admission._CustodiedRendezvous, '_release_admission', release):
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
        self.assertEqual(reached, [True], 'fault must follow genuine two-peer retirement')
        self.assert_held()
        self.assertIsNone(self.custody._status().result)
        self.terminal()

    def outer_release_fault(self, action):
        self.prepare(); reached = []
        original, owner = self.custody._cleanup_current, self.custody._original()
        def cleanup():
            if owner.slot._value == 1 and owner.slot_lock.locked():
                self.assertEqual(reached, [], 'mutate only the guarded post-notify fence')
                self.assertEqual(self.lifecycle._owned_buffer, bytearray())
                workers = self.custody._status().gate._worker_original()
                self.assertFalse(workers.association_thread.is_alive())
                self.assertFalse(workers.witness._original().thread.is_alive())
                reached.append(True); action()
            return original()
        with patch.object(self.custody, '_cleanup_current', side_effect=cleanup):
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
        self.assertEqual(reached, [True], 'fault must follow the genuine guarded slot transition')
        self.assert_held()
        self.assertIsNone(self.custody._status().result)
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        self.terminal()

    def after_release_fault(self, action):
        self.prepare(); reached = []
        original, owner = self.custody._retire, self.custody._original()
        def retire(candidate):
            sealed = original(candidate)
            self.assertEqual(owner.slot._value, 1)
            self.assertFalse(owner.slot_lock.locked())
            self.assertIsNotNone(sealed.result)
            newer = admission._SourceAdmissionCustody()
            newer.acquire()
            reached.append(newer); action(sealed)
            return sealed
        with patch.object(self.custody, '_retire', side_effect=retire):
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
        self.assertEqual(len(reached), 1, 'fault must follow genuine release and a later admission')
        newer = reached[0]
        self.assertEqual(owner.slot._value, 0)
        self.assertFalse(newer._status().poisoned)
        self.assertFalse(newer._cancel.is_set())
        self.assertEqual(self.lifecycle._owned_buffer, bytearray())
        self.terminal()
        newer.abort()
        self.assertEqual(owner.slot._value, 1, 'only the later owner can release its admission')

    def test_shallow_copy_cannot_retire_original_shared_admission(self):
        duplicate = copy.copy(self.custody)
        with self.assertRaises(admission.SourceAdmissionError): duplicate.abort()
        self.assert_held(); self.assertIs(self.custody._status().released, False)

    def test_foreign_thread_cannot_begin_review(self):
        self.assert_foreign_rejected(self.begin)
        self.assertFalse(self.custody._status().begun)

    def test_foreign_thread_cannot_begin_acquisition(self):
        token = self.reserve()
        self.assert_foreign_rejected(lambda: self.custody.begin_acquisition(
            token, 'app', self.credential, self.proposal))
        self.assertIsNone(self.lifecycle._wire)

    def test_foreign_thread_cannot_start_two_worker_handoff(self):
        self.prepare(); self.assert_foreign_rejected(self.finish)
        self.assertFalse(self.custody._status().attempted)
        self.assertIsNone(self.custody._status().gate)

    def test_foreign_thread_cannot_abort_and_release_original_owner(self):
        self.assert_foreign_rejected(self.custody.abort)
        self.assertEqual(self.lifecycle._state, 'new')

    def test_foreign_thread_cancellation_never_releases_admission(self):
        kind, result = foreign_call(self.custody.close)
        self.assertEqual((kind, result), ('returned', None))
        self.assert_held(); self.custody.abort(); self.terminal()

    def test_origin_archive_single_alias_mutation_cannot_begin_review(self):
        original = self.custody._origin
        self.custody._origin = object()
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.begin()
            self.assert_held(); self.assertFalse(self.custody._status().begun)
        finally: self.custody._origin = original

    def test_bound_source_archive_erasure_cannot_finish(self):
        self.prepare(); saved = self.custody._source
        self.custody._source = self.custody._issued_source = self.custody._recovery_source = None
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
            self.assert_held()
        finally:
            self.custody._source = self.custody._issued_source = self.custody._recovery_source = saved

    def test_begun_review_archive_erasure_cannot_finish(self):
        self.prepare(); saved = self.custody._review
        self.custody._review = self.custody._issued_review = self.custody._recovery_review = None
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
            self.assert_held()
        finally:
            self.custody._review = self.custody._issued_review = self.custody._recovery_review = saved

    def test_original_quarantine_archive_cannot_disappear_before_abort(self):
        self.stage(); wire, retained = self.lifecycle._wire, self.lifecycle._owned_buffer
        self.custody._wire = self.custody._issued_wire = self.custody._recovery_wire = None
        self.lifecycle._wire = self.lifecycle._owned_buffer = None
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
            self.assert_held()
            self.assertIsNone(self.custody._status().result)
        finally:
            # Test disposal only, never restoration of a usable custody owner.
            self.lifecycle._wire, self.lifecycle._owned_buffer = wire, retained

    def test_original_review_ticket_cannot_disappear_to_skip_pending_cleanup(self):
        self.review(); original = self.model._ticket
        self.model._ticket = None
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
            self.assert_held()
            self.assertIsNone(self.custody._status().result)
        finally: self.model._ticket = original

    def test_coherently_substituted_wire_timer_never_dispatches_during_abort(self):
        self.stage(); wire = self.lifecycle._wire
        original_timer, original_snapshot = wire._timer, wire._timer_snapshot
        foreign = Mock()
        wire._timer = wire._timer_snapshot = foreign
        try:
            with self.assertRaises(admission.SourceAdmissionError): self.custody.abort()
            self.assert_held()
            self.assertEqual(foreign.mock_calls, [])
        finally:
            wire._timer, wire._timer_snapshot = original_timer, original_snapshot

    def test_substituted_registry_lock_is_rejected_before_handoff(self):
        self.prepare(); self.mutation_rejected(self.registry, '_lock', threading.RLock())

    def test_substituted_review_lease_is_never_dispatched(self):
        self.prepare(); foreign = Mock(side_effect=AssertionError('foreign authority hook'))
        self.mutation_rejected(self.model, '_lease', foreign)
        foreign.assert_not_called()

    def test_substituted_review_timer_is_rejected_before_handoff(self):
        self.prepare(); foreign = Mock()
        self.mutation_rejected(self.model, '_timer', foreign)
        self.assertEqual(foreign.mock_calls, [])

    def test_substituted_review_timer_event_is_rejected_before_handoff(self):
        self.prepare(); self.mutation_rejected(self.model._timer, 'finished', threading.Event())

    def test_substituted_recipient_timer_is_rejected_before_handoff(self):
        self.prepare(); self.mutation_rejected(self.recipient, '_timer', Mock())

    def test_substituted_original_quarantine_buffer_is_rejected(self):
        self.prepare(); self.mutation_rejected(self.lifecycle, '_owned_buffer', bytearray(self.DATA))

    def test_substituted_original_quarantine_lock_is_rejected(self):
        self.prepare(); self.mutation_rejected(self.lifecycle._wire, '_lock', threading.RLock())

    def test_type_confused_custody_deadline_cannot_start_workers(self):
        self.prepare(); self.mutation_rejected(self.custody, '_deadline', True)

    def test_standalone_gate_cannot_acquire_during_custody(self):
        self.prepare()
        gate = SourceAssociationRendezvousDryRun(self.lifecycle)
        with self.assertRaises(Exception): gate._acquire_admission()
        self.assert_held(); self.assertIsNone(self.custody._status().gate)

    def test_late_gate_cleanup_flag_mutation_poisoned(self):
        self.late_fault(lambda gate, sealed: setattr(gate, '_history', sealed._replace(cleanup=False)))

    def test_late_gate_release_flag_cannot_claim_parent_admission(self):
        self.late_fault(lambda gate, sealed: setattr(gate, '_history', sealed._replace(released=True)))

    def test_late_gate_source_joined_flag_mutation_poisoned(self):
        self.late_fault(lambda gate, sealed: setattr(gate, '_history', sealed._replace(source_joined=False)))

    def test_late_gate_association_joined_flag_mutation_poisoned(self):
        self.late_fault(lambda gate, sealed: setattr(gate, '_history', sealed._replace(association_joined=False)))

    def test_late_gate_result_mutation_is_not_permission(self):
        self.late_fault(lambda gate, sealed: object.__setattr__(sealed.result, 'released_bytes', 1))

    def test_late_custody_source_archive_erasure_poisoned(self):
        def erase(gate, sealed):
            self.custody._source = self.custody._issued_source = self.custody._recovery_source = None
        self.late_fault(erase)

    def test_late_private_link_mutation_cannot_transfer_admission(self):
        self.late_fault(lambda gate, sealed: setattr(gate, '_link', object()))

    def test_late_original_worker_identity_mutation_cannot_release_admission(self):
        self.late_fault(lambda gate, sealed: setattr(gate._worker_original().witness, '_thread', object()))

    def test_late_native_observation_archive_erasure_cannot_release_admission(self):
        def erase(gate, sealed):
            witness = gate._worker_original().witness
            witness._native = witness._issued_native = witness._recovery_native = None
        self.late_fault(erase)

    def test_buffer_reinsertion_after_outer_notify_rolls_back_admission(self):
        self.outer_release_fault(lambda: self.lifecycle._owned_buffer.extend(b'late protected bytes'))

    def test_key_restoration_after_outer_notify_rolls_back_admission(self):
        def restore():
            self.assertEqual(self.lifecycle._wire._key, b'')
            self.lifecycle._wire._key = b'x'*32
        self.outer_release_fault(restore)

    def test_history_mutation_after_outer_notify_rolls_back_admission(self):
        self.outer_release_fault(lambda: setattr(self.custody, '_history',
            self.custody._status()._replace(cleanup=False)))

    def test_revocation_after_outer_notify_rejects_freshness_and_rolls_back(self):
        self.outer_release_fault(lambda: self.registry.revoke('app'))

    def test_history_mutation_after_release_cannot_reclaim_later_owner_slot(self):
        self.after_release_fault(lambda sealed: setattr(self.custody, '_history',
            sealed._replace(cleanup=False)))

    def test_result_mutation_after_release_cannot_reclaim_later_owner_slot(self):
        self.after_release_fault(lambda sealed: object.__setattr__(sealed.result, 'released_bytes', 1))

    def test_buffer_reinsertion_after_release_is_wiped_without_reclaiming_later_slot(self):
        self.after_release_fault(lambda sealed: self.lifecycle._owned_buffer.extend(b'late protected bytes'))

    def test_cancellation_uses_original_gate_owner_after_archive_substitution(self):
        self.prepare(); reached, foreign_cancel = [], threading.Event()
        original = admission._CustodiedRendezvous._acquire_admission
        def acquire(gate):
            captured = self.custody._status().gate_owner
            self.assertIs(gate._original(), captured)
            substituted = captured._replace(cancel=foreign_cancel)
            gate._origin = gate._issued_origin = gate._recovery_origin = substituted
            self.custody.close()
            self.assertTrue(captured.cancel.is_set())
            self.assertFalse(foreign_cancel.is_set())
            reached.append(True)
            return original(gate)
        with patch.object(admission._CustodiedRendezvous, '_acquire_admission', acquire):
            with self.assertRaises(admission.SourceAdmissionError): self.finish()
        self.assertEqual(reached, [True], 'fault must follow original private gate construction')
        self.assertFalse(foreign_cancel.is_set())
        self.assert_held()
        self.assertIsNone(self.custody._status().result)
        self.terminal()

    def test_detached_historical_fact_never_has_permission_truthiness(self):
        self.prepare(); result = self.finish()
        self.assertEqual(result.released_bytes, 0)
        self.assertNotIn('data', asdict(result))
        with self.assertRaises(TypeError): bool(result)
        self.terminal()
