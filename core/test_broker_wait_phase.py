"""Adversarial scheduling tests only; no review, process, file or read operation."""
from copy import copy
import math
import threading
import unittest
from unittest.mock import Mock, patch

from core import broker_wait_phase as phase


class WaitAcquisitionPhaseTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(phase, 'monotonic', return_value=100.0).start()
        self.addCleanup(patch.stopall)
        self.model = phase._WaitAcquisitionPhases()
        self.owner = self.model._original()
        self.addCleanup(self.model.close)

    def rejects(self, method=None):
        with self.assertRaises(phase.WaitPhaseError):
            (method or self.model.check_wait)()
        self.assertTrue(self.owner.terminal.is_set())
        self.assertTrue(self.owner.cancel.is_set())
        with self.assertRaises(phase.WaitPhaseError): self.model.check_wait()
        with self.assertRaises(phase.WaitPhaseError): self.model.check_acquisition()

    def test_fixed_nonrenewable_wait_and_separate_acquisition_deadlines(self):
        self.assertEqual((self.owner.created, self.owner.deadline_wait, self.owner.deadline_total),
            (100.0, 130.0, 135.0))
        self.assertEqual(self.model.check_wait(), 130.0)
        self.clock.return_value = 120.0
        self.assertEqual(self.model.check_wait(), 130.0)
        self.assertEqual(self.model.enter_acquisition(), 125.0)
        self.clock.return_value = 124.999
        self.assertEqual(self.model.check_acquisition(), 125.0)
        self.assertEqual(self.owner.deadline_total, 135.0)

    def test_early_acquisition_receives_five_seconds_not_unused_wait_budget(self):
        self.assertEqual(self.model.enter_acquisition(), 105.0)
        self.clock.return_value = 105.0
        self.rejects(self.model.check_acquisition)

    def test_latest_acquisition_remains_inside_total_lifetime(self):
        self.clock.return_value = math.nextafter(130.0, -math.inf)
        deadline = self.model.enter_acquisition()
        self.assertLessEqual(deadline, 135.0)
        self.assertEqual(deadline, min(self.clock.return_value+5.0, 135.0))
        self.clock.return_value = deadline
        self.rejects(self.model.check_acquisition)

    def test_exact_wait_expiry_is_terminal(self):
        self.clock.return_value = 130.0
        self.rejects()

    def test_cannot_enter_at_wait_expiry(self):
        self.clock.return_value = 130.0
        self.rejects(self.model.enter_acquisition)

    def test_no_constructor_selectors_or_subclasses(self):
        for name in ('timeout', 'clock', 'key', 'session', 'grant', 'path', 'callback', 'deadline'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                phase._WaitAcquisitionPhases(**{name: Mock()})
        class Other(phase._WaitAcquisitionPhases): pass
        with self.assertRaises(TypeError): Other()

    def test_phase_owner_is_not_boolean_permission(self):
        with self.assertRaises(TypeError): bool(self.model)
        self.assertFalse(hasattr(self.model, 'review'))
        self.assertFalse(hasattr(self.model, 'read'))
        self.assertFalse(hasattr(self.model, 'allow'))

    def test_duplicate_acquisition_attempt_is_terminal(self):
        self.model.enter_acquisition()
        self.rejects(self.model.enter_acquisition)

    def test_acquisition_check_before_transition_is_terminal(self):
        self.rejects(self.model.check_acquisition)

    def test_wait_check_after_acquisition_is_terminal(self):
        self.model.enter_acquisition()
        self.rejects()

    def test_closed_model_cannot_be_reopened_by_history_restore(self):
        state = self.model._state
        self.model.close()
        self.model._state = self.model._issued_state = self.model._recovery_state = state
        self.rejects()

    def test_cancel_signals_original_event_despite_mutated_mirror(self):
        foreign = threading.Event()
        self.model._cancel = foreign
        self.model.cancel()
        self.assertTrue(self.owner.cancel.is_set())
        self.assertFalse(foreign.is_set())
        self.rejects()

    def test_cancel_from_other_thread_never_waits_for_worker_lock(self):
        with self.owner.lock:
            thread = threading.Thread(target=self.model.cancel)
            thread.start(); thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertTrue(self.owner.cancel.is_set())
        self.rejects()

    def test_close_is_idempotent_and_does_not_require_clock(self):
        self.clock.side_effect = AssertionError('disposal consulted the clock')
        self.model.close(); self.model.close()
        self.assertTrue(self.owner.terminal.is_set())

    def test_foreign_thread_cannot_check_or_enter_and_retires_original(self):
        errors = []
        def run():
            try: self.model.check_wait()
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run)
        thread.start(); thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIs(type(errors[0]), phase.WaitPhaseError)
        self.rejects()

    def test_copied_model_cannot_cancel_or_use_original(self):
        other = copy(self.model)
        for method in (other.check_wait, other.enter_acquisition, other.cancel):
            with self.assertRaises(phase.WaitPhaseError): method()
        self.assertFalse(self.owner.cancel.is_set())
        self.assertEqual(self.model.check_wait(), 130.0)

    def test_busy_original_lock_fails_promptly_and_latches_failure(self):
        held, release = threading.Event(), threading.Event()
        def hold():
            with self.owner.lock:
                held.set(); release.wait(timeout=2)
        thread = threading.Thread(target=hold)
        thread.start(); self.assertTrue(held.wait(timeout=1))
        try: self.rejects()
        finally:
            release.set(); thread.join(timeout=1)
        self.assertFalse(thread.is_alive())

    def test_deadline_type_confusion_and_mutation_are_terminal(self):
        for name in ('_created', '_deadline_wait', '_deadline_total'):
            for value in (True, 130, float('nan'), float('inf'), 131.0):
                with self.subTest(name=name, value=value):
                    model = phase._WaitAcquisitionPhases()
                    setattr(model, name, value)
                    with self.assertRaises(phase.WaitPhaseError): model.check_wait()
                    self.assertTrue(model._original().failed.is_set())

    def test_nonfinite_or_type_confused_clock_cannot_start_model(self):
        for value in (True, 100, '100', None, float('nan'), float('inf'), -float('inf'), 1e308):
            with self.subTest(value=value):
                self.clock.return_value = value
                with self.assertRaises(phase.WaitPhaseError): phase._WaitAcquisitionPhases()

    def test_invalid_clock_during_wait_is_permanently_terminal(self):
        self.clock.return_value = float('nan')
        self.rejects()
        self.clock.return_value = 100.0
        self.rejects()

    def test_regressing_wait_clock_is_terminal(self):
        self.clock.return_value = 110.0; self.model.check_wait()
        self.clock.return_value = 109.0; self.rejects()

    def test_regressing_acquisition_clock_is_terminal(self):
        self.clock.return_value = 110.0; self.model.enter_acquisition()
        self.clock.return_value = 112.0; self.model.check_acquisition()
        self.clock.return_value = 111.0; self.rejects(self.model.check_acquisition)

    def test_missing_single_origin_archive_fails_then_original_cleanup_survives(self):
        self.model._origin = None
        self.rejects()
        self.model.close()

    def test_missing_all_origin_archives_cannot_be_restored_after_rejection(self):
        original = self.owner
        self.model._origin = self.model._issued_origin = self.model._recovery_origin = None
        with self.assertRaises(phase.WaitPhaseError): self.model.check_wait()
        self.assertTrue(original.failed.is_set())
        self.model._origin = self.model._issued_origin = self.model._recovery_origin = original
        self.rejects()

    def test_coherent_wait_history_rollback_is_rejected_by_original_clock_anchor(self):
        state = self.model._state
        self.clock.return_value = 110.0; self.model.check_wait()
        self.model._state = self.model._issued_state = self.model._recovery_state = state
        self.rejects()

    def test_acquisition_cannot_be_erased_by_coherent_history_rollback(self):
        state = self.model._state
        self.model.enter_acquisition()
        self.model._state = self.model._issued_state = self.model._recovery_state = state
        self.model._acquisition = self.model._issued_acquisition = self.model._recovery_acquisition = None
        self.rejects()

    def test_changed_acquisition_archive_rejects_despite_coherent_history(self):
        self.model.enter_acquisition()
        value = self.model._acquisition._replace(deadline=106.0)
        self.model._acquisition = self.model._issued_acquisition = self.model._recovery_acquisition = value
        state = self.model._state._replace(acquisition=value)
        self.model._state = self.model._issued_state = self.model._recovery_state = state
        self.rejects(self.model.check_acquisition)

    def test_missing_acquisition_archive_is_terminal(self):
        self.model.enter_acquisition()
        self.model._acquisition = None
        self.rejects(self.model.check_acquisition)

    def test_type_confused_phase_cannot_be_accepted(self):
        state = self.model._state._replace(phase=b'waiting')
        self.model._state = self.model._issued_state = self.model._recovery_state = state
        self.rejects()

    def test_invalid_original_clock_anchor_cannot_be_repaired_after_rejection(self):
        self.owner.clock[0] = float('inf')
        self.rejects()
        self.owner.clock[0] = 100.0
        self.rejects()

    def test_acquisition_budget_never_renews_from_repeated_checks(self):
        self.clock.return_value = 110.0
        self.assertEqual(self.model.enter_acquisition(), 115.0)
        for now in (111.0, 112.0, 114.0, 114.999):
            self.clock.return_value = now
            self.assertEqual(self.model.check_acquisition(), 115.0)
        self.clock.return_value = 115.0
        self.rejects(self.model.check_acquisition)

    def test_foreign_lock_is_never_used(self):
        foreign = Mock()
        self.model._lock = foreign
        self.rejects()
        self.assertFalse(foreign.mock_calls)

    def test_cancellation_during_clock_read_cannot_return_success(self):
        def now():
            self.model.cancel()
            return 100.0
        self.clock.side_effect = now
        self.rejects()


if __name__ == '__main__': unittest.main()
