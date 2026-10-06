"""Generated metadata-only child ownership tests; never access personal files."""
from concurrent.futures import ThreadPoolExecutor
import ctypes as c
from dataclasses import asdict, replace
import inspect
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from core import broker_recipient_process as native
from core.broker_process import BrokerProcessError, _ChildProcess


class RecipientProcessOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.entry = Path(self.directory.name)/'fixed-metadata-wait.py'
        self.entry.write_text('import sys\nsys.stdin.buffer.read()\n', encoding='utf-8')
        with patch.object(native._RecipientWitnessChild, '_entry_path', return_value=self.entry):
            self.child = native._RecipientWitnessChild()
        self.addCleanup(self.cleanup)
        self.original = self.child._issued_owned
        self.anchors = dict(self.child._issued_anchors)

    def cleanup(self):
        try: self.child.close()
        except BrokerProcessError: pass

    def assert_invalid(self, operation):
        with self.assertRaises(BrokerProcessError): operation()

    def wait_exit(self):
        deadline = time.monotonic()+2
        while time.monotonic() < deadline:
            value = self.child.poll()
            if value is not None: return value
            time.sleep(.005)
        self.fail('fixed metadata child did not exit within the bound')

    def test_observation_is_exact_issued_bounded_os_metadata(self):
        value = self.child._observe()
        self.assertIs(value, self.child._observe())
        self.assertEqual(set(asdict(value)), {'pid', 'creation_time'})
        self.assertEqual(value.pid, self.child.pid)
        self.assertTrue(1 <= value.pid <= 2**32-1)
        self.assertTrue(1 <= value.creation_time <= 2**64-1)
        with self.assertRaises(TypeError): bool(value)
        with patch.object(self.child._ownership.k, 'OpenProcess') as lookup:
            self.child._observe(); lookup.assert_not_called()

    def test_anchors_are_distinct_noninheritable_same_kernel_objects(self):
        for name, index in (('input', 2), ('output', 3), ('process', 4), ('job', 5)):
            anchor = self.anchors[name]
            self.assertNotEqual(anchor, self.original[index])
            self.assertEqual(self.child._ownership.flags(anchor)&1, 0)
            self.assertTrue(self.child._ownership.k.CompareObjectHandles(anchor, self.original[index]))

    def test_input_anchor_closes_with_original_input_and_cannot_prevent_eof(self):
        self.child.close_input()
        self.assertNotIn('input', self.child._anchors)
        self.assertEqual(self.wait_exit(), 0)
        self.child._validate(retiring=True)
        self.assert_invalid(self.child._validate)
        self.child.close(); self.child._retired()

    def test_retirement_mode_requires_closed_input_and_exact_boolean(self):
        self.assert_invalid(lambda: self.child._validate(retiring=True))
        self.assert_invalid(lambda: self.child._validate(retiring=1))

    def test_real_close_is_idempotent_and_evidence_cannot_restore_liveness(self):
        value = self.child._observe()
        self.child.close(); self.child.close(); self.child._retired()
        self.assertEqual(value.pid, self.original[6])
        self.assert_invalid(self.child._observe)
        self.assert_invalid(self.child._validate)
        self.assert_invalid(self.child.poll)

    def test_fixed_profile_exposes_no_executable_handle_pid_or_pipe_selector(self):
        self.assertEqual(list(inspect.signature(native._RecipientWitnessChild).parameters), [])
        self.assertEqual(native._RecipientWitnessChild._entry_path(self.child).name, 'broker_recipient_entry.py')
        for name in ('read', 'execute', 'release', 'publish', 'authorize'):
            self.assertFalse(hasattr(self.child, name))

    def test_pid_substitution_is_rejected_and_original_child_is_still_joined(self):
        self.child.pid += 1
        self.assert_invalid(self.child._observe)
        self.assert_invalid(self.child.close)
        self.assertIs(self.child._closed, True)
        self.assertIs(self.child._cleanup_failed, True)

    def test_pid_type_confusion_is_rejected(self):
        original = self.child.pid
        class Pid(int): pass
        self.child.pid = Pid(original)
        self.assert_invalid(self.child._validate)
        self.child.pid = original

    def test_changed_os_creation_time_rejects_same_numeric_pid(self):
        identity = self.child._observation_snapshot
        with patch.object(self.child._ownership, 'identity', return_value=(identity[0], identity[1]+1)):
            self.assert_invalid(self.child._validate)

    def test_changed_os_pid_rejects_same_creation_time(self):
        identity = self.child._observation_snapshot
        with patch.object(self.child._ownership, 'identity', return_value=(identity[0]+1, identity[1])):
            self.assert_invalid(self.child._validate)

    def test_process_observation_lookup_failure_is_not_current_identity(self):
        with patch.object(self.child._ownership, 'identity', side_effect=BrokerProcessError('failed')):
            self.assert_invalid(self.child._observe)

    def test_copied_observation_cannot_replace_exact_issued_object(self):
        original = self.child._issued_observation
        self.child._issued_observation = replace(original)
        self.assert_invalid(self.child._validate)
        self.child._issued_observation = original

    def test_mutated_observation_is_rejected_even_if_numeric_values_are_bounded(self):
        original = self.child._issued_observation.creation_time
        object.__setattr__(self.child._issued_observation, 'creation_time', original+1)
        self.assert_invalid(self.child._validate)
        object.__setattr__(self.child._issued_observation, 'creation_time', original)

    def test_observation_type_confusion_is_rejected(self):
        value = self.child._issued_observation
        original = value.pid
        object.__setattr__(value, 'pid', True)
        self.assert_invalid(self.child._validate)
        object.__setattr__(value, 'pid', original)

    def test_process_handle_field_substitution_does_not_close_foreign_child(self):
        with patch.object(native._RecipientWitnessChild, '_entry_path', return_value=self.entry):
            foreign = native._RecipientWitnessChild()
        try:
            self.child._process = foreign._process
            self.assert_invalid(self.child._validate)
            self.assert_invalid(self.child.close)
            foreign._validate()
        finally: foreign.close()

    def test_job_handle_field_substitution_does_not_terminate_foreign_child(self):
        with patch.object(native._RecipientWitnessChild, '_entry_path', return_value=self.entry):
            foreign = native._RecipientWitnessChild()
        try:
            self.child._job = foreign._job
            self.assert_invalid(self.child._validate)
            self.assert_invalid(self.child.close)
            foreign._validate()
        finally: foreign.close()

    def test_fd_field_substitution_preserves_foreign_descriptor(self):
        foreign = os.open(os.devnull, os.O_WRONLY)
        try:
            self.child.stdin_fd = foreign
            self.assert_invalid(self.child._validate)
            self.assert_invalid(self.child.close)
            os.fstat(foreign)
        finally: os.close(foreign)

    def test_real_same_number_crt_descriptor_reuse_preserves_foreign_pipe(self):
        fd = self.original[0]
        read_fd, write_fd = os.pipe()
        os.close(fd)
        try:
            if write_fd != fd:
                os.dup2(write_fd, fd); os.close(write_fd); write_fd = fd
            self.assertEqual(write_fd, self.original[0])
            self.assert_invalid(self.child._validate)
            self.assert_invalid(self.child.close)
            os.write(write_fd, b'x')
            self.assertEqual(os.read(read_fd, 1), b'x')
        finally:
            os.close(write_fd); os.close(read_fd)

    def test_native_cleanup_query_substituting_real_fd_preserves_foreign_pipe(self):
        fd = self.original[0]
        read_fd, write_fd = os.pipe()
        original = self.child._ownership.identity
        changed = [False]
        def identity(handle):
            value = original(handle)
            if not changed[0]:
                changed[0] = True
                os.close(fd); os.dup2(write_fd, fd)
            return value
        try:
            with patch.object(self.child._ownership, 'identity', side_effect=identity):
                self.assert_invalid(self.child.close)
            os.write(fd, b'x'); self.assertEqual(os.read(read_fd, 1), b'x')
            for handle in (self.anchors['input'], dict(self.child._issued_seals)['input']):
                self.assert_invalid(lambda handle=handle: self.child._ownership.flags(handle))
        finally:
            os.close(fd); os.close(write_fd); os.close(read_fd)

    def test_kernel_object_mismatch_rejects_equal_numeric_field_values(self):
        original = self.child._ownership.k.CompareObjectHandles
        def compare(first, second):
            if first == self.original[2]: return False
            return original(first, second)
        with patch.object(self.child._ownership.k, 'CompareObjectHandles', side_effect=compare):
            self.assert_invalid(self.child._validate)

    def test_pipe_type_failure_does_not_establish_provenance(self):
        with patch.object(self.child._ownership.k, 'GetFileType', return_value=1):
            self.assert_invalid(self.child._validate)

    def test_native_handle_flag_failure_is_fail_closed(self):
        with patch.object(self.child._ownership, 'flags', side_effect=BrokerProcessError('failed')):
            self.assert_invalid(self.child._observe)

    def test_inherited_pipe_or_anchor_is_rejected(self):
        with patch.object(self.child._ownership, 'flags', return_value=1):
            self.assert_invalid(self.child._validate)

    def test_blocking_pipe_cannot_enter_bounded_transport(self):
        os.set_blocking(self.original[1], True)
        self.assert_invalid(self.child._validate)
        os.set_blocking(self.original[1], False)

    def test_process_job_membership_failure_is_fail_closed(self):
        with patch.object(self.child._ownership, 'membership', return_value=False):
            self.assert_invalid(self.child._observe)

    def test_native_process_identity_call_mutating_fd_is_caught_after_call(self):
        original = self.child._ownership.identity
        foreign = os.open(os.devnull, os.O_WRONLY)
        try:
            def identity(handle):
                value = original(handle); self.child.stdin_fd = foreign; return value
            with patch.object(self.child._ownership, 'identity', side_effect=identity):
                self.assert_invalid(self.child._observe)
        finally:
            self.child.stdin_fd = self.original[0]
            os.close(foreign)

    def test_anchor_mapping_substitution_cannot_change_original_ownership(self):
        original = self.child._anchors['input']
        self.child._anchors['input'] = self.child._anchors['output']
        self.assert_invalid(self.child._validate)
        self.child._anchors['input'] = original

    def test_equal_copy_of_owned_snapshot_is_not_original_snapshot(self):
        original = self.child._owned
        self.child._owned = tuple(list(original))
        self.assert_invalid(self.child._validate)
        self.child._owned = original

    def test_malformed_guard_map_cannot_dispatch_cleanup_methods(self):
        class Unsupported:
            def clear(self): raise AssertionError('must not call untrusted cleanup')
        self.child._anchors = Unsupported()
        self.assert_invalid(self.child._validate)
        self.assert_invalid(self.child.close)
        self.assertIs(self.child._cleanup_failed, True)

    def test_malformed_fd_collection_cannot_dispatch_cleanup_methods(self):
        class Unsupported:
            def discard(self, value): raise AssertionError('must not call untrusted cleanup')
        self.child._fds = Unsupported()
        self.assert_invalid(self.child._validate)
        self.assert_invalid(self.child.close)
        self.assertIs(self.child._cleanup_failed, True)

    def test_duplicate_input_close_is_irreversibly_cleanup_uncertain(self):
        self.child.close_input()
        self.assert_invalid(self.child.close_input)
        self.assert_invalid(self.child.close)
        self.assert_invalid(self.child._retired)

    def test_input_guard_close_failure_still_attempts_other_guard_and_never_restores_status(self):
        original = self.child._ownership.close
        seal = dict(self.child._issued_seals)['input']
        def close(handle):
            original(handle)
            if handle == self.anchors['input']: raise BrokerProcessError('uncertain')
        with patch.object(self.child._ownership, 'close', side_effect=close):
            self.assert_invalid(self.child.close_input)
        for handle in (self.anchors['input'], seal):
            self.assert_invalid(lambda handle=handle: self.child._ownership.flags(handle))
        self.assert_invalid(self.child.close)
        self.assert_invalid(self.child._retired)

    def test_native_anchor_close_failure_is_permanent_cleanup_uncertainty(self):
        original = self.child._ownership.close
        def close(handle):
            original(handle)
            if handle == self.anchors['output']: raise BrokerProcessError('uncertain')
        with patch.object(self.child._ownership, 'close', side_effect=close):
            self.assert_invalid(self.child.close)
        self.assert_invalid(self.child.close)
        self.assert_invalid(self.child._retired)

    def test_constructor_partial_duplicate_failure_cleans_launch_and_prior_anchors(self):
        original = native._OwnershipApi.duplicate
        calls = []
        def duplicate(owner, handle):
            if len(calls) == 2: raise BrokerProcessError('duplication failed')
            value = original(owner, handle); calls.append(value); return value
        with patch.object(native._RecipientWitnessChild, '_entry_path', return_value=self.entry), patch.object(native._OwnershipApi, 'duplicate', new=duplicate):
            self.assert_invalid(native._RecipientWitnessChild)
        for handle in calls:
            self.assert_invalid(lambda handle=handle: self.child._ownership.flags(handle))

    def test_creation_time_native_lookup_failure_during_constructor_cleans_all(self):
        with patch.object(native._RecipientWitnessChild, '_entry_path', return_value=self.entry), patch.object(native._OwnershipApi, 'identity', side_effect=BrokerProcessError('identity failed')):
            self.assert_invalid(native._RecipientWitnessChild)

    def test_retired_fence_rejects_observation_mutation_after_join(self):
        self.child.close()
        value = self.child._issued_observation
        object.__setattr__(value, 'creation_time', value.creation_time+1)
        self.assert_invalid(self.child._retired)

    def test_retired_fence_rejects_owner_state_restoration(self):
        self.child.close(); self.child._closed = False
        self.assert_invalid(self.child._retired)
        self.child._closed = True

    def test_retired_fence_rejects_reintroduced_fd_without_closing_it(self):
        self.child.close()
        foreign = os.open(os.devnull, os.O_WRONLY)
        try:
            self.child._fds.add(foreign)
            self.assert_invalid(self.child._retired)
            os.fstat(foreign)
        finally:
            self.child._fds.remove(foreign); os.close(foreign)

    def test_retired_fence_rejects_exit_code_type_confusion(self):
        self.child.close(); self.child._exit = True
        self.assert_invalid(self.child._retired)

    def test_retired_fence_rejects_input_state_rollback_after_eof(self):
        self.child.close_input(); self.wait_exit(); self.child.close()
        self.child._input_closed = False
        self.assert_invalid(self.child._retired)

    def test_poll_native_query_mutation_is_caught_before_return(self):
        original = self.child._ownership.k.WaitForSingleObject
        pid = self.child.pid
        def wait(handle, timeout):
            result = original(handle, timeout); self.child.pid = pid+1; return result
        with patch.object(self.child._ownership.k, 'WaitForSingleObject', side_effect=wait):
            self.assert_invalid(self.child.poll)
        self.child.pid = pid

    def test_concurrent_close_and_observe_never_restores_live_owner(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.child._observe), executor.submit(self.child.close)]
        for future in futures:
            if future.exception() is not None:
                self.assertIsInstance(future.exception(), BrokerProcessError)
        self.child._retired()
        self.assert_invalid(self.child._observe)
