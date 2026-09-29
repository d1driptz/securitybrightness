"""Controlled real Windows reads. Operator actions are simulated by the test host."""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import replace, FrozenInstanceError
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from core.fixture_read_experiment import FixtureReadExperiment, FIXTURE_REFERENCE, MAX_FIXTURE_BYTES
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry, AuthorityInactiveError
from core.authority_store import SQLiteAuthorityStore


@unittest.skipUnless(os.name == 'nt', 'Windows controlled read experiment')
class FixtureReadTests(unittest.TestCase):
    def setUp(self):
        self.registry = ApplicationRegistry()
        self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', ['files.read'])
        self.data = b'ONLY THE SYNTHETIC FIXTURE\n'
        self.experiment = FixtureReadExperiment(self.registry, fixture_data=self.data)
        self.addCleanup(self.experiment.close)
        self.app = self.experiment.application_port
        self.operator = self.experiment.operator_port
        self.proposal = make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=128)

    def propose(self):
        return self.app.propose('app', self.credential, self.proposal)

    def approve(self, request):
        display = self.operator.review(request)
        self.assertTrue(self.operator.approve(display))
        return display

    def read(self, request):
        return self.app.read_once(request, 'app', self.credential, self.proposal)

    def denied(self, result):
        self.assertFalse(result.released)
        self.assertEqual(result.data, b'')
        self.assertEqual(result.reason, 'controlled_read_denied')

    def test_real_allow_returns_only_fixture_after_separate_operator_approval(self):
        request = self.propose()
        display = self.approve(request)
        self.assertEqual(display.application_id, 'app')
        self.assertEqual(display.max_bytes, 128)
        self.assertEqual(display.requester_reference, FIXTURE_REFERENCE)
        self.assertIn('not immutable bytes', display.meaning)
        result = self.read(request)
        self.assertTrue(result.released)
        self.assertEqual(result.data, self.data)
        self.assertNotIn(self.data.decode().strip(), repr(result))
        with self.assertRaises(TypeError):
            bool(result)

    def test_no_approval_means_no_native_read_and_attempt_is_burned(self):
        request = self.propose()
        with patch.object(self.experiment._reader.k, 'ReadFile') as read:
            self.denied(self.read(request))
            read.assert_not_called()
        with self.assertRaises(ValueError):
            self.operator.review(request)
        self.denied(self.read(request))

    def test_explicit_denial_and_operator_revocation_prevent_native_read(self):
        for revoke in [False, True]:
            with self.subTest(revoke=revoke):
                request = self.propose()
                self.approve(request)
                if revoke:
                    self.assertTrue(self.operator.revoke_review(request))
                else:
                    self.assertTrue(self.operator.deny(request))
                with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                    self.denied(self.read(request))
                    read.assert_not_called()

    def test_trusted_application_still_needs_action_approval(self):
        self.registry.set_trusted('app', True)
        request = self.propose()
        self.denied(self.read(request))

    def test_scopes_and_authentication_come_only_from_current_registry(self):
        self.registry.set_scopes('app', [])
        with self.assertRaises(AuthorityInactiveError):
            self.propose()
        self.registry.set_scopes('app', ['files.read'])
        for credential in ['', None, 'forged', True]:
            with self.assertRaises(AuthorityInactiveError):
                self.app.propose('app', credential, self.proposal)

    def test_wrong_application_or_credentials_returns_zero_and_burns_attempt(self):
        other = self.registry.register('other', ['files.read'])
        for app_id, credential in [('other', other), ('app', 'wrong')]:
            request = self.propose()
            self.approve(request)
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.app.read_once(request, app_id, credential, self.proposal))
                read.assert_not_called()
            self.denied(self.read(request))

    def test_proposal_effect_context_and_reference_changes_cannot_reuse_approval(self):
        changed = [make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=127),
                   make_file_read_proposal('different resource', max_bytes=128),
                   make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=128,
                                           requester_context={'reason': 'new intent'})]
        for proposal in changed:
            request = self.propose()
            self.approve(request)
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.app.read_once(request, 'app', self.credential, proposal))
                read.assert_not_called()

    def test_registry_revocation_rotation_and_grant_changes_prevent_native_read(self):
        for action in ['rotate', 'permissions', 'revoke']:
            request = self.propose()
            self.approve(request)
            if action == 'rotate':
                self.credential = self.registry.rotate_credential('app')
            elif action == 'permissions':
                self.registry.set_scopes('app', ['files.read'])
            else:
                self.registry.revoke('app')
                self.credential = self.registry.register('app', ['files.read'])
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.read(request))
                read.assert_not_called()

    def test_registry_failure_returns_no_bytes_and_no_retry_after_recovery(self):
        request = self.propose()
        self.approve(request)
        with patch.object(self.registry, 'get', side_effect=OSError('private authority location')):
            self.denied(self.read(request))
        self.denied(self.read(request))

    def test_expired_review_cannot_be_approved_or_consumed(self):
        request = self.propose()
        display = self.operator.review(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline):
            self.assertFalse(self.operator.approve(display))
        self.assertFalse(self.operator.approve(display))
        self.denied(self.read(request))

    def test_expiry_after_approval_before_consumption_returns_no_bytes(self):
        request = self.propose()
        self.approve(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline + 1):
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.read(request))
                read.assert_not_called()

    def test_replay_and_concurrent_consumption_release_exactly_once(self):
        request = self.propose()
        self.approve(request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.read(request), range(2)))
        self.assertEqual(sum(result.released for result in results), 1)
        self.assertEqual([r.data for r in results if r.released], [self.data])
        self.assertEqual([r.data for r in results if not r.released], [b''])
        self.denied(self.read(request))

    def test_display_copies_redisplay_and_duplicate_approval_cannot_grant(self):
        request = self.propose()
        first = self.operator.review(request)
        self.assertFalse(self.operator.approve(replace(first)))
        self.assertFalse(self.operator.approve(first.__dict__))
        self.assertTrue(self.operator.approve(first))
        self.assertFalse(self.operator.approve(first))
        new = self.operator.review(request)
        self.assertFalse(self.operator.approve(first))
        self.denied(self.read(request))  # Redisplay removed previous approval.
        self.assertFalse(self.operator.approve(new))
        with self.assertRaises(FrozenInstanceError):
            first.max_bytes = MAX_FIXTURE_BYTES

    def test_request_copies_malformed_ids_and_other_sessions_are_rejected(self):
        request = self.propose()
        self.approve(request)
        for value in [replace(request), replace(request, request_id=[]), request.__dict__, None]:
            self.denied(self.read(value))
        with FixtureReadExperiment(self.registry) as other:
            self.denied(other.application_port.read_once(request, 'app', self.credential, self.proposal))
        self.assertTrue(self.read(request).released)

    def test_requester_port_has_no_approval_path_or_arbitrary_path_argument(self):
        self.assertFalse(hasattr(self.app, 'approve'))
        self.assertFalse(hasattr(self.app, 'review'))
        with self.assertRaises(TypeError):
            self.app.propose('app', self.credential, self.proposal, approved=True)
        with self.assertRaises(TypeError):
            FixtureReadExperiment(self.registry, path=str(self.experiment._path))
        with self.assertRaises(ValueError):
            self.app.propose('app', self.credential,
                             make_file_read_proposal(str(self.experiment._path), max_bytes=128))

    def test_whole_file_boundary_no_truncation_and_no_oversized_effects(self):
        for limit in [len(self.data) - 1, MAX_FIXTURE_BYTES + 1]:
            with self.assertRaises(ValueError):
                self.app.propose('app', self.credential,
                                 make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=limit))
        proposal = make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=len(self.data))
        request = self.app.propose('app', self.credential, proposal)
        self.approve(request)
        result = self.app.read_once(request, 'app', self.credential, proposal)
        self.assertEqual(result.data, self.data)

    def test_empty_fixture_is_distinct_from_denial(self):
        with FixtureReadExperiment(self.registry, fixture_data=b'') as empty:
            request = empty.application_port.propose('app', self.credential, self.proposal)
            display = empty.operator_port.review(request)
            self.assertTrue(empty.operator_port.approve(display))
            result = empty.application_port.read_once(request, 'app', self.credential, self.proposal)
            self.assertTrue(result.released)
            self.assertEqual(result.data, b'')

    def test_changed_resource_observation_blocks_read(self):
        request = self.propose()
        self.approve(request)
        self.experiment._path.write_bytes(b'changed and longer synthetic fixture')
        with patch.object(self.experiment._reader.k, 'ReadFile') as read:
            self.denied(self.read(request))
            read.assert_not_called()

    def test_superseding_binding_or_draft_version_blocks_old_decision(self):
        first = self.propose()
        self.approve(first)
        second = self.propose()
        self.denied(self.read(first))
        self.approve(second)
        state = self.experiment._requests[second.request_id]
        ticket = state['envelope'].review.review
        draft = self.experiment._ledger._drafts[ticket.draft_id]
        self.experiment._ledger.replace(draft.draft_id, 1, draft.constraint)
        self.denied(self.read(second))

    def test_native_open_failure_never_calls_read_and_poisons_adapter(self):
        request = self.propose()
        self.approve(request)
        with patch.object(self.experiment._reader.k, 'ReOpenFile', return_value=c.c_void_p(-1).value), \
             patch.object(self.experiment._reader.k, 'ReadFile') as read:
            self.denied(self.read(request))
            read.assert_not_called()
        with self.assertRaises(ValueError):
            self.propose()

    def test_partial_native_read_failure_releases_no_staged_data(self):
        request = self.propose()
        self.approve(request)
        native_read = self.experiment._reader.k.ReadFile
        def partial_failure(*args):
            self.assertTrue(native_read(*args))
            return False
        with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=partial_failure):
            self.denied(self.read(request))
        self.denied(self.read(request))

    def test_wrong_native_handle_identity_is_rejected_before_read(self):
        request = self.propose()
        self.approve(request)
        with tempfile.TemporaryDirectory() as folder:
            wrong = Path(folder) / 'wrong-fixture.txt'
            wrong.write_bytes(b'wrong resource')
            native = self.experiment._collector._native
            handle = native.k.CreateFileW(str(wrong), 0x100081, 1, None, 3, 0, None)
            self.assertNotEqual(handle, c.c_void_p(-1).value)
            with patch.object(self.experiment._reader.k, 'ReOpenFile', return_value=handle), \
                 patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.read(request))
                read.assert_not_called()  # Experiment closes this injected handle.

    def test_read_handle_rejects_normal_writer_and_replacement_during_read(self):
        request = self.propose()
        self.approve(request)
        native_read = self.experiment._reader.k.ReadFile
        def checked_read(*args):
            with self.assertRaises(OSError):
                self.experiment._path.write_bytes(b'forbidden during read')
            with self.assertRaises(OSError):
                self.experiment._path.unlink()
            return native_read(*args)
        with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=checked_read):
            result = self.read(request)
        self.assertTrue(result.released)
        self.assertEqual(result.data, self.data)

    def test_existing_writer_prevents_read_access_upgrade(self):
        request = self.propose()
        self.approve(request)
        with self.experiment._path.open('r+b'):
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.read(request))
                read.assert_not_called()

    def test_authority_change_inside_native_read_discards_staged_bytes(self):
        request = self.propose()
        self.approve(request)
        native_read = self.experiment._reader.k.ReadFile
        def changed_authority(*args):
            result = native_read(*args)
            self.registry.revoke('app')  # Same-thread reentrant fault injection.
            return result
        with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=changed_authority):
            self.denied(self.read(request))

    def test_revocation_from_another_thread_linearizes_after_inflight_release(self):
        request = self.propose()
        self.approve(request)
        entered, attempted, revoked = Event(), Event(), Event()
        native_read = self.experiment._reader.k.ReadFile
        def read_while_revocation_waits(*args):
            entered.set()
            self.assertTrue(attempted.wait(5))
            self.assertFalse(revoked.is_set())
            return native_read(*args)
        def revoke():
            self.assertTrue(entered.wait(5))
            attempted.set()
            self.registry.revoke('app')
            revoked.set()
        with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=read_while_revocation_waits):
            with ThreadPoolExecutor(max_workers=2) as pool:
                removal = pool.submit(revoke)
                result = pool.submit(self.read, request).result(timeout=10)
                removal.result(timeout=10)
        self.assertTrue(result.released)
        self.assertTrue(revoked.is_set())
        self.denied(self.read(request))

    def test_native_close_failure_prevents_data_release(self):
        request = self.propose()
        self.approve(request)
        close = self.experiment._collector._native.close
        def uncertain_close(handle):
            close(handle)
            raise OSError('uncertain close result')
        with patch.object(self.experiment._collector._native, 'close', side_effect=uncertain_close):
            self.denied(self.read(request))

    def test_persistent_lock_reunlock_does_not_restore_old_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(folder) / 'authority.db'))
            try:
                credential = registry.register('persist', ['files.read'])
                registry.operator_unlock('persist', registry.get('persist').grant_id)
                with FixtureReadExperiment(registry) as experiment:
                    request = experiment.application_port.propose('persist', credential, self.proposal)
                    self.assertTrue(experiment.operator_port.approve(experiment.operator_port.review(request)))
                    registry.lock_all()
                    registry.operator_unlock('persist', registry.get('persist').grant_id)
                    result = experiment.application_port.read_once(request, 'persist', credential, self.proposal)
                    self.denied(result)
            finally:
                registry.close()

    def test_closed_experiment_and_duplicate_request_ids_fail_closed(self):
        with patch('core.fixture_read_experiment.uuid4', return_value='duplicate'):
            request = self.propose()
            with self.assertRaises(ValueError):
                self.propose()
        self.approve(request)
        self.experiment.close()
        self.denied(self.read(request))
        with self.assertRaises(ValueError):
            self.propose()

    def test_expiry_during_read_discards_already_staged_bytes(self):
        request = self.propose()
        self.approve(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        original = self.experiment._reader.read_staged
        def expire_after_read(limit):
            data = original(limit)
            clock.return_value = deadline
            return data
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline - 1) as clock:
            with patch.object(self.experiment._reader, 'read_staged', side_effect=expire_after_read):
                self.denied(self.read(request))

    def test_metadata_failure_after_native_read_discards_bytes(self):
        request = self.propose()
        self.approve(request)
        native = self.experiment._collector._native
        original_read = self.experiment._reader.k.ReadFile
        original_metadata = native.metadata
        read_happened = False
        def read(*args):
            nonlocal read_happened
            result = original_read(*args)
            read_happened = True
            return result
        def metadata(*args):
            if read_happened:
                raise OSError('metadata failure after buffered read')
            return original_metadata(*args)
        with patch.object(native, 'metadata', side_effect=metadata), \
             patch.object(self.experiment._reader.k, 'ReadFile', side_effect=read):
            self.denied(self.read(request))
        self.assertTrue(read_happened)

    def test_short_successful_native_read_is_not_released(self):
        request = self.propose()
        self.approve(request)
        original = self.experiment._reader.k.ReadFile
        def short_read(handle, buffer, size, count, overlapped):
            result = original(handle, buffer, size, count, overlapped)
            c.cast(count, c.POINTER(w.DWORD)).contents.value = size - 1
            return result
        with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=short_read):
            self.denied(self.read(request))

    def test_invalid_or_oversized_adapter_output_never_reaches_application(self):
        for output in [self.data + b'extra', bytearray(self.data), 'not bytes']:
            request = self.propose()
            self.approve(request)
            with patch.object(self.experiment._reader, 'read_staged', return_value=output):
                self.denied(self.read(request))

    def test_oversized_credentials_and_unknown_fields_rejected_before_native_read(self):
        with self.assertRaises(AuthorityInactiveError):
            self.app.propose('app', 'x' * 100000, self.proposal)
        request = self.propose()
        self.approve(request)
        with patch.object(self.experiment._reader.k, 'ReadFile') as read:
            self.denied(self.app.read_once(request, 'app', 'x' * 100000, self.proposal))
            read.assert_not_called()
        with self.assertRaises(TypeError):
            self.app.read_once(request, 'app', self.credential, self.proposal, grant_id='forged')

    def test_failed_review_is_terminal_even_after_clock_recovery(self):
        request = self.propose()
        deadline = self.experiment._requests[request.request_id]['deadline']
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline):
            with self.assertRaises(ValueError):
                self.operator.review(request)
        with self.assertRaises(ValueError):
            self.operator.review(request)

    def test_existing_writable_mapping_is_not_an_immutable_content_promise(self):
        import mmap
        request = self.propose()
        self.approve(request)
        with self.experiment._path.open('r+b') as writer:
            mapping = mmap.mmap(writer.fileno(), 0, access=mmap.ACCESS_WRITE)
        changed = b'X' * len(self.data)
        original = self.experiment._reader.k.ReadFile
        def mutate_mapping_then_read(*args):
            mapping[:] = changed
            mapping.flush()
            return original(*args)
        try:
            with patch.object(self.experiment._reader.k, 'ReadFile', side_effect=mutate_mapping_then_read):
                result = self.read(request)
            # A restrictive OS failure is valid. If released, only the approved
            # object's bounded bytes are promised, NOT the approval-time contents.
            if result.released:
                self.assertEqual(result.data, changed)
            else:
                self.denied(result)
        finally:
            mapping.close()

    def test_external_file_replacement_cannot_change_the_retained_resource(self):
        request = self.propose()
        self.approve(request)
        replacement = self.experiment._path.with_name('test-owned-replacement.txt')
        replacement.write_bytes(b'other resource')
        try:
            os.replace(replacement, self.experiment._path)
        except OSError:
            # If the OS prevented replacement, the original approved read is valid.
            self.assertEqual(self.read(request).data, self.data)
        else:
            with patch.object(self.experiment._reader.k, 'ReadFile') as read:
                self.denied(self.read(request))
                read.assert_not_called()

    def test_demo_rejects_noninteractive_input_and_arbitrary_arguments_before_acquisition(self):
        from core.controlled_read_demo import main
        with patch('core.controlled_read_demo.sys.stdin.isatty', return_value=False), \
             patch('core.controlled_read_demo.FixtureReadExperiment') as fixture, patch('builtins.print'):
            self.assertEqual(main([]), 2)
            fixture.assert_not_called()
        with patch('core.controlled_read_demo.sys.stdin.isatty', return_value=True), \
             patch('core.controlled_read_demo.FixtureReadExperiment') as fixture, patch('builtins.print'):
            self.assertEqual(main(['--approve']), 2)
            fixture.assert_not_called()

    def test_demo_complete_script_with_simulated_input_and_clock_only_in_test(self):
        from core.controlled_read_demo import main
        now = 1000.0
        def advance(seconds):
            nonlocal now
            now += seconds
        with patch('core.controlled_read_demo.sys.stdin.isatty', return_value=True), \
             patch('builtins.input', side_effect=['DENY'] + ['ALLOW ONCE'] * 8), \
             patch('core.fixture_read_experiment.monotonic', side_effect=lambda: now), \
             patch('core.controlled_read_demo.sleep', side_effect=advance), \
             patch('builtins.print') as output:
            self.assertEqual(main([]), 0)
            lines = [str(call.args[0]) for call in output.call_args_list]
            for label in ['Owner denial', '3. Replay', 'Revoked approval', 'Stale grant approval',
                          'Expired approval', 'Changed request cannot', 'Different resource/session']:
                self.assertTrue(any(line.startswith(label) and 'DENY: 0' in line for line in lines), label)
            self.assertEqual(sum(' — ALLOW:' in line for line in lines), 3)
            self.assertIn('All owner demonstration stages completed. No broader protection is claimed.',
                          [line.strip() for line in lines])

    def test_demo_never_automatically_approves_after_owner_stops(self):
        from core.controlled_read_demo import main
        with patch('core.controlled_read_demo.sys.stdin.isatty', return_value=True), \
             patch('builtins.input', side_effect=['DENY', 'stop']), patch('builtins.print') as output:
            self.assertEqual(main([]), 0)
            self.assertFalse(any(' — ALLOW:' in str(call.args[0]) for call in output.call_args_list))

    def test_expiry_during_final_freshness_validation_prevents_delivery(self):
        request = self.propose()
        self.approve(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        inspect = self.experiment._envelopes.inspect
        calls = 0
        def slow_final_validation(*args):
            nonlocal calls
            result = inspect(*args)
            calls += 1
            if calls == 2:
                clock.return_value = deadline
            return result
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline - 1) as clock, \
             patch.object(self.experiment._envelopes, 'inspect', side_effect=slow_final_validation):
            self.denied(self.read(request))

    def test_review_evidence_without_operator_decision_is_not_permission(self):
        request = self.propose()
        self.operator.review(request)
        with patch.object(self.experiment._reader.k, 'ReadFile') as native_read:
            self.denied(self.read(request))
            native_read.assert_not_called()

    def test_post_buffer_draft_revocation_discards_all_bytes(self):
        request = self.propose()
        self.approve(request)
        ticket = self.experiment._requests[request.request_id]['envelope'].review.review
        read = self.experiment._reader.read_staged
        def revoke_after_buffer(limit):
            data = read(limit)
            self.experiment._ledger.revoke(ticket.draft_id, ticket.revision)
            return data
        with patch.object(self.experiment._reader, 'read_staged', side_effect=revoke_after_buffer):
            self.denied(self.read(request))

    def test_redisplay_never_extends_deadline_and_expiry_during_display_retires(self):
        request = self.propose()
        deadline = self.experiment._requests[request.request_id]['deadline']
        inspect = self.experiment._envelopes.inspect
        def slow_display(*args):
            result = inspect(*args)
            clock.return_value = deadline
            return result
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline - 1) as clock, \
             patch.object(self.experiment._envelopes, 'inspect', side_effect=slow_display):
            with self.assertRaises(ValueError):
                self.operator.review(request)
        self.assertEqual(self.experiment._requests[request.request_id]['deadline'], deadline)
        self.denied(self.read(request))

    def test_expiry_at_publication_after_evidence_retirement_releases_nothing(self):
        request = self.propose()
        self.approve(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        discard = self.experiment._envelopes.discard
        def delayed_retirement(*args):
            discard(*args)
            clock.return_value = deadline
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline - 1) as clock, \
             patch.object(self.experiment._envelopes, 'discard', side_effect=delayed_retirement):
            self.denied(self.read(request))
        self.denied(self.read(request))

    def test_approval_crossing_deadline_is_not_issued(self):
        request = self.propose()
        display = self.operator.review(request)
        deadline = self.experiment._requests[request.request_id]['deadline']
        inspect = self.experiment._envelopes.inspect
        def slow_approval(*args):
            result = inspect(*args)
            clock.return_value = deadline
            return result
        with patch('core.fixture_read_experiment.monotonic', return_value=deadline - 1) as clock, \
             patch.object(self.experiment._envelopes, 'inspect', side_effect=slow_approval):
            self.assertFalse(self.operator.approve(display))
        self.denied(self.read(request))

    def test_retired_request_capacity_cannot_be_recycled_to_restore_approval(self):
        retired = []
        for _ in range(32):
            request = self.propose()
            self.operator.deny(request)
            retired.append(request)
        with self.assertRaises(ValueError):
            self.propose()
        for request in retired:
            self.denied(self.read(request))

    def test_demo_revocation_is_pass_with_zero_bytes_and_no_native_read(self):
        from core.controlled_read_demo import _revoked_case
        credential = self.registry.register('controlled-demo-app', ['files.read'])
        request = self.app.propose('controlled-demo-app', credential, self.proposal)
        self.assertTrue(self.operator.approve(self.operator.review(request)))
        with patch.object(self.experiment._reader.k, 'ReadFile') as native_read, \
             patch('builtins.print') as output:
            _revoked_case(self.experiment, request, credential, self.proposal)
            native_read.assert_not_called()
            self.assertIn('Revoked approval — PASS — DENY: 0 protected bytes released.',
                          [call.args[0] for call in output.call_args_list])
        fresh = self.app.propose('controlled-demo-app', credential, self.proposal)
        self.assertTrue(self.operator.approve(self.operator.review(fresh)))
        result = self.app.read_once(fresh, 'controlled-demo-app', credential, self.proposal)
        self.assertTrue(result.released)  # Later stages remain usable with new approval.
        self.denied(self.app.read_once(request, 'controlled-demo-app', credential, self.proposal))

    def test_demo_cannot_call_failed_revocation_a_pass(self):
        from core.controlled_read_demo import _revoked_case
        request = self.propose()
        with patch.object(self.operator, 'revoke_review', return_value=False), \
             patch.object(self.app, 'read_once') as read, patch('builtins.print') as output:
            with self.assertRaises(RuntimeError):
                _revoked_case(self.experiment, request, self.credential, self.proposal)
            read.assert_not_called()
            self.assertFalse(any('PASS' in str(call) for call in output.call_args_list))

    def test_demo_never_interprets_arbitrary_exception_as_expected_denial(self):
        from core.controlled_read_demo import _revoked_case
        request = self.propose()
        with patch.object(self.app, 'read_once', side_effect=RuntimeError('unexpected adapter error')), \
             patch('builtins.print') as output:
            with self.assertRaises(RuntimeError):
                _revoked_case(self.experiment, request, self.credential, self.proposal)
            self.assertFalse(any('PASS' in str(call) for call in output.call_args_list))

    def test_demo_never_labels_leaked_or_malformed_results_as_pass(self):
        from core.controlled_read_demo import _report
        from core.fixture_read_experiment import ProtectedReadResult
        bad = [ProtectedReadResult(False, 'controlled_read_denied', b'leak'),
               ProtectedReadResult(True, 'controlled_read_released', b'leak'),
               ProtectedReadResult(False, 'controlled_read_denied', None),
               ProtectedReadResult(False, 'unexpected_failure'), None]
        for result in bad:
            with patch('builtins.print') as output:
                with self.assertRaises(RuntimeError):
                    _report('Revoked approval', result, allowed=False)
                output.assert_not_called()

    def test_demo_expiry_at_revocation_prompt_is_not_misreported_as_revocation_pass(self):
        from core.controlled_read_demo import main
        from core.fixture_read_experiment import _Reader
        now, prompts = 1000.0, 0
        def answer(_):
            nonlocal now, prompts
            prompts += 1
            if prompts == 3:  # Human waits at the revoke-before-use approval prompt.
                now += 61
            return 'DENY' if prompts == 1 else 'ALLOW ONCE'
        original_read = _Reader.read_staged
        with patch('core.controlled_read_demo.sys.stdin.isatty', return_value=True), \
             patch('core.fixture_read_experiment.monotonic', side_effect=lambda: now), \
             patch('builtins.input', side_effect=answer), patch('builtins.print') as output, \
             patch('core.fixture_read_experiment.OperatorFixturePort.revoke_review') as revoke, \
             patch.object(_Reader, 'read_staged', autospec=True, side_effect=original_read) as reader:
            self.assertEqual(main([]), 1)
            revoke.assert_not_called()
            self.assertEqual(reader.call_count, 1)  # Only the preceding approved read.
            self.assertEqual(prompts, 3)
            lines = [str(call.args[0]) for call in output.call_args_list]
            self.assertTrue(any('operator approval was not accepted' in line for line in lines))
            self.assertFalse(any('Revoked approval — PASS' in line for line in lines))


if __name__ == '__main__':
    unittest.main()
