"""Fixed guarded fixture profile tests; generated data, never app delivery."""
from dataclasses import asdict, replace
import inspect
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest
from unittest.mock import patch

from core import broker_source_fixture_process as fixture
from core import test_broker_live_review as review_helpers
from core import test_broker_native_commit_peer as peer_helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_bootstrap import BOOT_SIZE, MAGIC, READY_SIZE, ready
from core.broker_process import BrokerProcessError, _ChildProcess, _PublicationCheckChild, _WinApi
from core.broker_publication_lifecycle import LivePublicationDraft
from core.broker_publication_recipient import LogicalPublicationRecipient
from core.broker_recipient_process import _RecipientWitnessChild


class SourceFixtureProcessTests(unittest.TestCase):
    # Reuse bounded original-handle test transport without inheriting its tests.
    write = peer_helpers.NativeCommitPeerTests.write
    read = peer_helpers.NativeCommitPeerTests.read
    frame = peer_helpers.NativeCommitPeerTests.frame
    wait_exit = peer_helpers.NativeCommitPeerTests.wait_exit
    remaining_output = peer_helpers.NativeCommitPeerTests.remaining_output
    read_to_eof = peer_helpers.NativeCommitPeerTests.read_to_eof

    def setUp(self):
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(32)
        self.child = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.child is not None:
            try: self.child.close()
            except BrokerProcessError: pass

    def launch(self):
        self.child = fixture._SourceFixtureChild()
        self.observation = self.child._observe()
        return self.child

    def boot(self):
        self.launch(); self.write(MAGIC+self.key+self.session)
        frame = self.read(READY_SIZE)
        self.assertEqual(frame, ready(self.key, self.session, self.observation.pid))
        return frame

    def test_profile_overrides_only_fixed_entry_and_inherits_original_guards(self):
        self.assertIs(fixture._SourceFixtureChild.__init__, _RecipientWitnessChild.__init__)
        functions = {name for name, value in fixture._SourceFixtureChild.__dict__.items()
                     if inspect.isfunction(value)}
        self.assertEqual(functions, {'_entry_path'})
        self.assertEqual(list(inspect.signature(fixture._SourceFixtureChild).parameters), [])
        entry = fixture._SourceFixtureChild._entry_path(None)
        self.assertEqual(entry, Path(fixture.__file__).resolve().with_name('broker_publication_entry.py'))
        self.assertTrue(entry.is_absolute()); self.assertTrue(entry.is_file())

    def test_requester_cannot_select_path_executable_handle_pid_or_pipe(self):
        for selector in ('path', 'executable', 'handle', 'pid', 'pipe', 'entry', 'callback'):
            with self.subTest(selector=selector), self.assertRaises(TypeError):
                fixture._SourceFixtureChild(**{selector: 'requester controlled'})
        for name in ('read', 'write', 'execute', 'publish', 'deliver', 'release', 'authorize'):
            self.assertFalse(hasattr(fixture._SourceFixtureChild, name))

    def test_existing_plain_publication_profile_is_unchanged(self):
        self.assertIs(_PublicationCheckChild.__bases__[0], _ChildProcess)
        self.assertIs(_PublicationCheckChild.__init__, _ChildProcess.__init__)
        self.assertEqual(_PublicationCheckChild._entry_path(None).name, 'broker_publication_entry.py')
        self.assertIsNot(_PublicationCheckChild, fixture._SourceFixtureChild)

    def test_genuine_startup_is_bound_to_original_os_observed_process(self):
        self.boot()
        value = self.child._observe()
        self.assertIs(value, self.observation)
        self.assertEqual(set(asdict(value)), {'pid', 'creation_time'})
        self.assertEqual(value.pid, self.child._issued_owned[6])
        self.assertTrue(1 <= value.creation_time <= 2**64-1)
        self.assertIsNone(self.child.poll())
        with self.assertRaises(TypeError): bool(value)
        self.child.close(); self.child._retired()
        with self.assertRaises(BrokerProcessError): self.child._observe()

    def test_genuine_startup_uses_fixed_isolated_python_and_atomic_hidden_job_launch(self):
        calls, original = [], _WinApi.__init__
        def initialize(api):
            original(api)
            launch = api.k.CreateProcessW
            def create(*arguments):
                calls.append(dict(executable=arguments[0], command=arguments[1].value,
                    inherit=arguments[4], flags=arguments[5], environment=arguments[6][:],
                    directory=arguments[7]))
                return launch(*arguments)
            api.k.CreateProcessW = create
        with patch.object(_WinApi, '__init__', initialize): self.boot()
        self.assertEqual(len(calls), 1)
        call, entry = calls[0], self.child._entry_path()
        self.assertEqual(call['executable'], sys.executable)
        self.assertEqual(call['command'], subprocess.list2cmdline([sys.executable, '-I', '-S', str(entry)]))
        self.assertEqual(call['directory'], str(entry.parent))
        self.assertIs(call['inherit'], True)
        self.assertEqual(call['flags'], 0x08000000 | 0x00080000 | 0x00000400)
        environment = [item for item in call['environment'].split('\0') if item]
        self.assertTrue(all(item.split('=', 1)[0] in {'SystemRoot', 'WINDIR'} for item in environment))
        self.assertNotIn('PYTHONPATH', call['environment'])
        self.assertTrue(self.child._ownership.membership(self.child._owned[4], self.child._owned[5]))

    def test_original_native_anchors_are_distinct_noninheritable_kernel_objects(self):
        self.launch()
        for name, index in (('input', 2), ('output', 3), ('process', 4), ('job', 5)):
            original, anchor, seal = self.child._owned[index], self.child._anchors[name], self.child._seals[name]
            self.assertEqual(len({original, anchor, seal}), 3)
            self.assertTrue(self.child._ownership.k.CompareObjectHandles(original, anchor))
            self.assertTrue(self.child._ownership.k.CompareObjectHandles(anchor, seal))
            self.assertEqual(self.child._ownership.flags(original)&1, 0)
            self.assertEqual(self.child._ownership.flags(anchor)&1, 0)
            self.assertEqual(self.child._ownership.flags(seal)&1, 0)
        self.assertFalse(os.get_blocking(self.child.stdin_fd))
        self.assertFalse(os.get_blocking(self.child.stdout_fd))

    def test_invalid_bootstrap_emits_no_ready_observation_or_fixture_data(self):
        self.launch(); self.child._validate()
        self.assertEqual(os.write(self.child.stdin_fd, b'x'*BOOT_SIZE), BOOT_SIZE)
        self.assertNotEqual(self.wait_exit(), 0)
        self.assertEqual(self.remaining_output(), b'')
        self.child.close(); self.child._retired()

    def test_original_input_anchor_closes_so_incomplete_bootstrap_can_reach_eof(self):
        self.launch(); self.child.close_input()
        self.assertNotIn('input', self.child._anchors)
        self.assertNotIn('input', self.child._seals)
        self.assertNotEqual(self.wait_exit(), 0)
        self.assertEqual(self.remaining_output(), b'')
        self.child.close(); self.child._retired()
        self.assertIs(self.child._retired_snapshot[1], True)

    def test_copied_os_observation_cannot_replace_original_issued_identity(self):
        self.launch(); original = self.child._issued_observation
        self.child._issued_observation = replace(original)
        try:
            with self.assertRaises(BrokerProcessError): self.child._observe()
        finally: self.child._issued_observation = original
        self.child.close(); self.child._retired()

    def test_native_identity_lookup_failure_is_fail_closed_without_pid_fallback(self):
        self.launch()
        with patch.object(self.child._ownership, 'identity', side_effect=BrokerProcessError('query failed')):
            with self.assertRaises(BrokerProcessError): self.child._observe()
        self.child.close(); self.child._retired()

    def test_equal_numeric_handle_fields_cannot_override_kernel_object_mismatch(self):
        self.launch()
        with patch.object(self.child._ownership.k, 'CompareObjectHandles', return_value=False):
            with self.assertRaises(BrokerProcessError): self.child._observe()
        self.child.close(); self.child._retired()

    def test_native_query_mutation_is_rejected_after_genuine_os_observation(self):
        self.launch(); original = self.child._ownership.identity; pid = self.child.pid
        def identity(handle):
            result = original(handle); self.child.pid = pid+1; return result
        try:
            with patch.object(self.child._ownership, 'identity', side_effect=identity):
                with self.assertRaises(BrokerProcessError): self.child._observe()
        finally: self.child.pid = pid
        self.child.close(); self.child._retired()

    def test_failed_constructor_never_publishes_native_retirement_evidence(self):
        allocated, original = object.__new__(fixture._SourceFixtureChild), _ChildProcess.__init__
        def fail_after_launch(owner):
            original(owner)
            raise BrokerProcessError('generated constructor uncertainty')
        self.child = allocated
        with patch.object(_ChildProcess, '__init__', fail_after_launch):
            with self.assertRaises(BrokerProcessError): fixture._SourceFixtureChild.__init__(allocated)
        self.assertIs(allocated._closed, True)
        self.assertIsNone(allocated._process); self.assertIsNone(allocated._job)
        self.assertEqual(allocated._fds, set())
        self.assertIsNone(allocated._issued_observation)
        with self.assertRaises(BrokerProcessError): allocated._retired()

    def test_generated_fixture_stages_only_reviewed_bound_data_then_retires_original_child(self):
        review_helpers.LiveReviewMappingTests.setUp(self)
        acquisition = AcquisitionDraft(self.model)
        recipient = LogicalPublicationRecipient('app')
        source = LivePublicationDraft(acquisition, recipient)
        self.addCleanup(source.close); self.addCleanup(recipient.close)
        descriptor = recipient.descriptor
        self.boot()
        self.write(self.model.coordinator.begin('app', self.credential, self.proposal, self.draft.draft_id, 1))
        self.model.coordinator.observe(self.frame())
        display = self.model.operator.display()
        self.assertTrue(Path(display.display_path).exists())
        self.model.operator.record(display, 'ALLOW ONCE')
        token = source.coordinator.reserve()
        self.write(source.adapter.begin(token, 'app', self.credential, self.proposal))
        summary = source.adapter.stage(self.frame())
        self.assertEqual(summary.staged_bytes, 37)
        self.write(source.adapter.retire()); self.child.close_input()
        acknowledgment = self.frame()
        self.assertEqual(self.read_to_eof(), b'')
        self.assertEqual(self.wait_exit(), 0)
        self.child.close(); self.child._retired()
        self.assertEqual(self.child._retired_snapshot, (0, True))
        self.assertFalse(Path(display.display_path).exists())
        receipt = source.adapter.confirm_retirement(acknowledgment)
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(bytes(source._owned_buffer), b'SecurityBrightness synthetic fixture\n')
        result = source.coordinator.check_publication('app', self.credential, self.proposal, descriptor)
        self.assertEqual((result.staged_bytes, result.released_bytes), (37, 0))
        self.assertEqual(source._owned_buffer, bytearray())
        self.assertNotIn('data', asdict(result))
        with self.assertRaises(TypeError): bool(result)
