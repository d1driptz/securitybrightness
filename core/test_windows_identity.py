"""Real Windows metadata tests operate only on test-owned temporary fixtures."""
import ctypes
from ctypes import wintypes
from dataclasses import replace, FrozenInstanceError
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from core.file_read_schema import make_file_read_proposal
from core.resource_binding import AdapterObservationSession
from core.windows_identity import WindowsIdentityCollector, ResourceIdentityError, _path_parts


class WindowsPathTests(unittest.TestCase):
    def test_rejects_ambiguous_names_before_os_access(self):
        invalid = [None, {}, True, '', 'relative.txt', r'C:relative.txt', 'C:\\',
                   r'\\server\share\file', r'\\?\C:\file', r'\\.\C:\file',
                   r'C:\a\..\b', r'C:\.\b', r'C:\a\\b', r'C:\a:stream',
                   'C:\\a.', 'C:\\a ', r'C:\NUL.txt', r'C:\COM1', 'C:\\a\x00b',
                   'C:\\a\ud800', 'C:\\' + 'a' * 256, 'C:\\' + '\\'.join(['a'] * 129),
                   'C:\\' + 'a' * 40000]
        for value in invalid:
            with self.subTest(value=repr(value)[:80]), self.assertRaises(ResourceIdentityError):
                _path_parts(value)

    def test_syntax_parsing_does_not_claim_identity_or_fold_case(self):
        self.assertEqual(_path_parts('c:/Folder/File.txt'), ('c:\\', ['Folder', 'File.txt']))
        self.assertNotEqual(_path_parts('C:/A.txt'), _path_parts('C:/a.txt'))

    def test_unsupported_platform_fails_without_fallback(self):
        with patch('core.windows_identity.os.name', 'posix'), self.assertRaises(ResourceIdentityError):
            WindowsIdentityCollector()


@unittest.skipUnless(os.name == 'nt', 'Windows native fixture tests')
class WindowsIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.file = self.folder / 'fixture.txt'
        self.file.write_bytes(b'synthetic fixture')
        self.adapter = WindowsIdentityCollector()
        self.addCleanup(self.adapter.close)
        self.proposal = make_file_read_proposal('untrusted descriptive label', max_bytes=32)

    def collect(self):
        return self.adapter.collect(str(self.file))

    def test_real_handle_metadata_and_separate_requester_reference(self):
        observation = self.collect()
        self.assertEqual(len(observation.file_id), 16)
        self.assertEqual(observation.size_bytes, 17)
        binding = self.adapter.bind('app', self.proposal, observation)
        match = self.adapter.matches(binding, 'app', self.proposal, observation)
        self.assertTrue(match.matches)
        with self.assertRaises(TypeError):
            bool(match)
        self.assertNotEqual(observation.display_path, 'untrusted descriptive label')
        with self.assertRaises(FrozenInstanceError):
            observation.size_bytes = 0

    def test_retained_handle_cannot_read_file_content(self):
        observation = self.collect()
        handle = self.adapter._held[observation.observation_id][1][-1]
        read = self.adapter._native.k.ReadFile
        read.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        read.restype = wintypes.BOOL
        output, count = ctypes.create_string_buffer(1), wintypes.DWORD()
        self.assertFalse(read(handle, output, 1, ctypes.byref(count), None))
        self.assertEqual(ctypes.get_last_error(), 5)  # ERROR_ACCESS_DENIED
        self.assertEqual(count.value, 0)

    def test_case_and_slash_aliases_identify_handle_but_never_reuse_evidence(self):
        old = self.collect()
        alias = self.adapter.collect(str(self.file).upper().replace('\\', '/'))
        self.assertEqual((old.volume_serial, old.file_id), (alias.volume_serial, alias.file_id))
        self.assertNotEqual(old.observation_id, alias.observation_id)
        binding = self.adapter.bind('app', self.proposal, old)
        self.assertFalse(self.adapter.matches(binding, 'app', self.proposal, alias).matches)

    def test_fabricated_copied_and_cross_session_reports_are_rejected(self):
        observation = self.collect()
        fake = AdapterObservationSession().record_observation(
            volume_serial=observation.volume_serial, file_id=observation.file_id,
            size_bytes=17, change_time=observation.change_time, display_path=str(self.file),
            filesystem='local_ntfs', file_kind='regular', reparse_status='excluded')
        for value in [replace(observation), fake, observation.__dict__, None]:
            self.assertFalse(self.adapter.revalidate(value))
            with self.assertRaises(ResourceIdentityError):
                self.adapter.bind('app', self.proposal, value)

    def test_exact_application_proposal_effect_and_binding_ownership(self):
        observation = self.collect()
        binding = self.adapter.bind('app', self.proposal, observation)
        self.assertFalse(self.adapter.matches(binding, 'other', self.proposal, observation).matches)
        for proposal in [make_file_read_proposal('changed', max_bytes=32),
                         make_file_read_proposal('untrusted descriptive label', max_bytes=31),
                         make_file_read_proposal('untrusted descriptive label', max_bytes=32,
                                                 requester_context={'purpose': 'changed'})]:
            self.assertFalse(self.adapter.matches(binding, 'app', proposal, observation).matches)
        self.assertFalse(self.adapter.matches(replace(binding), 'app', self.proposal, observation).matches)
        new = self.adapter.bind('app', self.proposal, observation)
        self.assertFalse(self.adapter.matches(binding, 'app', self.proposal, observation).matches)
        self.assertTrue(self.adapter.matches(new, 'app', self.proposal, observation).matches)

    def test_byte_boundary_rejects_oversized_read_intent(self):
        observation = self.collect()
        with self.assertRaises(ValueError):
            self.adapter.bind('app', make_file_read_proposal('label', max_bytes=16), observation)
        self.adapter.bind('app', make_file_read_proposal('label', max_bytes=17), observation)

    def test_metadata_handle_does_not_claim_write_exclusion_and_change_retires_evidence(self):
        observation = self.collect()
        self.file.write_bytes(b'changed fixture with different length')
        self.assertFalse(self.adapter.revalidate(observation))
        self.assertFalse(self.adapter.revalidate(observation))

    def test_existing_writer_is_not_misrepresented_as_content_stability(self):
        with self.file.open('r+b') as writer:
            observation = self.collect()
            writer.write(b'writer changes this fixture to a longer value')
            writer.flush()
            self.assertFalse(self.adapter.revalidate(observation))

    def test_replacement_or_deletion_either_fails_or_retires_old_evidence(self):
        observation = self.collect()
        replacement = self.folder / 'replacement.txt'
        replacement.write_bytes(b'replacement')
        try:
            os.replace(replacement, self.file)
        except OSError:
            self.assertTrue(self.adapter.revalidate(observation))
        else:
            self.assertFalse(self.adapter.revalidate(observation))
        self.adapter.release(observation)
        observation = self.collect()
        try:
            self.file.unlink()
        except OSError:
            self.assertTrue(self.adapter.revalidate(observation))
        else:
            self.assertFalse(self.adapter.revalidate(observation))

    def test_release_recreation_and_replay_require_new_lifetime(self):
        old = self.collect()
        binding = self.adapter.bind('app', self.proposal, old)
        self.adapter.release(old)
        self.file.unlink()
        self.file.write_bytes(b'synthetic fixture')
        new = self.collect()
        self.assertFalse(self.adapter.revalidate(old))
        self.assertFalse(self.adapter.matches(binding, 'app', self.proposal, new).matches)
        self.assertNotEqual(old.observation_id, new.observation_id)
        # File IDs may be recycled: this assertion deliberately uses the lifetime.

    def test_close_is_final_and_cannot_restore_observations(self):
        observation = self.collect()
        self.adapter.close()
        self.adapter.close()
        self.assertFalse(self.adapter.revalidate(observation))
        with self.assertRaises(ResourceIdentityError):
            self.collect()
        self.file.write_bytes(b'closed handles')

    def test_hard_links_and_directories_are_rejected(self):
        alias = self.folder / 'hardlink.txt'
        os.link(self.file, alias)
        for path in [self.file, alias, self.folder]:
            with self.assertRaises(ResourceIdentityError):
                self.adapter.collect(str(path))

    def test_junction_traversal_is_rejected(self):
        target = self.folder / 'target'
        target.mkdir()
        (target / 'fixture.txt').write_bytes(b'junction fixture')
        junction = self.folder / 'junction'
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        try:
            with self.assertRaises(ResourceIdentityError):
                self.adapter.collect(str(junction / 'fixture.txt'))
        finally:
            junction.rmdir()  # Remove test-owned link, never traverse its target.

    def test_parent_rename_and_replacement_during_traversal_stays_on_original_handle(self):
        parent = self.folder / 'original'
        parent.mkdir()
        target = parent / 'nested.txt'
        target.write_bytes(b'original')
        moved = self.folder / 'moved'
        child = self.adapter._native.child
        switched = False
        def racing_child(handle, name, directory):
            nonlocal switched
            if name == 'nested.txt' and not switched:
                switched = True
                parent.rename(moved)
                parent.mkdir()
                (parent / name).write_bytes(b'replacement has other size')
            return child(handle, name, directory)
        with patch.object(self.adapter._native, 'child', side_effect=racing_child):
            observed = self.adapter.collect(str(target))
        self.assertTrue(switched)
        self.assertEqual(observed.size_bytes, 8)
        self.assertIn('moved', observed.display_path)
        replacement = self.adapter.collect(str(target))
        self.assertNotEqual(observed.file_id, replacement.file_id)
        self.assertTrue(self.adapter.revalidate(observed))

    def test_query_failure_retires_evidence_even_after_recovery(self):
        observation = self.collect()
        with patch.object(self.adapter._native, 'metadata', side_effect=OSError('private path')):
            self.assertFalse(self.adapter.revalidate(observation))
        self.assertFalse(self.adapter.revalidate(observation))
        self.file.write_bytes(b'handles released')

    def test_changed_metadata_retires_evidence(self):
        observation = self.collect()
        original = self.adapter._native.metadata
        def changed(handle, directory):
            value = original(handle, directory)
            return value if directory else (*value[:2], value[2] + 1, *value[3:])
        with patch.object(self.adapter._native, 'metadata', side_effect=changed):
            self.assertFalse(self.adapter.revalidate(observation))
        self.assertFalse(self.adapter.revalidate(observation))

    def test_collection_errors_close_all_partial_handles_and_hide_paths(self):
        original = self.adapter._native.close
        closed = []
        def close(handle):
            closed.append(handle)
            return original(handle)
        with patch.object(self.adapter._native, 'display', side_effect=OSError('secret path')), \
             patch.object(self.adapter._native, 'close', side_effect=close):
            with self.assertRaisesRegex(ResourceIdentityError, '^collection_failed$'):
                self.collect()
        self.assertGreaterEqual(len(closed), 2)
        self.file.write_bytes(b'no leaked file handle')

    def test_capacity_and_duplicate_ids_fail_without_handle_leaks(self):
        with WindowsIdentityCollector(capacity=1) as adapter:
            first = adapter.collect(str(self.file))
            adapter.release(first)
            with self.assertRaises(ResourceIdentityError):
                adapter.collect(str(self.file))
        with patch('core.resource_binding.uuid4', return_value='duplicate'):
            first = self.collect()
            self.adapter.release(first)
            with self.assertRaises(ResourceIdentityError):
                self.collect()
        self.file.write_bytes(b'all acquisition handles closed')

    def test_unknown_fields_and_requester_objects_not_native_input(self):
        with self.assertRaises(TypeError):
            self.adapter.collect(str(self.file), permission=True)
        with self.assertRaises(ResourceIdentityError):
            self.adapter.collect({'path': str(self.file), 'file_id': b'fake'})
        with patch.object(self.adapter._native, 'root') as root:
            with self.assertRaises(ResourceIdentityError):
                self.adapter.collect(r'C:\fixture.txt:stream')
            root.assert_not_called()

    def test_acquisition_metadata_change_aborts_without_issuing_observation(self):
        original = self.adapter._native.metadata
        final_calls = 0
        def changing(handle, directory):
            nonlocal final_calls
            value = original(handle, directory)
            if not directory:
                final_calls += 1
                if final_calls > 1:
                    return (*value[:2], value[2] + 1, *value[3:])
            return value
        with patch.object(self.adapter._native, 'metadata', side_effect=changing):
            with self.assertRaisesRegex(ResourceIdentityError, 'resource_changed'):
                self.collect()
        self.assertEqual(self.adapter._held, {})

    def test_close_failure_poisons_entire_collector_and_still_attempts_cleanup(self):
        first = self.collect()
        second = self.collect()
        original = self.adapter._native.close
        calls = []
        def uncertain_close(handle):
            original(handle)
            calls.append(handle)
            if len(calls) == 1:
                raise OSError('unreliable closure result')
        count = len(self.adapter._held[first.observation_id][1])
        with patch.object(self.adapter._native, 'close', side_effect=uncertain_close):
            with self.assertRaisesRegex(ResourceIdentityError, '^handle_close_failed$'):
                self.adapter.release(first)
        self.assertEqual(len(calls), count)
        self.assertFalse(self.adapter.revalidate(second))
        with self.assertRaises(ResourceIdentityError):
            self.collect()

    def test_unknown_filesystem_or_volume_query_failure_never_falls_back(self):
        with patch.object(self.adapter._native, 'local_ntfs', side_effect=ResourceIdentityError('unsupported_filesystem')):
            with self.assertRaises(ResourceIdentityError):
                self.collect()
        self.assertEqual(self.adapter._held, {})

    def test_reparse_directory_case_and_inconsistent_native_metadata_rejected(self):
        from core.windows_identity import _Basic, _Standard, _FileId
        def check(*, attributes=0, directory=0, links=1, pending=0, size=1, change=1, case=0):
            def query(handle, kind, structure):
                if kind == 0:
                    value = _Basic()
                    value.attributes, value.change = attributes, change
                elif kind == 1:
                    value = _Standard()
                    value.directory, value.links, value.delete_pending, value.size = directory, links, pending, size
                elif kind == 18:
                    value = _FileId()
                else:
                    value = wintypes.DWORD(case)
                return value
            with patch.object(self.adapter._native, 'query', side_effect=query), \
                 patch.object(self.adapter._native.k, 'GetFileType', return_value=1):
                return self.adapter._native.metadata(1, bool(directory))
        for changes in [{'attributes': 0x400}, {'links': 0}, {'links': 2}, {'pending': 1},
                        {'size': -1}, {'change': -1}, {'directory': 1, 'case': 1},
                        {'directory': 1, 'case': 2}]:
            with self.subTest(changes=changes), self.assertRaises(ResourceIdentityError):
                check(**changes)

    def test_hostile_observation_property_is_never_evaluated(self):
        class RequesterObject:
            @property
            def observation_id(self):
                raise AssertionError('requester property evaluated')
        self.assertFalse(self.adapter.revalidate(RequesterObject()))
        self.adapter.release(RequesterObject())

    def test_capacity_bounds_reject_bool_and_excessive_handle_budgets(self):
        for capacity in [True, 0, -1, 65, 1.0, '16']:
            with self.assertRaises(ValueError):
                WindowsIdentityCollector(capacity=capacity)


if __name__ == '__main__':
    unittest.main()
