"""Retained descriptor/object binding tests, using generated fixtures only."""
import os
import unittest
from unittest.mock import patch

from core import broker_native_acquisition as native
from core import test_broker_native_acquisition as helpers


class NativeDescriptorBindingTests(unittest.TestCase):
    def setUp(self):
        helpers.NativeFixtureAcquisitionTests.setUp(self)

    def opening(self): return helpers.NativeFixtureAcquisitionTests.opening(self)
    def request(self, answer='ALLOW ONCE'): return helpers.NativeFixtureAcquisitionTests.request(self, answer)
    def terminal(self): return helpers.NativeFixtureAcquisitionTests.terminal(self)
    def rejected_stage(self, frame): return helpers.NativeFixtureAcquisitionTests.rejected_stage(self, frame)

    def foreign(self):
        owner = native._NativeReadFixture()
        self.addCleanup(owner.close)
        return owner

    def preserved(self, owner):
        self.assertIsNotNone(owner._fd)
        self.assertEqual(os.fstat(owner._fd).st_size, len(helpers.NativeFixtureAcquisitionTests.DATA))

    def test_equal_content_foreign_fd_is_rejected_before_read_and_not_closed(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        original_path = owner.description.display_path
        owner._fd = foreign._fd
        with patch.object(native.os, 'read', side_effect=AssertionError('wrong fd must not read')) as read:
            self.rejected_stage(frame); read.assert_not_called()
        self.assertFalse(os.path.exists(original_path))
        self.preserved(foreign)

    def test_cached_native_handle_substitution_is_rejected_before_read(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        original_path = owner.description.display_path
        owner._handle = foreign._handle
        with patch.object(native.os, 'read', side_effect=AssertionError('wrong handle must not read')) as read:
            self.rejected_stage(frame); read.assert_not_called()
        self.assertFalse(os.path.exists(original_path))
        self.preserved(foreign)

    def test_equal_valued_float_fd_is_not_an_owned_descriptor(self):
        frame = self.request(); self.adapter._owner._fd = float(self.adapter._owner._fd)
        with patch.object(native.os, 'read', side_effect=AssertionError('float fd must not read')) as read:
            self.rejected_stage(frame); read.assert_not_called()

    def test_boolean_fd_is_not_an_owned_descriptor(self):
        frame = self.request(); self.adapter._owner._fd = True
        with patch.object(native.os, 'read', side_effect=AssertionError('bool fd must not read')) as read:
            self.rejected_stage(frame); read.assert_not_called()

    def test_equal_valued_float_native_handle_is_rejected(self):
        frame = self.request(); self.adapter._owner._handle = float(self.adapter._owner._handle)
        with patch.object(native.os, 'read', side_effect=AssertionError('float handle must not read')) as read:
            self.rejected_stage(frame); read.assert_not_called()

    def test_fd_change_during_metadata_validation_is_rejected_before_read(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        real_metadata = owner._native.metadata
        changed = [False]
        def metadata(*args):
            result = real_metadata(*args)
            if not changed[0]:
                changed[0] = True; owner._fd = foreign._fd
            return result
        with patch.object(owner._native, 'metadata', side_effect=metadata):
            with patch.object(native.os, 'read', side_effect=AssertionError('changed fd must not read')) as read:
                self.rejected_stage(frame); read.assert_not_called()
        self.preserved(foreign)

    def test_fd_change_during_seek_is_rejected_before_read(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        real_seek = os.lseek
        def seek(fd, offset, origin):
            result = real_seek(fd, offset, origin); owner._fd = foreign._fd; return result
        with patch.object(native.os, 'lseek', side_effect=seek):
            with patch.object(native.os, 'read', side_effect=AssertionError('changed fd must not read')) as read:
                self.rejected_stage(frame); read.assert_not_called()
        self.preserved(foreign)

    def test_fd_change_during_read_withholds_private_staging_frame(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        real_read = os.read
        def read(fd, size):
            data = real_read(fd, size); owner._fd = foreign._fd; return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)
        self.preserved(foreign)

    def test_native_handle_change_during_read_withholds_private_staging_frame(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        real_read = os.read
        def read(fd, size):
            data = real_read(fd, size); owner._handle = foreign._handle; return data
        with patch.object(native.os, 'read', side_effect=read): self.rejected_stage(frame)
        self.preserved(foreign)

    def test_closed_and_reused_fd_never_reads_or_closes_foreign_object(self):
        frame = self.request(); owner, foreign = self.adapter._owner, self.foreign()
        original_fd = owner._fd
        os.close(original_fd)
        reused = os.dup(foreign._fd)
        self.assertEqual(reused, original_fd, 'CRT must reuse lowest available fixture descriptor')
        def close_reused():
            try: os.close(reused)
            except OSError: pass
        self.addCleanup(close_reused)
        try:
            with patch.object(native.os, 'read', side_effect=AssertionError('reused fd must not read')) as read:
                with self.assertRaises(native.NativeAcquisitionError): self.adapter.stage(frame)
                read.assert_not_called()
            self.assertEqual(os.fstat(reused).st_size, len(helpers.NativeFixtureAcquisitionTests.DATA))
            self.assertTrue(owner._cleanup_failed)
            self.preserved(foreign)
        finally:
            # Original ownership was deliberately destroyed in this test; the
            # known foreign duplicate is closed by test cleanup, never adapter.
            self.adapter._owner = None
