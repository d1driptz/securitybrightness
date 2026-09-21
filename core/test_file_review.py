import os
import gc
from pathlib import Path
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from file_security.acquisition import FileInputError, read_selected_file
from file_security import analyze_bytes


class FileAcquisitionTests(unittest.TestCase):
    def test_regular_snapshot_and_size_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.txt'
            for size in [0, 1, 1048576]:
                path.write_bytes(b'x' * size)
                self.assertEqual(read_selected_file(str(path)), b'x' * size)
            path.write_bytes(b'x' * 1048577)
            with self.assertRaisesRegex(FileInputError, 'input_too_large'):
                read_selected_file(str(path))

    def test_path_types_directories_devices_and_missing_files(self):
        for path in [None, Path('sample'), 'relative.txt', '', '\x00']:
            with self.assertRaisesRegex(FileInputError, 'unsupported_path'):
                read_selected_file(path)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(FileInputError, 'unsupported_file'):
                read_selected_file(folder)
            with self.assertRaisesRegex(FileInputError, '^file_unavailable$'):
                read_selected_file(str(Path(folder) / 'SYNTHETIC_SECRET.txt'))
        if os.name == 'nt':
            for path in ['C:\\NUL', '\\\\server\\share\\file.txt', 'C:\\file.txt:stream']:
                with self.assertRaises(FileInputError):
                    read_selected_file(path)

    def test_changed_file_is_rejected_and_read_error_is_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.txt'
            path.write_bytes(b'original')
            real_read = os.read
            changed = False
            def mutate(descriptor, size):
                nonlocal changed
                data = real_read(descriptor, size)
                if not changed:
                    path.write_bytes(b'changed content length')
                    changed = True
                return data
            with patch('file_security.acquisition.os.read', side_effect=mutate):
                with self.assertRaises(FileInputError):
                    read_selected_file(str(path))
            with patch('file_security.acquisition.os.read', side_effect=OSError('SYNTHETIC_SECRET')):
                with self.assertRaisesRegex(FileInputError, '^file_unavailable$'):
                    read_selected_file(str(path))
            # The descriptor must have been closed on failure.
            path.unlink()


class FileReviewWidgetTests(unittest.TestCase):
    def setUp(self):
        # Repeated test roots must be finalized on the Tk/main thread, before
        # background allocation can collect unreachable earlier widget cycles.
        gc.collect()

    def tearDown(self):
        gc.collect()

    def make_window(self):
        import tkinter as tk
        from core.desktop import ReviewWindow
        from core.review_channel import OperatorReviewChannel
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest('Tk display unavailable')
        root.withdraw()
        channel = OperatorReviewChannel(timeout=5)
        return root, channel, ReviewWindow(root, channel)

    def wait_report(self, root, panel):
        deadline = time.monotonic() + 8
        while panel.busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        self.assertFalse(panel.busy)
        return panel.evidence.get('1.0', 'end')

    def test_operator_selection_runs_real_worker_without_exposing_contents(self):
        root, channel, window = self.make_window()
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'sample.txt'
                path.write_bytes(b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC_SECRET')
                with patch('file_security.desktop.filedialog.askopenfilename', return_value=str(path)):
                    window.file_review.choose.invoke()
                report = self.wait_report(root, window.file_review)
                self.assertIn('pem.private-key', report)
                self.assertIn('Snapshot SHA-256:', report)
                self.assertNotIn('SYNTHETIC_SECRET', report)
                self.assertIn('No file was modified', report)
                self.assertEqual(channel.pending_reviews(), ())
                self.assertEqual(path.read_bytes(), b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC_SECRET')
        finally:
            window.close()

    def test_cancellation_and_failure_never_display_a_clean_verdict(self):
        root, channel, window = self.make_window()
        panel = window.file_review
        try:
            with patch('file_security.desktop.filedialog.askopenfilename', return_value=''), patch('file_security.desktop.read_selected_file') as read:
                panel.choose.invoke()
                read.assert_not_called()
                self.assertFalse(panel.busy)
            with patch('file_security.desktop.filedialog.askopenfilename', return_value='selected.txt'), patch('file_security.desktop.read_selected_file', side_effect=OSError('SYNTHETIC_SECRET')):
                panel.choose.invoke()
                report = self.wait_report(root, panel)
            self.assertIn('No analysis conclusion', report)
            self.assertNotIn('SYNTHETIC_SECRET', report)
            self.assertNotIn('No supported header patterns found', report)
        finally:
            window.close()

    def test_review_keeps_priority_and_close_does_not_wait_for_file_io(self):
        from core.events import SecurityEvent
        root, channel, window = self.make_window()
        panel = window.file_review
        entered, release = threading.Event(), threading.Event()
        def delayed_read(path):
            entered.set()
            release.wait(8)
            return b'ordinary text'
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                with patch('file_security.desktop.filedialog.askopenfilename', return_value='selected.txt'), patch('file_security.desktop.read_selected_file', side_effect=delayed_read):
                    panel.choose.invoke()
                    self.assertTrue(entered.wait(1))
                    self.assertTrue(panel.busy)
                    window.tabs.select(panel.frame)
                    event = SecurityEvent.create('test', 'app', 'send_message', 'recipient')
                    future = pool.submit(channel.request_approval, event, strong=False)
                    deadline = time.monotonic() + 2
                    while not channel.pending_reviews() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    window.poll()
                    self.assertEqual(window.tabs.select(), str(window.review_frame))
                    self.assertFalse(future.done())
                    window.deny.invoke()
                    self.assertFalse(future.result(timeout=1))
                    timers = (window._poll_timer, panel._timer)
                    window.close()
                    remaining = root.tk.call('after', 'info')
                    for timer in timers:
                        self.assertNotIn(timer, remaining)
                    self.assertTrue(panel.closed)
                    release.set()
                    deadline = time.monotonic() + 2
                    while panel._results.empty() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertFalse(panel._results.empty())
                    panel.wait_for_cleanup()
                    self.assertIn('analysis_cancelled', panel._results.get_nowait())
            finally:
                release.set()
                if not window.closed:
                    window.close()
