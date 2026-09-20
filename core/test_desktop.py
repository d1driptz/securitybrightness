import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from core.events import SecurityEvent
from core.permissions import ApprovalProviderError
from core.review_channel import OperatorReviewChannel


class DesktopTests(unittest.TestCase):
    def test_real_widgets_require_confirmation_and_close_pending_review(self):
        try:
            import tkinter as tk
            from core.desktop import ReviewWindow
        except ImportError:
            self.skipTest("Tk is not installed")
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Tk display is unavailable")
        root.withdraw()
        channel = OperatorReviewChannel(timeout=5)
        pool = ThreadPoolExecutor(max_workers=1)
        window = ReviewWindow(root, channel)
        try:
            event = SecurityEvent.create("test", "app", "send_message", "recipient\nFAKE",
                                         {"purpose": "hello\u202e"})
            future = pool.submit(channel.request_approval, event, strong=True)
            deadline = time.monotonic() + 2
            while not channel.pending_reviews() and time.monotonic() < deadline:
                time.sleep(0.005)
            window.poll()
            root.update_idletasks()
            self.assertIsNotNone(window.current)
            contents = window.text.get("1.0", "end")
            self.assertIn(r"recipient\nFAKE", contents)
            self.assertIn(r"hello\u202e", contents)
            self.assertNotIn("\u202e", contents)
            window.allow.invoke()
            self.assertFalse(future.done())
            window.confirmation.insert(0, "ALLOW")
            window.allow.invoke()
            self.assertTrue(future.result(timeout=1))
            self.assertEqual(str(window.allow.cget("state")), "disabled")
            self.assertEqual(window.confirmation.get(), "")
            pending = pool.submit(channel.request_approval, event, strong=True)
            deadline = time.monotonic() + 2
            while not channel.pending_reviews() and time.monotonic() < deadline:
                time.sleep(0.005)
            window.close()
            with self.assertRaises(ApprovalProviderError):
                pending.result(timeout=1)
        finally:
            channel.close()
            if not window.closed:
                window.close()
            pool.shutdown(wait=True)
