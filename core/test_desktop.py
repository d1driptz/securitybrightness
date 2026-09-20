import tempfile
from pathlib import Path
from unittest.mock import patch
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from core.events import SecurityEvent
from core.permissions import ApprovalProviderError
from core.review_channel import OperatorReviewChannel
from core.registry import ApplicationRegistry


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
        registry = ApplicationRegistry()
        credential = registry.register("app", ["communications.send"])
        window = ReviewWindow(root, channel, application_reader=registry.list_applications)
        try:
            rows = window.application_table.get_children()
            self.assertEqual(len(rows), 1)
            values = window.application_table.item(rows[0], "values")
            self.assertIn("communications.send", str(values))
            window.application_table.selection_set(rows[0])
            window.show_application()
            self.assertIn("communications.send", window.application_details.get("1.0", "end"))
            self.assertNotIn(credential, str(values))
            self.assertNotIn(registry.get("app").credential_hash, str(values))
            registry.revoke("app")
            window.refresh_applications()
            self.assertEqual(window.application_table.get_children(), ())
            window.tabs.select(1)
            event = SecurityEvent.create("test", "app", "send_message", "recipient\nFAKE",
                                         {"purpose": "hello\u202e"})
            future = pool.submit(channel.request_approval, event, strong=True)
            deadline = time.monotonic() + 2
            while not channel.pending_reviews() and time.monotonic() < deadline:
                time.sleep(0.005)
            window.poll()
            root.update_idletasks()
            self.assertIsNotNone(window.current)
            self.assertEqual(window.tabs.select(), str(window.review_frame))
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


    def test_operator_controls_require_confirmation_and_can_revoke_inactive_grants(self):
        try:
            import tkinter as tk
            from core.desktop import ReviewWindow
            from core.authority_store import SQLiteAuthorityStore
        except ImportError:
            self.skipTest("Tk is not installed")
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Tk display unavailable")
        root.withdraw()
        with tempfile.TemporaryDirectory() as folder:
            registry = ApplicationRegistry(store=SQLiteAuthorityStore(Path(folder) / "authority.db"))
            credential = registry.register("app", ["files.read"])
            channel = OperatorReviewChannel()
            window = ReviewWindow(root, channel, application_reader=registry.list_applications,
                                  persistent_mode=True, authority_unlock=registry.operator_unlock,
                                  authority_revoke=registry.operator_revoke, authority_lock=registry.lock_all)
            def select():
                window.refresh_applications()
                row = window.application_table.get_children()[0]
                window.application_table.selection_set(row)
                window.show_application()
            try:
                select()
                text = window.application_details.get("1.0", "end")
                self.assertIn("locked / inactive", text)
                self.assertIn("Created:", text)
                self.assertIn("Expiry:", text)
                with patch("core.desktop.messagebox.askyesno", return_value=False):
                    window.unlock_button.invoke()
                self.assertIsNone(registry.authenticate("app", credential))
                def changed_while_confirming(*args, **kwargs):
                    registry.set_scopes("app", ["files.write"])
                    return True
                with patch("core.desktop.messagebox.askyesno", side_effect=changed_while_confirming), patch("core.desktop.messagebox.showwarning") as warning:
                    window.unlock_button.invoke()
                warning.assert_called_once()
                self.assertFalse(registry.list_applications()[0].active)
                select()
                with patch("core.desktop.messagebox.askyesno", return_value=True) as confirmation:
                    window.unlock_button.invoke()
                self.assertIn("files.write", confirmation.call_args.args[1])
                self.assertTrue(registry.list_applications()[0].active)
                window.lock_button.invoke()
                self.assertFalse(registry.list_applications()[0].active)
                select()
                with patch("core.desktop.messagebox.askyesno", return_value=True):
                    window.revoke_button.invoke()
                self.assertEqual(registry.list_applications(), ())
            finally:
                if not window.closed:
                    window.close()
                registry.close()
