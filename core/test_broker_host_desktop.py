"""Real Tk and private child tests, distinct from a human owner walkthrough."""
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import replace
from pathlib import Path
import threading
import time
import gc
import tkinter as tk
import unittest
from unittest.mock import patch
from core import broker_transport as transport
from core import broker_process as process
from core.broker_host_desktop import BrokerHostWindow
from core.broker_review_host import BrokerReviewHost
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry


class BrokerHostDesktopTests(unittest.TestCase):
    def setUp(self):
        # Collect prior Tk test cycles on the UI thread, before starting a worker.
        gc.collect()
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.registry = ApplicationRegistry(); self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', ['files.read'])
        self.ledger = FileReadReviewLedger()
        self.draft = self.ledger.create(FileReadConstraint('app', 'label', max_bytes=128))
        self.proposal = make_file_read_proposal('label', max_bytes=128)
        self.root = tk.Tk(); self.root.withdraw()
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.host = BrokerReviewHost(self.registry, self.ledger, timeout=2)
        self.window = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.host.close(); self.pool.shutdown(wait=True)
        if self.window is not None and not self.window.closed: self.window._destroy()
        elif self.window is None: self.root.destroy()
        self.window = self.root = None
        gc.collect()

    def start(self, wait=True):
        self.future = self.pool.submit(self.host.worker.run, 'app', self.credential,
                                      self.proposal, self.draft.draft_id, 1)
        self.window = BrokerHostWindow(self.root, self.host.operator, self.future, self.pool)
        if wait: self.pump(lambda: self.window.current is not None)
        return self.window

    def pump(self, condition):
        deadline = time.monotonic()+4
        while not condition() and time.monotonic() < deadline:
            self.root.update(); time.sleep(.003)
        self.assertTrue(condition(), self.window.status.get())

    def finish(self):
        self.pump(lambda: self.window.terminal)

    def test_real_allow_requires_exact_confirmation_and_joined_cleanup(self):
        window = self.start(); path = Path(window.current.display_path)
        self.assertTrue(path.exists())
        window.allow.invoke(); self.assertFalse(self.future.done())
        window.confirmation.insert(0, 'allow once')
        window.allow.invoke(); self.assertFalse(self.future.done())
        window.confirmation.delete(0, 'end'); window.confirmation.insert(0, 'ALLOW ONCE')
        window.allow.invoke()
        self.assertIn('queued', window.status.get())
        self.finish()
        self.assertIn('retired: allow_once', window.status.get())
        self.assertIn('Worker joined; child cleanup confirmed', window.status.get())
        self.assertIn('0 protected bytes', window.status.get())
        self.assertFalse(path.exists())
        self.assertTrue(all(not thread.is_alive() for thread in self.pool._threads))
        self.assertEqual(str(window.allow['state']), 'disabled')
        self.assertEqual(window.confirmation.get(), '')

    def test_deny_and_no_enter_approval_binding(self):
        window = self.start()
        self.assertEqual(window.confirmation.bind('<Return>'), '')
        window.deny.invoke(); self.finish()
        self.assertIn('retired: deny', window.status.get())

    def test_cancel_stays_visible_until_cleanup_confirmed(self):
        window = self.start(); path = Path(window.current.display_path)
        window.cancel.invoke()
        self.assertIn('waiting for worker cleanup', window.status.get())
        self.finish()
        self.assertFalse(window.closed)
        self.assertIn('cancelled, expired or rejected', window.status.get())
        self.assertIn('cleanup confirmed', window.status.get())
        self.assertFalse(path.exists())

    def test_window_close_waits_for_worker_before_destroying(self):
        window = self.start(); path = Path(window.current.display_path)
        window.close()
        self.assertFalse(window.closed)
        self.pump(lambda: window.closed)
        self.assertTrue(self.future.done())
        self.assertTrue(all(not thread.is_alive() for thread in self.pool._threads))
        self.assertFalse(path.exists())

    def test_close_during_startup_joins_worker(self):
        window = self.start(wait=False)
        window.close(); self.pump(lambda: window.closed)
        self.assertTrue(self.future.done())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_expiry_reports_no_success_and_cleanup(self):
        self.host = BrokerReviewHost(self.registry, self.ledger, timeout=.5)
        window = self.start(); self.finish()
        self.assertIn('expired', window.status.get())
        self.assertIn('cleanup confirmed', window.status.get())
        self.assertNotIn('retired: allow_once', window.status.get())

    def test_revocation_after_display_never_reports_allow(self):
        window = self.start(); self.registry.revoke('app')
        window.respond('ALLOW ONCE'); self.finish()
        self.assertIn('rejected', window.status.get())
        self.assertNotIn('retired: allow_once', window.status.get())

    def test_mutation_cancels_and_joins(self):
        window = self.start()
        object.__setattr__(window.current, 'file_id', 'f'*32)
        window.respond('ALLOW ONCE'); self.finish()
        self.assertIn('rejected', window.status.get())
        self.assertTrue(self.host.operator.shutdown_status().cleanup_confirmed)

    def test_display_is_readonly_and_credential_free(self):
        window = self.start()
        self.assertEqual(str(window.text['state']), 'disabled')
        text = window.text.get('1.0', 'end')
        for name in ('application_id', 'proposal_json', 'file_id', 'volume_serial', 'max_bytes'):
            self.assertIn(name, text)
        self.assertNotIn(self.credential, text)

    def test_cleanup_failure_does_not_claim_confirmation_or_auto_close(self):
        original = process._ReviewWaitChild.close
        def fail(child):
            original(child); raise process.BrokerProcessError('process_cleanup_failed')
        with patch.object(process._ReviewWaitChild, 'close', fail):
            window = self.start(); window.close(); self.finish()
        self.assertFalse(window.closed)
        self.assertIn('could NOT be confirmed', window.status.get())
        self.assertFalse(self.host.operator.shutdown_status().cleanup_confirmed)
        window.close(); self.assertTrue(window.closed)

    def test_replay_buttons_do_not_restart_worker(self):
        window = self.start(); window.respond('DENY'); self.finish()
        status = window.status.get()
        window.respond('ALLOW ONCE'); window.approve()
        self.assertEqual(window.status.get(), status)

    def test_unexpected_receipt_is_not_reported_as_success(self):
        window = self.start(); window.respond('DENY')
        result = self.future.result(timeout=2)
        forged = Future(); forged.set_result(replace(result, decision='allow_once'))
        window.completion = forged; self.finish()
        self.assertNotIn('retired: allow_once', window.status.get())
        self.assertIn('rejected', window.status.get())

    def test_missing_cleanup_status_is_not_success(self):
        window = self.start(); window.respond('DENY')
        self.future.result(timeout=2)
        with patch.object(self.host.operator, 'shutdown_status', return_value=None): self.finish()
        self.assertIn('could NOT be confirmed', window.status.get())

    def test_cancel_before_worker_admission_has_confirmed_no_child_cleanup(self):
        self.host.close()
        window = self.start(wait=False); self.finish()
        self.assertIn('cleanup confirmed', window.status.get())
        self.assertFalse(self.host._started)

    def test_wrong_resource_receipt_never_reports_success(self):
        window = self.start(); window.respond('ALLOW ONCE')
        result = self.future.result(timeout=2)
        forged = Future(); forged.set_result(replace(result, canonical_display=b'{}'))
        window.completion = forged; self.finish()
        self.assertIn('rejected', window.status.get())
        self.assertNotIn('retired: allow_once', window.status.get())

    def test_standalone_bootstrap_failure_cancels_and_joins(self):
        from core import broker_host_desktop as desktop
        sessions = []
        def create(*args, **kwargs):
            result = BrokerReviewHost(*args, **kwargs); sessions.append(result); return result
        with patch.object(desktop, 'BrokerReviewHost', side_effect=create), \
                patch.object(desktop, 'BrokerHostWindow', side_effect=RuntimeError('UI unavailable')), \
                patch('sys.argv', ['fixture-demo']):
            with self.assertRaisesRegex(RuntimeError, 'UI unavailable'): desktop.main()
        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].operator.shutdown_status().cleanup_confirmed)

    def test_standalone_early_loop_exit_cancels_and_joins(self):
        from core import broker_host_desktop as desktop
        sessions = []
        windows = []
        def create(*args, **kwargs):
            result = BrokerReviewHost(*args, **kwargs); sessions.append(result); return result
        def create_window(*args):
            result = BrokerHostWindow(*args); windows.append(result); return result
        with patch.object(desktop, 'BrokerReviewHost', side_effect=create), \
                patch.object(desktop, 'BrokerHostWindow', side_effect=create_window), \
                patch('tkinter.Tk.mainloop', return_value=None), \
                patch('tkinter.Tk.deiconify', return_value=None), patch('sys.argv', ['fixture-demo']):
            desktop.main()
        self.assertTrue(sessions[0].operator.shutdown_status().cleanup_confirmed)
        self.assertTrue(windows[0].closed)

    def test_standalone_rejects_path_arguments_before_startup(self):
        from core import broker_host_desktop as desktop
        with patch('sys.argv', ['fixture-demo', 'personal-file.txt']), patch.object(desktop.tk, 'Tk') as root:
            with self.assertRaises(SystemExit): desktop.main()
            root.assert_not_called()
