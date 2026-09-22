import gc
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from core.history import HistoryUnavailable, MAX_HISTORY_BYTES, project_history, read_decision_history
from core.events import SecurityEvent
from core.logger import log_event
from core.permissions import PermissionResult
from core.policy import Decision


class HistoryTests(unittest.TestCase):
    def setUp(self):
        gc.collect()

    def tearDown(self):
        gc.collect()

    def test_real_audit_projection_does_not_modify_or_expose_freeform_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'audit.json'
            with patch('core.logger.LOG_FILE', path):
                event = SecurityEvent.create('test', 'SYNTHETIC_SOURCE', 'read', 'SYNTHETIC_TARGET', {'note': 'SYNTHETIC_DETAILS'})
                log_event(event, PermissionResult(Decision.ALLOW, 'SYNTHETIC_REASON', 'policy', 'safe_read'))
                original = path.read_bytes()
                snapshot = read_decision_history()
                self.assertEqual(path.read_bytes(), original)
            self.assertEqual(snapshot.status, 'available')
            self.assertEqual(snapshot.records[0].request_id, event.request_id)
            self.assertEqual(snapshot.records[0].policy_rule, 'safe_read')
            self.assertNotIn('SYNTHETIC_', repr(snapshot))
            with self.assertRaises(FrozenInstanceError):
                snapshot.records[0].decision = 'allow'

    def test_append_order_cap_and_legacy_unknown_fields(self):
        rows = [{'timestamp': '2026-09-22T12:00:00Z', 'action': 'read', 'decision': 'allow'} for _ in range(105)]
        rows[-1].update(action='SYNTHETIC_SECRET', decision=True, timestamp='SYNTHETIC_SECRET')
        snapshot = project_history(json.dumps(rows).encode())
        self.assertEqual(snapshot.total_records, 105)
        self.assertEqual(len(snapshot.records), 100)
        self.assertEqual([snapshot.records[0].position, snapshot.records[-1].position], [105, 6])
        self.assertEqual(snapshot.records[-1].request_id, 'not recorded / unrecognized')
        self.assertNotIn('SYNTHETIC_SECRET', repr(snapshot))
        self.assertEqual(snapshot.records[0].decision, 'not recorded / unrecognized')

    def test_every_current_policy_outcome_survives_real_decision_logging(self):
        from core.security import process_event
        class DenyReview:
            def request_approval(self, event, strong=False):
                return False
        cases = [('', 'notes', 'missing_action'),
                 ('disable_security', 'notes', 'blocked_action'),
                 ('read', '.env', 'sensitive_target'),
                 ('read', 'notes', 'safe_read'),
                 ('write', 'notes', 'change_or_execute'),
                 ('custom', 'notes', 'unknown_action')]
        with tempfile.TemporaryDirectory() as folder:
            with patch('core.logger.LOG_FILE', Path(folder) / 'audit.json'):
                for action, target, rule in cases:
                    with self.subTest(rule=rule):
                        event = SecurityEvent.create('test', 'test', action, target)
                        result = process_event(event, DenyReview())
                        row = read_decision_history().records[0]
                        self.assertEqual(row.policy_rule, rule)
                        self.assertEqual(row.decision, result.decision.value)
                        self.assertEqual(row.human_control, result.human_control)

    def test_missing_empty_corrupt_and_oversized_are_distinct(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'audit.json'
            with patch('core.logger.LOG_FILE', path):
                self.assertEqual(read_decision_history().status, 'missing')
                self.assertFalse(path.exists())
                path.write_bytes(b'[]')
                self.assertEqual(read_decision_history().status, 'available')
                for payload in [b'broken', b'{}', b'[1]', b'[{"a":1,"a":2}]', b'[NaN]', b'\xff', b' ' * (MAX_HISTORY_BYTES + 1)]:
                    path.write_bytes(payload)
                    with self.assertRaises(HistoryUnavailable):
                        read_decision_history()
                    self.assertEqual(path.read_bytes(), payload)

    def test_busy_writer_and_read_error_do_not_reset_history(self):
        from core import logger
        entered, release = threading.Event(), threading.Event()
        def hold():
            with logger._LOG_LOCK:
                entered.set()
                release.wait(5)
        thread = threading.Thread(target=hold)
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            with self.assertRaisesRegex(HistoryUnavailable, 'busy'):
                read_decision_history()
        finally:
            release.set()
            thread.join(timeout=2)
        with patch.object(Path, 'open', side_effect=PermissionError('SYNTHETIC_SECRET')):
            with self.assertRaises(HistoryUnavailable) as failure:
                read_decision_history()
        self.assertNotIn('SYNTHETIC_SECRET', str(failure.exception))

    def test_actual_widget_refresh_escapes_ids_clears_stale_results_and_closes(self):
        try:
            import tkinter as tk
            from core.desktop import ReviewWindow
        except ImportError:
            self.skipTest('Tk is not installed')
        from core.review_channel import OperatorReviewChannel
        gc.collect()
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest('Tk display unavailable')
        root.withdraw()
        channel = OperatorReviewChannel()
        snapshot = project_history(json.dumps([{'decision': 'allow', 'action': 'read',
                                                'application_id': 'app\nFAKE\u202e',
                                                'details': {'token': 'SYNTHETIC_SECRET'}}]).encode())
        def wait_panel(panel):
            deadline = time.monotonic() + 3
            while panel.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.005)
            self.assertFalse(panel.busy)
        with patch('core.desktop.read_decision_history', return_value=snapshot):
            window = ReviewWindow(root, channel)
        try:
            panel = window.history
            panel.refresh.invoke()
            wait_panel(panel)
            text = panel.text.get('1.0', 'end')
            self.assertIn(r'app\nFAKE\u202e', text)
            self.assertNotIn('\u202e', text)
            self.assertNotIn('SYNTHETIC_SECRET', text)
            self.assertIn('not execution evidence', text)
            def fail():
                raise HistoryUnavailable('SYNTHETIC_SECRET')
            panel._reader = fail
            panel.refresh.invoke()
            self.assertNotIn('recorded decision: allow', panel.text.get('1.0', 'end'))
            wait_panel(panel)
            self.assertIn('History unavailable', panel.status.get())
            self.assertNotIn('SYNTHETIC_SECRET', panel.text.get('1.0', 'end'))
            self.assertEqual(channel.pending_reviews(), ())
            timer = panel._timer
            window.close()
            self.assertNotIn(timer, root.tk.call('after', 'info'))
        finally:
            if not window.closed:
                window.close()
            gc.collect()
