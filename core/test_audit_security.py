import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from core.api import check_action
from core.events import SecurityEvent
from core.logger import AuditLogError, log_event
from core.permissions import PermissionResult
from core.policy import Decision


class AuditSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "events.json"
        self.log_patch = patch("core.logger.LOG_FILE", self.log)
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)

    def event(self, details=None):
        return SecurityEvent.create("test", "suite", "read", "x", details)

    def result(self):
        return PermissionResult(Decision.ALLOW, "safe", "policy", "safe_read")

    def test_redacts_secret_key_variants_recursively(self):
        keys = ["accessToken", "refresh_token", "API-KEY", "privateKey", "client_secret",
                "Proxy-Authorization", "Set-Cookie", "session_id", "userPassword", "credentials"]
        details = {"nested": [{key: "hidden" for key in keys}], "note": "visible"}
        log_event(self.event(details), self.result())
        text = self.log.read_text()
        self.assertNotIn("hidden", text)
        record = json.loads(text)[0]
        self.assertEqual(record["details"]["note"], "visible")
        self.assertTrue(all(value == "[REDACTED]" for value in record["details"]["nested"][0].values()))

    def test_invalid_existing_history_is_preserved(self):
        for original in (b"broken", b"{}", b"[1]", b'[{"a":1,"a":2}]', b'[{"a":NaN}]',
                         b'[{"a":"\xff"}]'):
            with self.subTest(original=original):
                self.log.write_bytes(original)
                with self.assertRaises(AuditLogError):
                    log_event(self.event(), self.result())
                self.assertEqual(self.log.read_bytes(), original)

    def test_read_errors_do_not_reset_history(self):
        original = b'[{"previous":"record"}]'
        self.log.write_bytes(original)
        with patch.object(Path, "read_text", side_effect=PermissionError), self.assertRaises(AuditLogError):
            log_event(self.event(), self.result())
        self.assertEqual(self.log.read_bytes(), original)

    def test_replace_failure_preserves_history_and_cleans_tempfile(self):
        original = b'[{"previous":"record"}]'
        self.log.write_bytes(original)
        with patch.object(Path, "replace", side_effect=OSError), self.assertRaises(AuditLogError):
            log_event(self.event(), self.result())
        self.assertEqual(self.log.read_bytes(), original)
        self.assertEqual(list(self.log.parent.glob("*.tmp")), [])

    def test_flush_failure_preserves_history_and_cleans_tempfile(self):
        original = b'[{"previous":"record"}]'
        self.log.write_bytes(original)
        with patch("core.logger.os.fsync", side_effect=OSError), self.assertRaises(AuditLogError):
            log_event(self.event(), self.result())
        self.assertEqual(self.log.read_bytes(), original)
        self.assertEqual(list(self.log.parent.glob("*.tmp")), [])

    def test_threaded_writers_do_not_lose_audit_records(self):
        events = [self.event() for _ in range(24)]
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda event: log_event(event, self.result()), events))
        records = json.loads(self.log.read_text())
        self.assertEqual(len(records), 24)
        self.assertEqual({record["request_id"] for record in records}, {event.request_id for event in events})

    def test_invalid_new_record_does_not_poison_existing_history(self):
        original = b'[{"previous":"record"}]'
        for details in ({"value": float("nan")}, {"value": "\ud800"}, {"value": object()}):
            with self.subTest(details=details):
                self.log.write_bytes(original)
                with self.assertRaises(AuditLogError):
                    log_event(self.event(details), self.result())
                self.assertEqual(self.log.read_bytes(), original)

    def test_python_api_cannot_return_allow_when_audit_fails(self):
        self.log.write_bytes(b"corrupt")
        with self.assertRaises(AuditLogError):
            check_action("read", "x")
