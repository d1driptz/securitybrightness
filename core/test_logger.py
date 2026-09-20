import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.events import SecurityEvent
from core.logger import AuditLogError, log_event
from core.permissions import PermissionResult
from core.policy import Decision


class LoggerTests(unittest.TestCase):
    def result(self):
        return PermissionResult(
            decision=Decision.ALLOW,
            reason="Allowed by test policy.",
            decision_source="policy",
            policy_rule="safe_read",
        )

    def event(self):
        return SecurityEvent.create(
            event_type="file_access",
            source="test_suite",
            action="read",
            target="example.txt",
            details={"purpose": "test"},
        )

    def test_audit_record_contains_decision_context(self):
        event = self.event()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            with patch("core.logger.LOG_FILE", log_path):
                log_event(event, self.result())

            record = json.loads(log_path.read_text(encoding="utf-8"))[0]
            self.assertEqual(record["request_id"], event.request_id)
            self.assertEqual(record["decision"], "allow")
            self.assertEqual(record["decision_source"], "policy")
            self.assertEqual(record["policy_rule"], "safe_read")
            self.assertEqual(record["target"], "example.txt")
            self.assertTrue(record["timestamp"].endswith("Z"))

    def test_malformed_existing_log_fails_safe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            log_path.write_text("not-json", encoding="utf-8")
            original = log_path.read_bytes()
            with patch("core.logger.LOG_FILE", log_path), self.assertRaises(AuditLogError):
                log_event(self.event(), self.result())
            self.assertEqual(log_path.read_bytes(), original)

    def test_non_list_existing_log_fails_safe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            log_path.write_text('{"unexpected": true}', encoding="utf-8")
            original = log_path.read_bytes()
            with patch("core.logger.LOG_FILE", log_path), self.assertRaises(AuditLogError):
                log_event(self.event(), self.result())
            self.assertEqual(log_path.read_bytes(), original)

    def test_sensitive_detail_values_are_redacted_recursively(self):
        event = SecurityEvent.create(
            event_type="test",
            source="test_suite",
            action="read",
            target="example.txt",
            details={
                "purpose": "safe to log",
                "token": "top-secret",
                "nested": {"password": "hidden", "note": "visible"},
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            with patch("core.logger.LOG_FILE", log_path):
                log_event(event, self.result())

            details = json.loads(log_path.read_text(encoding="utf-8"))[0]["details"]
            self.assertEqual(details["purpose"], "safe to log")
            self.assertEqual(details["token"], "[REDACTED]")
            self.assertEqual(details["nested"]["password"], "[REDACTED]")
            self.assertEqual(details["nested"]["note"], "visible")


if __name__ == "__main__":
    unittest.main()
