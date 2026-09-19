import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.events import SecurityEvent
from core.logger import log_event
from core.permissions import PermissionResult
from core.policy import Decision


class LoggerTests(unittest.TestCase):
    def test_audit_record_contains_decision_context(self):
        event = SecurityEvent.create(
            event_type="file_access",
            source="test_suite",
            action="read",
            target="example.txt",
            details={"purpose": "test"},
        )
        result = PermissionResult(
            decision=Decision.ALLOW,
            reason="Allowed by test policy.",
            decision_source="policy",
            policy_rule="safe_read",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            with patch("core.logger.LOG_FILE", log_path):
                log_event(event, result)

            records = json.loads(log_path.read_text())
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record["decision"], "allow")
            self.assertEqual(record["decision_source"], "policy")
            self.assertEqual(record["policy_rule"], "safe_read")
            self.assertEqual(record["reason"], "Allowed by test policy.")
            self.assertEqual(record["target"], "example.txt")
            self.assertTrue(record["timestamp"].endswith("Z"))

    def test_malformed_existing_log_fails_safe(self):
        event = SecurityEvent.create(
            event_type="test",
            source="test_suite",
            action="read",
            target="example.txt",
        )
        result = PermissionResult(
            decision=Decision.ALLOW,
            reason="Allowed.",
            decision_source="policy",
            policy_rule="safe_read",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.json"
            log_path.write_text("not-json")
            with patch("core.logger.LOG_FILE", log_path):
                log_event(event, result)

            records = json.loads(log_path.read_text())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
