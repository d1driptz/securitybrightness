import unittest
from unittest.mock import patch

from core.api import check_action


class FakeApprovalProvider:
    def __init__(self, approved):
        self.approved = approved

    def request_approval(self, event):
        return self.approved


class ApiTests(unittest.TestCase):
    @patch("core.security.log_event")
    def test_safe_application_request_is_allowed(self, _log_event):
        result = check_action("read", "example.txt")
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["decision_source"], "policy")
        self.assertTrue(result["request_id"])

    @patch("core.security.log_event")
    def test_sensitive_application_request_can_be_approved(self, _log_event):
        result = check_action(
            "read",
            ".env",
            approval_provider=FakeApprovalProvider(True),
        )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["decision_source"], "user")
        self.assertEqual(result["policy_rule"], "sensitive_target")

    @patch("core.security.log_event")
    def test_blocked_application_request_is_denied(self, _log_event):
        result = check_action("disable_security", "system_resource")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["decision_source"], "policy")

    @patch("core.security.log_event")
    def test_invalid_details_are_rejected(self, _log_event):
        with self.assertRaises(TypeError):
            check_action("read", "example.txt", details="not-a-dict")


if __name__ == "__main__":
    unittest.main()
