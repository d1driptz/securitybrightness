import unittest
from unittest.mock import patch

from core.api import check_action
from core.policy import Decision


class FakeApprovalProvider:
    def __init__(self, approved):
        self.approved = approved

    def request_approval(self, event):
        return self.approved


class ApiTests(unittest.TestCase):
    @patch("core.security.log_event")
    def test_safe_application_request_is_allowed(self, _log_event):
        result = check_action("read", "example.txt")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.decision_source, "policy")

    @patch("core.security.log_event")
    def test_sensitive_application_request_can_be_approved(self, _log_event):
        result = check_action(
            "read",
            ".env",
            approval_provider=FakeApprovalProvider(True),
        )
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.decision_source, "user")
        self.assertEqual(result.policy_rule, "sensitive_target")

    @patch("core.security.log_event")
    def test_blocked_application_request_is_denied(self, _log_event):
        result = check_action("disable_security", "system_resource")
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.decision_source, "policy")


if __name__ == "__main__":
    unittest.main()
