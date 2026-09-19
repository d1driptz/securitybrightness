import unittest
from unittest.mock import patch

from core.approval import TerminalApprovalProvider
from core.events import SecurityEvent


class ApprovalTests(unittest.TestCase):
    def event(self):
        return SecurityEvent.create(
            event_type="test",
            source="assistant",
            action="send_message",
            target="recipient",
            details={"purpose": "reply to a message"},
        )

    @patch("builtins.input", return_value="ALLOW")
    def test_strong_confirmation_requires_exact_allow(self, _input):
        self.assertTrue(
            TerminalApprovalProvider().request_approval(self.event(), strong=True)
        )

    @patch("builtins.input", return_value="yes")
    def test_strong_confirmation_rejects_normal_yes(self, _input):
        self.assertFalse(
            TerminalApprovalProvider().request_approval(self.event(), strong=True)
        )


if __name__ == "__main__":
    unittest.main()
