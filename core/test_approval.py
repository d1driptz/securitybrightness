import io
import unittest
from contextlib import redirect_stdout
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

    def test_both_review_modes_show_proposal_context_before_input(self):
        for action, strong, answer, scope in (
            ("write", False, "yes", "files.write"),
            ("transfer_money", True, "ALLOW", "payments.transfer"),
        ):
            with self.subTest(action=action):
                event = SecurityEvent.create("test", "billing-assistant", action, "proposal-42",
                                             {"purpose": "review this bill", "credential": "HIDDEN"})
                output = io.StringIO()
                def respond(prompt):
                    display = output.getvalue()
                    for value in (event.request_id, "billing-assistant", action, "proposal-42", scope):
                        self.assertIn(value, display)
                    self.assertIn("Requester explanation (unverified):", display)
                    self.assertIn("review this bill", display)
                    self.assertIn("not a grant", display)
                    self.assertIn("does not grant ongoing authority", display)
                    self.assertNotIn("HIDDEN", display)
                    return answer
                with redirect_stdout(output), patch("builtins.input", side_effect=respond):
                    self.assertTrue(TerminalApprovalProvider().request_approval(event, strong=strong))

    def test_ordinary_review_reprompts_then_denies_and_supports_reason(self):
        event = SecurityEvent.create("test", "app", "write", "notes", {"reason": "fix typo"})
        output = io.StringIO()
        with redirect_stdout(output), patch("builtins.input", side_effect=["maybe", "no"]) as prompt:
            self.assertFalse(TerminalApprovalProvider().request_approval(event))
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(output.getvalue().count("Request ID:"), 1)
        self.assertIn('Requester explanation (unverified): "fix typo"', output.getvalue())

    def test_ordinary_review_escapes_all_caller_labels(self):
        event = SecurityEvent.create("test", "app\x1b[2J", "custom\nACTION", "notes\rTARGET",
                                     {"purpose": "looks safe\u202e"})
        output = io.StringIO()
        with redirect_stdout(output), patch("builtins.input", return_value="no"):
            self.assertFalse(TerminalApprovalProvider().request_approval(event))
        display = output.getvalue()
        for control in ("\x1b", "\r", "\u202e"):
            self.assertNotIn(control, display)
        self.assertIn(r"custom\nACTION", display)
        self.assertIn(r"action.custom\naction", display)
        self.assertIn(r"notes\rTARGET", display)


if __name__ == "__main__":
    unittest.main()
