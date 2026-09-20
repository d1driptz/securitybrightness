import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from core.approval import TerminalApprovalProvider
from core.events import SecurityEvent
from core.permissions import ApprovalProviderError, request_permission
from core.policy import Decision


class Provider:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def request_approval(self, event, *, strong=False):
        self.calls.append(strong)
        return self.result


class ApprovalSecurityTests(unittest.TestCase):
    def event(self, action="write"):
        return SecurityEvent.create("test", "test", action, "x")

    def test_only_actual_boolean_approval_is_accepted(self):
        for value in ("false", "yes", 1, 0, None, [], [True], {}, object()):
            provider = Provider(value)
            with self.subTest(value=value), self.assertRaises(ApprovalProviderError):
                request_permission(self.event(), provider)
            self.assertEqual(len(provider.calls), 1)

    def test_strong_provider_receives_strong_flag(self):
        provider = Provider(True)
        result = request_permission(self.event("send_message"), provider)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(provider.calls, [True])

    def test_legacy_provider_cannot_silently_downgrade_strong_confirmation(self):
        class Legacy:
            calls = 0
            def request_approval(self, event):
                self.calls += 1
                return True
        provider = Legacy()
        with self.assertRaises(ApprovalProviderError):
            request_permission(self.event("send_message"), provider)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(request_permission(self.event(), provider).decision, Decision.ALLOW)

    def test_invalid_signature_is_not_called(self):
        class Invalid:
            def request_approval(self, event, another_required_argument):
                raise AssertionError("must not run")
        with self.assertRaises(ApprovalProviderError):
            request_permission(self.event(), Invalid())

    def test_missing_approval_method_is_a_contract_error(self):
        with self.assertRaises(ApprovalProviderError):
            request_permission(self.event(), object())

    def test_falsey_provider_is_not_replaced_with_terminal(self):
        class Falsey(Provider):
            def __bool__(self):
                return False
        provider = Falsey(False)
        with patch("core.permissions.TerminalApprovalProvider") as terminal:
            self.assertEqual(request_permission(self.event(), provider).decision, Decision.DENY)
        terminal.assert_not_called()
        self.assertEqual(provider.calls, [False])

    def test_eof_denies_instead_of_allowing_or_retrying(self):
        with patch("builtins.input", side_effect=EOFError) as prompt:
            result = request_permission(self.event())
        self.assertEqual(result.decision, Decision.DENY)
        prompt.assert_called_once()

    def test_terminal_escapes_untrusted_display_fields(self):
        event = SecurityEvent.create("test", "app\x1b[2J", "send_message", "recipient\nAPPROVED",
                                     {"purpose": "look\rhere\u202e"})
        output = io.StringIO()
        with patch("builtins.input", return_value="no"), redirect_stdout(output):
            self.assertFalse(TerminalApprovalProvider().request_approval(event, strong=True))
        display = output.getvalue()
        self.assertNotIn("\x1b", display)
        self.assertNotIn("\r", display)
        self.assertNotIn("\u202e", display)
        self.assertIn(r"\u001b[2J", display)
        self.assertIn(r"recipient\nAPPROVED", display)
        with patch("builtins.input", return_value="no") as prompt:
            TerminalApprovalProvider().request_approval(event)
        self.assertNotIn("\n", prompt.call_args.args[0])
