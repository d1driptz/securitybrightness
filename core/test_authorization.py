import unittest
from unittest.mock import patch

from core.api import check_action
from core.events import SecurityEvent
from core.identity import identify
from core.scopes import check_scope
from core.permissions import request_permission

from core.authorization import AuthorizationContext


class AuthorizationContextTests(unittest.TestCase):
    def test_authenticated_context_applies_server_owned_fields(self):
        context = AuthorizationContext.authenticated_application(
            "app-1",
            scopes=["files.read"],
            trusted=True,
        )
        details = context.apply({"purpose": "test"})
        self.assertEqual(details["application_id"], "app-1")
        self.assertTrue(details["authenticated"])
        self.assertEqual(details["trust"], "trusted")
        self.assertEqual(details["granted_scopes"], ["files.read"])
        self.assertEqual(details["purpose"], "test")

    def test_context_rejects_reserved_fields_from_caller_details(self):
        context = AuthorizationContext.authenticated_application("app-1")
        with self.assertRaises(ValueError):
            context.apply({"authenticated": True})

    def test_context_requires_application_id(self):
        with self.assertRaises(ValueError):
            AuthorizationContext.authenticated_application("  ")

    @patch("core.security.log_event")
    def test_context_reaches_core_without_becoming_caller_details(self, log):
        context = AuthorizationContext.authenticated_application("app", ["files.read"])
        result = check_action("read", "notes", details={"purpose": "summarize"}, authorization_context=context)
        event = log.call_args.args[0]
        self.assertIs(event.authorization_context, context)
        self.assertEqual(event.details, {"purpose": "summarize"})
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["scope_granted"])

    def test_details_cannot_override_context_even_after_event_creation(self):
        context = AuthorizationContext.authenticated_application("actual-app", [])
        event = SecurityEvent.create("test", "source", "read", "notes", authorization_context=context)
        event.details.update({"application_id": "spoofed", "authenticated": True,
                              "trust": "trusted", "granted_scopes": ["*"]})
        identity = identify(event)
        self.assertEqual(identity.application_id, "actual-app")
        self.assertEqual(identity.trust.value, "recognized")
        self.assertFalse(check_scope(event).granted)
        self.assertEqual(request_permission(event).decision_source, "scope")

    def test_context_and_legacy_fields_cannot_be_supplied_together(self):
        context = AuthorizationContext.authenticated_application("app", [])
        for key in ("application_id", "authenticated", "trust", "granted_scopes"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                SecurityEvent.create("test", "source", "read", "notes", {key: "spoof"},
                                     authorization_context=context)
        with self.assertRaises(TypeError):
            SecurityEvent.create("test", "source", "read", "notes", authorization_context={})

    def test_unauthenticated_context_does_not_bypass_human_review(self):
        context = AuthorizationContext("app", granted_scopes=frozenset({"files.read"}))
        event = SecurityEvent.create("test", "source", "read", "notes", authorization_context=context)
        with patch("builtins.input", return_value="no") as prompt:
            result = request_permission(event)
        prompt.assert_called_once()
        self.assertEqual(result.decision.value, "deny")
        self.assertFalse(result.authenticated)


if __name__ == "__main__":
    unittest.main()
