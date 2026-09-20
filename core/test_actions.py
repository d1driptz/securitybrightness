import unittest
from unittest.mock import patch

from core.actions import describe_action, list_actions
from core.api import check_action
from core.authorization import AuthorizationContext


class ActionCatalogTests(unittest.TestCase):
    @patch("core.security.log_event")
    def test_catalog_preserves_review_requirements_for_every_known_action(self, log):
        class Provider:
            def __init__(self):
                self.calls = []
            def request_approval(self, event, *, strong=False):
                self.calls.append(strong)
                return False
        for item in list_actions():
            with self.subTest(action=item.action):
                provider = Provider()
                result = check_action(item.action, "ordinary-resource", approval_provider=provider,
                                      authorization_context=AuthorizationContext.authenticated_application("app", ["*"]))
                self.assertEqual(result["human_control"], item.baseline_control)
                self.assertEqual(result["required_scope"], item.required_scope)
                self.assertEqual(result["action_category"], item.category)
                self.assertEqual(result["decision"], "allow" if item.baseline_control == "automatic" else "deny")
                expected_calls = [] if item.baseline_control in {"automatic", "blocked"} else [item.baseline_control == "strong_confirm"]
                self.assertEqual(provider.calls, expected_calls)

    @patch("core.security.log_event")
    def test_target_and_impact_can_raise_but_not_lower_review_level(self, log):
        class Provider:
            def request_approval(self, event, *, strong=False):
                return False
        for action, target, details, level, risk in (
            ("read", ".env", {}, "approval", "elevated"),
            ("read", "x", {"impact": "high"}, "strong_confirm", "high"),
            ("send_message", "x", {"impact": "low"}, "strong_confirm", "high"),
            ("disable_security", "x", {"impact": "low"}, "blocked", "prohibited"),
        ):
            result = check_action(action, target, details=details, approval_provider=Provider())
            self.assertEqual((result["human_control"], result["risk_level"]), (level, risk))
            self.assertTrue(result["review_reason"])

    def test_unknown_action_has_its_own_scope_and_requires_review(self):
        item = describe_action(" CUSTOM_TOOL ")
        self.assertEqual((item.category, item.required_scope, item.baseline_control),
                         ("unknown", "action.custom_tool", "approval"))
        self.assertEqual(describe_action(" OPEN ").required_scope, "files.read")
