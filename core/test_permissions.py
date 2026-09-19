import unittest

from core.events import SecurityEvent
from core.permissions import request_permission
from core.policy import Decision


class FakeApprovalProvider:
    def __init__(self, approved):
        self.approved = approved
        self.calls = 0

    def request_approval(self, event):
        self.calls += 1
        return self.approved


class PermissionTests(unittest.TestCase):
    def event(self, action="unknown_action", target="system_resource", details=None):
        return SecurityEvent.create(
            event_type="test",
            source="test_suite",
            action=action,
            target=target,
            details=details,
        )

    def test_user_can_approve_ask_decision(self):
        provider = FakeApprovalProvider(True)
        result = request_permission(self.event(), provider)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.decision_source, "user")
        self.assertEqual(provider.calls, 1)

    def test_user_can_deny_ask_decision(self):
        provider = FakeApprovalProvider(False)
        result = request_permission(self.event(), provider)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.decision_source, "user")
        self.assertEqual(provider.calls, 1)

    def test_policy_allow_does_not_prompt(self):
        provider = FakeApprovalProvider(False)
        result = request_permission(self.event("read", "example.txt"), provider)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.decision_source, "policy")
        self.assertEqual(provider.calls, 0)

    def test_policy_deny_does_not_prompt(self):
        provider = FakeApprovalProvider(True)
        result = request_permission(
            self.event("disable_security", "system_resource"),
            provider,
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.decision_source, "policy")
        self.assertEqual(provider.calls, 0)

    def test_identified_app_without_scope_is_denied(self):
        provider = FakeApprovalProvider(True)
        result = request_permission(
            self.event(
                "read",
                "example.txt",
                {"application_id": "app-1", "authenticated": True},
            ),
            provider,
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.decision_source, "scope")
        self.assertEqual(provider.calls, 0)

    def test_identified_app_with_scope_can_follow_policy(self):
        provider = FakeApprovalProvider(False)
        result = request_permission(
            self.event(
                "read",
                "example.txt",
                {
                    "application_id": "app-1",
                    "authenticated": True,
                    "granted_scopes": ["files.read"],
                },
            ),
            provider,
        )
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.decision_source, "policy")
        self.assertEqual(provider.calls, 0)


if __name__ == "__main__":
    unittest.main()
