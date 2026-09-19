import unittest

from core.events import SecurityEvent
from core.policy import Decision, evaluate


class PolicyTests(unittest.TestCase):
    def event(self, action, target="example.txt", details=None):
        return SecurityEvent.create(
            event_type="test",
            source="test_suite",
            action=action,
            target=target,
            details=details,
        )

    def test_normal_read_is_allowed(self):
        result = evaluate(self.event("read"))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.rule, "safe_read")

    def test_sensitive_read_requires_approval(self):
        result = evaluate(self.event("read", ".env"))
        self.assertEqual(result.decision, Decision.ASK)
        self.assertEqual(result.rule, "sensitive_target")

    def test_explicit_sensitive_detail_requires_approval(self):
        result = evaluate(
            self.event("view", "notes.txt", {"sensitivity": "sensitive"})
        )
        self.assertEqual(result.decision, Decision.ASK)

    def test_change_requires_approval(self):
        result = evaluate(self.event("write"))
        self.assertEqual(result.decision, Decision.ASK)
        self.assertEqual(result.rule, "change_or_execute")

    def test_blocked_action_is_denied(self):
        result = evaluate(self.event("disable_security", "system_resource"))
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.rule, "blocked_action")

    def test_unknown_action_requires_approval(self):
        result = evaluate(self.event("unknown_action", "system_resource"))
        self.assertEqual(result.decision, Decision.ASK)
        self.assertEqual(result.rule, "unknown_action")


if __name__ == "__main__":
    unittest.main()
