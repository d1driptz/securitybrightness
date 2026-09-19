import unittest

from core.events import SecurityEvent
from core.human_control import HumanControlLevel, classify
from core.policy import evaluate


class HumanControlTests(unittest.TestCase):
    def event(self, action="read", target="example.txt", details=None):
        return SecurityEvent.create(
            event_type="test",
            source="test",
            action=action,
            target=target,
            details=details,
        )

    def test_safe_read_is_automatic(self):
        event = self.event()
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.AUTOMATIC)

    def test_notify_flag_creates_notification_level(self):
        event = self.event(details={"notify": True})
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.NOTIFY)

    def test_policy_ask_requires_approval(self):
        event = self.event(action="write")
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.APPROVAL)

    def test_human_impact_action_requires_strong_confirmation(self):
        event = self.event(action="send_message", target="recipient")
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.STRONG_CONFIRM)

    def test_high_impact_detail_requires_strong_confirmation(self):
        event = self.event(action="custom", details={"impact": "high"})
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.STRONG_CONFIRM)

    def test_policy_denial_is_blocked(self):
        event = self.event(action="disable_security")
        result = classify(event, evaluate(event))
        self.assertEqual(result.level, HumanControlLevel.BLOCKED)


if __name__ == "__main__":
    unittest.main()
