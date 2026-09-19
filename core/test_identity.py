import unittest

from core.events import SecurityEvent
from core.identity import TrustLevel, identify


class IdentityTests(unittest.TestCase):
    def event(self, details=None):
        return SecurityEvent.create(
            event_type="test",
            source="example_app",
            action="read",
            target="example.txt",
            details=details,
        )

    def test_unverified_source_is_unknown(self):
        result = identify(self.event())
        self.assertEqual(result.trust, TrustLevel.UNKNOWN)
        self.assertFalse(result.authenticated)

    def test_authenticated_application_is_recognized(self):
        result = identify(self.event({
            "application_id": "app-123",
            "authenticated": True,
        }))
        self.assertEqual(result.trust, TrustLevel.RECOGNIZED)

    def test_trusted_claim_without_authentication_is_ignored(self):
        result = identify(self.event({
            "application_id": "attacker",
            "trust": "trusted",
        }))
        self.assertEqual(result.trust, TrustLevel.UNKNOWN)

    def test_authenticated_trusted_application_can_be_trusted(self):
        result = identify(self.event({
            "application_id": "app-123",
            "authenticated": True,
            "trust": "trusted",
        }))
        self.assertEqual(result.trust, TrustLevel.TRUSTED)


if __name__ == "__main__":
    unittest.main()
