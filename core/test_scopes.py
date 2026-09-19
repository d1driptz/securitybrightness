import unittest

from core.events import SecurityEvent
from core.scopes import check_scope


class ScopeTests(unittest.TestCase):
    def event(self, action, scopes=None):
        details = {}
        if scopes is not None:
            details["granted_scopes"] = scopes
        return SecurityEvent.create(
            event_type="test",
            source="test_app",
            action=action,
            target="target",
            details=details,
        )

    def test_read_requires_files_read(self):
        result = check_scope(self.event("read", ["files.read"]))
        self.assertEqual(result.required_scope, "files.read")
        self.assertTrue(result.granted)

    def test_missing_scope_is_not_granted(self):
        result = check_scope(self.event("write", ["files.read"]))
        self.assertEqual(result.required_scope, "files.write")
        self.assertFalse(result.granted)

    def test_wildcard_scope_grants_action(self):
        result = check_scope(self.event("send_message", ["*"]))
        self.assertTrue(result.granted)

    def test_unknown_action_gets_specific_scope(self):
        result = check_scope(self.event("custom_action", []))
        self.assertEqual(result.required_scope, "action.custom_action")
        self.assertFalse(result.granted)


if __name__ == "__main__":
    unittest.main()
