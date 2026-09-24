import unittest

from core.action_migration import LEGACY_TO_OPERATION, structured_operation_for_legacy_action


class ActionMigrationTests(unittest.TestCase):
    def test_known_actions_map_explicitly_to_existing_scope_vocabulary(self):
        expected = {
            "read": "files.read",
            "write": "files.write",
            "delete": "files.delete",
            "execute": "process.execute",
            "send_message": "communications.send",
            "transfer_money": "payments.transfer",
            "delete_account": "account.delete",
        }
        for action, operation in expected.items():
            with self.subTest(action=action):
                self.assertEqual(structured_operation_for_legacy_action(action), operation)

    def test_blocked_security_actions_remain_explicitly_namespaced(self):
        self.assertEqual(
            structured_operation_for_legacy_action("bypass_permission"),
            "action.bypass_permission",
        )

    def test_unknown_action_does_not_gain_implicit_mapping(self):
        for action in ("unknown", "files.read", "", "new_future_action"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                structured_operation_for_legacy_action(action)

    def test_mapping_is_immutable_and_normalization_is_limited(self):
        self.assertEqual(structured_operation_for_legacy_action(" READ "), "files.read")
        with self.assertRaises(TypeError):
            LEGACY_TO_OPERATION["read"] = "files.write"
        with self.assertRaises(TypeError):
            structured_operation_for_legacy_action(False)
