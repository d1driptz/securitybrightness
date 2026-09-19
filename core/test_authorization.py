import unittest

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


if __name__ == "__main__":
    unittest.main()
