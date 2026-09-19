import unittest

from core.registry import ApplicationRegistry


class RegistryTests(unittest.TestCase):
    def test_registered_application_authenticates_with_issued_credential(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1", scopes=["files.read"])
        application = registry.authenticate("app-1", credential)
        self.assertIsNotNone(application)
        self.assertEqual(application.application_id, "app-1")
        self.assertEqual(application.scopes, {"files.read"})

    def test_wrong_credential_is_rejected(self):
        registry = ApplicationRegistry()
        registry.register("app-1")
        self.assertIsNone(registry.authenticate("app-1", "wrong"))

    def test_unknown_application_is_rejected(self):
        registry = ApplicationRegistry()
        self.assertIsNone(registry.authenticate("missing", "credential"))

    def test_duplicate_registration_is_rejected(self):
        registry = ApplicationRegistry()
        registry.register("app-1")
        with self.assertRaises(ValueError):
            registry.register("app-1")

    def test_empty_application_id_is_rejected(self):
        registry = ApplicationRegistry()
        with self.assertRaises(ValueError):
            registry.register("  ")


if __name__ == "__main__":
    unittest.main()
