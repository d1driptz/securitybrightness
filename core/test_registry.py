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

    def test_rotating_credential_invalidates_old_credential(self):
        registry = ApplicationRegistry()
        old_credential = registry.register("app-1")
        new_credential = registry.rotate_credential("app-1")
        self.assertIsNone(registry.authenticate("app-1", old_credential))
        self.assertIsNotNone(registry.authenticate("app-1", new_credential))

    def test_revoked_application_can_no_longer_authenticate(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1")
        self.assertTrue(registry.revoke("app-1"))
        self.assertIsNone(registry.authenticate("app-1", credential))

    def test_rotating_unknown_application_is_rejected(self):
        registry = ApplicationRegistry()
        with self.assertRaises(KeyError):
            registry.rotate_credential("missing")

    def test_scopes_can_be_changed_after_registration(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1", scopes=["files.read"])
        registry.set_scopes("app-1", ["files.write"])
        application = registry.authenticate("app-1", credential)
        self.assertEqual(application.scopes, {"files.write"})

    def test_trust_can_be_changed_after_registration(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1")
        registry.set_trusted("app-1", True)
        application = registry.authenticate("app-1", credential)
        self.assertTrue(application.trusted)

    def test_registry_rejects_single_string_scope_input(self):
        registry = ApplicationRegistry()
        with self.assertRaises(TypeError):
            registry.register("app-1", scopes="files.read")


if __name__ == "__main__":
    unittest.main()
