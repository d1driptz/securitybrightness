import http.client
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

from core.authorization import AuthorizationContext
from core.registry import ApplicationRegistry
from core.scopes import normalize_scopes
from core.service import create_server


class RegistrySecurityTests(unittest.TestCase):
    def setUp(self):
        self.registry = ApplicationRegistry()
        self.credential = self.registry.register("app", ["files.read"])

    def test_registration_rejects_non_string_ids_without_side_effects(self):
        for value in (None, 123, True, [], {}):
            with self.subTest(value=value), self.assertRaises(TypeError):
                self.registry.register(value)
        self.assertEqual(len(self.registry._applications), 1)

    def test_ids_reject_blank_control_and_oversized_strings(self):
        for value in ("", "  ", "app\x00name", "app\x7fname", "x" * 2049):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.registry.register(value)
        self.assertEqual(len(self.registry._applications), 1)

    def test_invalid_trust_never_grants_trust(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    self.registry.register("new", trusted=value)
                with self.assertRaises(TypeError):
                    self.registry.set_trusted("app", value)
                self.assertIsNone(self.registry.get("new"))
                self.assertFalse(self.registry.get("app").trusted)

    def test_scopes_reject_mappings_and_non_string_elements(self):
        for value in ({"*": False}, [None], [1], [True], [[]], ["files.read", {}]):
            with self.subTest(value=value), self.assertRaises(TypeError):
                normalize_scopes(value)

    def test_scopes_reject_empty_and_control_values(self):
        for value in ([""], ["  "], ["files.\x00read"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_scopes(value)

    def test_scope_normalization_preserves_supported_inputs(self):
        for value in ([" FILES.READ ", "*"], (" FILES.READ ", "*"), {" FILES.READ ", "*"}):
            self.assertEqual(normalize_scopes(value), {"files.read", "*"})
        self.assertEqual(normalize_scopes(None), set())

    def test_failed_combined_update_preserves_entire_record(self):
        before = self.registry.get("app")
        for changes in ({"scopes": ["*"], "trusted": "false"},
                        {"scopes": [False], "trusted": True}):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                self.registry.update_permissions("app", **changes)
            self.assertIs(self.registry.get("app"), before)
            self.assertIs(self.registry.authenticate("app", self.credential), before)

    def test_combined_update_and_explicit_scope_clear(self):
        result = self.registry.update_permissions("app", scopes=["*"], trusted=True)
        self.assertEqual(result.scopes, {"*"})
        self.assertTrue(result.trusted)
        self.registry.update_permissions("app", scopes=None)
        self.assertEqual(self.registry.get("app").scopes, set())
        self.assertTrue(self.registry.get("app").trusted)

    def test_records_are_immutable_snapshots(self):
        old = self.registry.authenticate("app", self.credential)
        with self.assertRaises(FrozenInstanceError):
            old.trusted = True
        with self.assertRaises(AttributeError):
            old.scopes.add("*")
        self.registry.set_trusted("app", True)
        self.assertFalse(old.trusted)
        self.assertTrue(self.registry.get("app").trusted)

    def test_concurrent_duplicate_registration_issues_one_credential(self):
        def register(_):
            try:
                return self.registry.register("new")
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=8) as executor:
            credentials = [item for item in executor.map(register, range(32)) if item]
        self.assertEqual(len(credentials), 1)
        self.assertIsNotNone(self.registry.authenticate("new", credentials[0]))

    def test_rotation_and_revocation_do_not_mutate_old_snapshots(self):
        old = self.registry.get("app")
        credential = self.registry.rotate_credential("app")
        self.assertNotEqual(old.credential_hash, self.registry.get("app").credential_hash)
        self.assertIsNone(self.registry.authenticate("app", self.credential))
        self.assertIsNotNone(self.registry.authenticate("app", credential))
        self.registry.revoke("app")
        self.assertIsNone(self.registry.authenticate("app", credential))

    def test_invalid_authentication_fails_closed(self):
        for app_id, credential in ((None, self.credential), (123, self.credential),
                                   ("app", None), ("app", "\ud800")):
            self.assertIsNone(self.registry.authenticate(app_id, credential))

    def test_context_validates_direct_and_factory_construction(self):
        for factory in (AuthorizationContext, AuthorizationContext.authenticated_application):
            with self.assertRaises(TypeError):
                factory(None)
            with self.assertRaises(TypeError):
                factory("app", trusted="false")
        with self.assertRaises(TypeError):
            AuthorizationContext("app", authenticated=1)
        scopes = {"files.read"}
        context = AuthorizationContext("app", granted_scopes=scopes)
        scopes.add("*")
        self.assertEqual(context.granted_scopes, {"files.read"})

    def test_context_does_not_coerce_caller_details(self):
        context = AuthorizationContext.authenticated_application("app")
        for value in ([], "", False, [("purpose", "test")]):
            with self.subTest(value=value), self.assertRaises(TypeError):
                context.apply(value)


class RegistryHttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.registry = ApplicationRegistry()
        self.credential = self.registry.register("app", ["files.read"])
        self.server = create_server(port=0, token="admin", registry=self.registry)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def post(self, path, payload, token="admin"):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            body = None if payload is None else json.dumps(payload).encode("utf-8")
            connection.request("POST", path, body, {
                "Authorization": "Bearer " + token, "Content-Type": "application/json",
            })
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_invalid_registration_does_not_create_application(self):
        for payload in ({"application_id": 123}, {"application_id": "new", "trusted": "false"},
                        {"application_id": "new", "scopes": {"*": False}}):
            self.assertEqual(self.post("/register", payload)[0], 400)
        self.assertIsNone(self.registry.get("new"))
        self.assertIsNone(self.registry.get("123"))

    def test_failed_permission_update_preserves_authentication_and_permissions(self):
        before = self.registry.get("app")
        status, _ = self.post("/permissions", {"application_id": "app", "scopes": ["*"], "trusted": "false"})
        self.assertEqual(status, 400)
        self.assertIs(self.registry.authenticate("app", self.credential), before)

    def test_lifecycle_rejects_non_string_ids(self):
        self.registry.register("123")
        for path in ("/permissions", "/rotate", "/revoke"):
            self.assertEqual(self.post(path, {"application_id": 123})[0], 400)
        self.assertIsNotNone(self.registry.get("123"))

    def test_application_credential_cannot_use_any_admin_endpoint(self):
        for path in ("/register", "/permissions", "/rotate", "/revoke"):
            status, _ = self.post(path, None, self.credential)
            self.assertEqual(status, 401)
        self.assertIsNotNone(self.registry.authenticate("app", self.credential))
        self.assertEqual(self.registry.get("app").scopes, {"files.read"})


class OperatorSummaryTests(unittest.TestCase):
    def test_summaries_are_immutable_credential_free_snapshots(self):
        from dataclasses import asdict, FrozenInstanceError
        from core.registry import ApplicationRegistry
        registry = ApplicationRegistry()
        credential = registry.register("app", ["files.read"])
        snapshot = registry.list_applications()
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(set(asdict(snapshot[0])), {"application_id", "scopes", "trusted"})
        self.assertNotIn(credential, repr(snapshot))
        self.assertNotIn(registry.get("app").credential_hash, repr(snapshot))
        with self.assertRaises(FrozenInstanceError):
            snapshot[0].trusted = True
        registry.update_permissions("app", scopes=["files.write"], trusted=True)
        self.assertEqual(snapshot[0].scopes, frozenset({"files.read"}))
        fresh = registry.list_applications()[0]
        self.assertTrue(fresh.trusted)
        self.assertEqual(fresh.scopes, frozenset({"files.write"}))
        registry.rotate_credential("app")
        self.assertEqual(registry.list_applications()[0], fresh)
        registry.revoke("app")
        self.assertEqual(registry.list_applications(), ())
