import http.client
import json
import threading
import unittest
from unittest.mock import patch

from core.registry import ApplicationRegistry
from core.service import create_server

TOKEN = "test-token"


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server("127.0.0.1", 0, token=TOKEN)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, token=TOKEN, content_type="application/json", raw_body=None, application_id=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {}
        encoded = None
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if application_id is not None:
            headers["X-SecurityBrightness-App"] = application_id
        if raw_body is not None:
            encoded = raw_body
            headers["Content-Type"] = content_type
        elif body is not None:
            encoded = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = content_type
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        connection.close()
        return status, payload

    def test_health_endpoint(self):
        status, payload = self.request("GET", "/health", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

    @patch("core.service.check_action")
    def test_check_endpoint_returns_decision(self, check_action):
        check_action.return_value = {
            "request_id": "test-id",
            "timestamp": "2026-01-01T00:00:00Z",
            "decision": "allow",
            "decision_source": "policy",
            "policy_rule": "safe_read",
            "human_control": "automatic",
            "reason": "Allowed.",
        }
        status, payload = self.request("POST", "/check", {"action": "read", "target": "example.txt"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["decision"], "allow")

    def test_missing_token_is_rejected(self):
        status, payload = self.request("POST", "/check", {"action": "read", "target": "x"}, token=None)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")

    def test_wrong_token_is_rejected(self):
        status, payload = self.request("POST", "/check", {"action": "read", "target": "x"}, token="wrong")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")

    def test_wrong_content_type_is_rejected(self):
        status, payload = self.request(
            "POST",
            "/check",
            token=TOKEN,
            content_type="text/plain",
            raw_body=b'{"action":"read","target":"x"}',
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"], "content_type_must_be_application_json")

    def test_missing_fields_are_rejected(self):
        status, payload = self.request("POST", "/check", {"action": "read"})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "action_and_target_required")

    def test_unknown_fields_are_rejected(self):
        status, payload = self.request("POST", "/check", {"action": "read", "target": "x", "unexpected": True})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "unknown_fields")

    def test_unknown_route_is_not_found(self):
        status, payload = self.request("GET", "/missing")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not_found")

    def test_remote_binding_is_rejected(self):
        with self.assertRaises(ValueError):
            create_server("0.0.0.0", 0, token=TOKEN)

    def test_registered_application_identity_is_server_derived(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1", scopes=["files.read"])
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = create_server("127.0.0.1", 0, token=TOKEN, registry=registry)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

        status, payload = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "example.txt"},
            token=credential,
            application_id="app-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["application_id"], "app-1")
        self.assertTrue(payload["authenticated"])
        self.assertTrue(payload["scope_granted"])

    def test_client_cannot_spoof_identity_fields(self):
        status, payload = self.request(
            "POST",
            "/check",
            {
                "action": "read",
                "target": "example.txt",
                "details": {"authenticated": True, "application_id": "attacker"},
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "reserved_identity_fields")

    def test_invalid_registered_app_credential_does_not_fall_back_to_session_token(self):
        status, payload = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "x"},
            token=TOKEN,
            application_id="missing-app",
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "invalid_application_credentials")

    def test_non_object_details_are_rejected_cleanly(self):
        status, payload = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "x", "details": "invalid"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "details_must_be_object")

    def test_registered_application_cannot_spoof_source(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1", scopes=["files.read"])
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = create_server("127.0.0.1", 0, token=TOKEN, registry=registry)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

        with patch("core.service.check_action") as check_action:
            check_action.return_value = {"decision": "allow"}
            status, _ = self.request(
                "POST",
                "/check",
                {"action": "read", "target": "x", "source": "spoofed-source"},
                token=credential,
                application_id="app-1",
            )
            self.assertEqual(status, 200)
            self.assertEqual(check_action.call_args.kwargs["source"], "app-1")

    def test_admin_can_register_application_and_use_issued_credential(self):
        status, registration = self.request(
            "POST",
            "/register",
            {"application_id": "new-app", "scopes": ["files.read"]},
        )
        self.assertEqual(status, 201)
        self.assertEqual(registration["application_id"], "new-app")

        status, result = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "example.txt"},
            token=registration["credential"],
            application_id="new-app",
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["scope_granted"])

    def test_registration_requires_admin_token(self):
        status, payload = self.request(
            "POST",
            "/register",
            {"application_id": "new-app"},
            token=None,
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")

    def test_application_credential_cannot_register_another_application(self):
        registry = ApplicationRegistry()
        credential = registry.register("app-1", scopes=["files.read"])
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = create_server("127.0.0.1", 0, token=TOKEN, registry=registry)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

        status, payload = self.request(
            "POST",
            "/register",
            {"application_id": "app-2"},
            token=credential,
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")


if __name__ == "__main__":
    unittest.main()
