import http.client
import json
import threading
import unittest
from unittest.mock import patch

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

    def request(self, method, path, body=None, token=TOKEN, content_type="application/json", raw_body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {}
        encoded = None
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
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


if __name__ == "__main__":
    unittest.main()
