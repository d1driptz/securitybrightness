import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from core.service import SecurityBrightnessHandler


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            SecurityBrightnessHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {}
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        connection.close()
        return status, payload

    def test_health_endpoint(self):
        status, payload = self.request("GET", "/health")
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
            "reason": "Allowed.",
        }
        status, payload = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "example.txt"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["decision"], "allow")

    def test_missing_fields_are_rejected(self):
        status, payload = self.request("POST", "/check", {"action": "read"})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "action_and_target_required")

    def test_unknown_fields_are_rejected(self):
        status, payload = self.request(
            "POST",
            "/check",
            {"action": "read", "target": "x", "unexpected": True},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "unknown_fields")

    def test_unknown_route_is_not_found(self):
        status, payload = self.request("GET", "/missing")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
