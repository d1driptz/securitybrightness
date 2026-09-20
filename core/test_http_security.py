from contextlib import closing
import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.permissions import ApprovalProviderError
from core.service import MAX_BODY_BYTES, create_server


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server(port=0, token="admin")
        self.error_patch = patch.object(self.server, "handle_error")
        self.server_error = self.error_patch.start()
        self.addCleanup(self.error_patch.stop)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.address = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server_error.assert_not_called()

    def wire(self, body=b'{"action":"read","target":"x"}', *, path="/check", headers=None,
             shutdown_write=False):
        if headers is None:
            headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                       ("Content-Length", str(len(body)))]
        request = (f"POST {path} HTTP/1.1\r\n" + "".join(
            f"{key}: {value}\r\n" for key, value in headers) + "\r\n").encode("latin-1") + body
        with socket.create_connection(self.address, timeout=2) as connection:
            connection.sendall(request)
            if shutdown_write:
                connection.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(connection)
            response.begin()
            return response.status, json.loads(response.read())

    def health(self):
        with closing(http.client.HTTPConnection(*self.address, timeout=2)) as connection:
            connection.request("GET", "/health")
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)

    @patch("core.service.check_action")
    def test_duplicate_headers_never_reach_authorization(self, check):
        for name, value in (("Authorization", "Bearer admin"), ("Content-Length", "2"),
                            ("Content-Type", "application/json"), ("X-SecurityBrightness-App", "app"),
                            ("Host", "localhost")):
            with self.subTest(header=name):
                headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                           ("Content-Length", "2")]
                if name not in ("Authorization", "Content-Length", "Content-Type"):
                    headers.append((name, value))
                headers.append((name.lower(), value))
                self.assertEqual(self.wire(b"{}", headers=headers)[0], 400)
        check.assert_not_called()

    @patch("core.service.check_action")
    def test_unsupported_encodings_and_folded_headers(self, check):
        for name, value, status in (("Transfer-Encoding", "chunked", 400),
                                    ("Content-Encoding", "gzip", 400),
                                    ("Expect", "100-continue", 417),
                                    ("X-Note", "one\r\n two", 400)):
            with self.subTest(header=name):
                headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                           ("Content-Length", "2"), (name, value)]
                self.assertEqual(self.wire(b"{}", headers=headers)[0], status)
        check.assert_not_called()

    @patch("core.service.check_action")
    def test_malformed_header_lines_are_rejected(self, check):
        headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                   ("Content-Length", "2"), ("Invalid Header", "value")]
        self.assertEqual(self.wire(b"{}", headers=headers)[0], 400)
        check.assert_not_called()

    def test_missing_length_and_unsupported_charset_are_rejected(self):
        headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json")]
        self.assertEqual(self.wire(b"{}", headers=headers)[0], 400)
        headers = [("Authorization", "Bearer admin"), ("Content-Length", "2"),
                   ("Content-Type", "application/json; charset=iso-8859-1")]
        self.assertEqual(self.wire(b"{}", headers=headers)[0], 415)

    def test_content_length_is_strict_and_bounded(self):
        for length in ("+2", "-2", "2,2", "2_0", "two", ""):
            with self.subTest(length=length):
                headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                           ("Content-Length", length)]
                self.assertEqual(self.wire(b"{}", headers=headers)[0], 400)
        for length in ("0", str(MAX_BODY_BYTES + 1), "9" * 100):
            headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                       ("Content-Length", length)]
            self.assertEqual(self.wire(b"", headers=headers)[0], 413)

    @patch("core.service.check_action")
    def test_all_routes_reject_ambiguous_json_before_mutation(self, check):
        credential = self.server.application_registry.register("app", ["files.read"])
        before = self.server.application_registry.get("app")
        bodies = [b'{"application_id":"app","application_id":"other"}',
                  b'{"details":{"a":1,"a":2}}', b'{"x":NaN}', b'{"x":Infinity}',
                  b'{"x":-Infinity}', b'{"x":1e9999}', b'{"x":"\\ud800"}', b'{"x":"\xff"}',
                  b'{"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}']
        for path in ("/check", "/register", "/permissions", "/rotate", "/revoke"):
            for body in bodies:
                with self.subTest(path=path, body=body[:40]):
                    status, response = self.wire(body, path=path)
                    self.assertEqual(status, 400)
                    self.assertEqual(response["error"], "invalid_json")
        check.assert_not_called()
        self.assertIs(self.server.application_registry.authenticate("app", credential), before)
        self.assertIsNone(self.server.application_registry.get("other"))

    def test_truncated_body_is_rejected_and_service_recovers(self):
        headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                   ("Content-Length", "20")]
        status, payload = self.wire(b"{}", headers=headers, shutdown_write=True)
        self.assertEqual((status, payload["error"]), (400, "incomplete_body"))
        self.health()

    def test_idle_connection_cannot_block_service_indefinitely(self):
        self.server.request_read_timeout = 0.2
        started = time.monotonic()
        with socket.create_connection(self.address, timeout=2) as connection:
            self.assertEqual(connection.recv(1), b"")
        self.assertLess(time.monotonic() - started, 2)
        self.health()

    @patch("core.service.check_action")
    def test_trickled_body_cannot_extend_absolute_deadline(self, check):
        self.server.request_read_timeout = 0.25
        with socket.create_connection(self.address, timeout=2) as connection:
            connection.sendall(b"POST /check HTTP/1.1\r\nAuthorization: Bearer admin\r\n"
                               b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
            stop = threading.Event()
            def trickle():
                while not stop.wait(0.03):
                    try:
                        connection.sendall(b" ")
                    except OSError:
                        break
            sender = threading.Thread(target=trickle, daemon=True)
            sender.start()
            started = time.monotonic()
            try:
                response = http.client.HTTPResponse(connection)
                try:
                    response.begin()
                    self.assertEqual(response.status, 408)
                    response.read()
                except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError):
                    pass  # Expired reads may close/reset before an HTTP response.
                self.assertLess(time.monotonic() - started, 2)
            finally:
                stop.set()
                sender.join(timeout=1)
        check.assert_not_called()
        self.health()

    def test_partial_headers_are_bounded(self):
        self.server.request_read_timeout = 0.2
        with socket.create_connection(self.address, timeout=2) as connection:
            connection.sendall(b"POST /check HTTP/1.1\r\nAuthorization: Bearer admin\r\nX-Partial: ")
            response = http.client.HTTPResponse(connection)
            try:
                response.begin()
                self.assertEqual(response.status, 408)
                response.read()
            except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError):
                pass
        self.health()

    def test_empty_app_header_cannot_fall_back_to_admin_token(self):
        headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                   ("Content-Length", "2"), ("X-SecurityBrightness-App", " ")]
        self.assertEqual(self.wire(b"{}", headers=headers)[0], 401)

    def test_app_mode_is_not_admin_mode_even_with_admin_token(self):
        for path in ("/register", "/permissions", "/rotate", "/revoke"):
            headers = [("Authorization", "Bearer admin"), ("Content-Type", "application/json"),
                       ("Content-Length", "2"), ("X-SecurityBrightness-App", "app")]
            self.assertEqual(self.wire(b"{}", path=path, headers=headers)[0], 401)

    def test_non_ascii_credentials_return_unauthorized(self):
        headers = [("Authorization", "Bearer caf\xe9"), ("Content-Type", "application/json"),
                   ("Content-Length", "2")]
        self.assertEqual(self.wire(b"{}", headers=headers)[0], 401)
        self.health()

    def test_invalid_server_tokens_rejected_before_binding(self):
        for token in ("", 123, False, "has space", "caf\xe9", "line\n"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                create_server(port=0, token=token)

    def test_early_rejection_returns_response_with_unread_body(self):
        for _ in range(10):
            headers = [("Authorization", "Bearer wrong"), ("Content-Type", "application/json"),
                       ("Content-Length", "1000")]
            self.assertEqual(self.wire(b"x" * 1000, headers=headers)[0], 401)

    def test_corrupt_audit_returns_no_allow_and_preserves_history(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "audit.json"
            log.write_bytes(b"damaged audit history")
            with patch("core.logger.LOG_FILE", log):
                status, response = self.wire()
            self.assertEqual((status, response), (503, {"error": "audit_unavailable"}))
            self.assertEqual(log.read_bytes(), b"damaged audit history")

    @patch("core.service.check_action", side_effect=ApprovalProviderError("internal secret"))
    def test_provider_errors_do_not_return_allow_or_internal_error_text(self, check):
        self.assertEqual(self.wire(), (503, {"error": "approval_unavailable"}))

    def test_valid_request_has_real_identity_scope_and_audit(self):
        registry = self.server.application_registry
        credential = registry.register("app", ["files.read"])
        body = b'{"action":"read","target":"x","source":"spoofed","details":{"accessToken":"hidden"}}'
        headers = [("Authorization", "Bearer " + credential), ("X-SecurityBrightness-App", "app"),
                   ("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body)))]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "audit.json"
            with patch("core.logger.LOG_FILE", log):
                status, payload = self.wire(body, headers=headers)
            record = json.loads(log.read_text())[0]
        self.assertEqual(status, 200)
        self.assertEqual(payload["decision"], "allow")
        self.assertTrue(payload["authenticated"])
        self.assertTrue(payload["scope_granted"])
        self.assertEqual(record["source"], "app")
        self.assertEqual(record["details"]["accessToken"], "[REDACTED]")

    @patch("core.service.check_action")
    def test_read_deadline_does_not_limit_human_review(self, check):
        self.server.request_read_timeout = 0.1
        def review(**kwargs):
            time.sleep(0.2)
            return {"decision": "deny"}
        check.side_effect = review
        self.assertEqual(self.wire(), (200, {"decision": "deny"}))

    @patch("core.service.check_action")
    def test_all_legacy_identity_fields_remain_rejected_over_http(self, check):
        for field, value in (("application_id", "attacker"), ("authenticated", True),
                             ("trust", "trusted"), ("granted_scopes", ["*"])):
            body = json.dumps({"action": "read", "target": "x", "details": {field: value}}).encode()
            self.assertEqual(self.wire(body)[0], 400)
        check.assert_not_called()
