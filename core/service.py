import hmac
import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from .api import check_action
from .authorization import AuthorizationContext
from .registry import ApplicationRegistry
from .json_input import loads as strict_json_loads
from .logger import AuditLogError
from .permissions import ApprovalProviderError
from .validation import application_id as validate_application_id

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 64 * 1024
TOKEN_ENV = "SECURITYBRIGHTNESS_TOKEN"
REQUEST_TIMEOUT_SECONDS = 5.0


class SecurityBrightnessHandler(BaseHTTPRequestHandler):
    server_version = "SecurityBrightness/0.2"

    def setup(self):
        super().setup()
        self._read_lock = threading.Lock()
        self._reading_done = False
        self._read_expired = False
        self._body_consumed = False
        timeout = self.server.request_read_timeout
        self.connection.settimeout(timeout)
        self._read_deadline = time.monotonic() + timeout
        self._read_timer = threading.Timer(timeout, self._expire_read)
        self._read_timer.daemon = True
        self._read_timer.start()

    def _expire_read(self):
        with self._read_lock:
            if not self._reading_done:
                self._read_expired = True
                try:
                    self.connection.shutdown(socket.SHUT_RD)
                except OSError:
                    pass

    def _stop_reading(self):
        with self._read_lock:
            self._reading_done = True
            self._read_timer.cancel()

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, TimeoutError):
            # Client disconnects and deadline-triggered shutdowns are not server faults.
            self.close_connection = True

    def finish(self):
        self._stop_reading()
        # Send a FIN before closing a rejected request with unread body bytes.
        # A short, size-bounded drain avoids Windows resets without trusting length.
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            if not self._body_consumed and not self._read_expired:
                deadline = time.monotonic() + 0.1
                remaining = MAX_BODY_BYTES
                while remaining and time.monotonic() < deadline:
                    self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                    chunk = self.rfile.read1(min(8192, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
        except OSError:
            pass
        finally:
            super().finish()

    def parse_request(self):
        if not super().parse_request():
            return False
        if self._read_expired or time.monotonic() >= self._read_deadline:
            self._send_json(408, {"error": "request_timeout"})
            return False
        if self.headers.defects:
            self._send_json(400, {"error": "malformed_headers"})
            return False
        for name in ("Authorization", "X-SecurityBrightness-App", "Content-Length",
                     "Content-Type", "Host", "Content-Encoding", "Expect"):
            if len(self.headers.get_all(name, [])) > 1:
                self._send_json(400, {"error": "duplicate_header"})
                return False
        if any("\r" in value or "\n" in value for value in self.headers.values()):
            self._send_json(400, {"error": "folded_header_not_supported"})
            return False
        if "Transfer-Encoding" in self.headers or "Content-Encoding" in self.headers:
            self._send_json(400, {"error": "request_encoding_not_supported"})
            return False
        if "Expect" in self.headers:
            self._send_json(417, {"error": "expectation_not_supported"})
            return False
        return True

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _bearer_token(self):
        supplied = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not supplied.startswith(prefix):
            return ""
        return supplied[len(prefix):]

    def _application(self):
        application_id = self.headers.get("X-SecurityBrightness-App", "").strip()
        credential = self._bearer_token()
        registry = getattr(self.server, "application_registry", None)
        if application_id and registry is not None:
            return registry.authenticate(application_id, credential)
        return None

    def _authorized(self):
        expected = getattr(self.server, "securitybrightness_token", "")
        supplied = self._bearer_token()
        if not isinstance(expected, str) or not expected or not supplied:
            return False
        try:
            return hmac.compare_digest(supplied.encode("ascii"), expected.encode("ascii"))
        except UnicodeEncodeError:
            return False

    def do_GET(self):
        self._stop_reading()
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "SecurityBrightness"})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path in {"/register", "/rotate", "/revoke", "/permissions"}:
            if "X-SecurityBrightness-App" in self.headers or not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return
            if self.path == "/register":
                self._handle_register()
            else:
                self._handle_admin_application_action(self.path)
            return

        if self.path != "/check":
            self._send_json(404, {"error": "not_found"})
            return

        application = self._application()
        if "X-SecurityBrightness-App" in self.headers and application is None:
            self._send_json(401, {"error": "invalid_application_credentials"})
            return
        if application is None and not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return

        payload = self._read_json_payload()
        if payload is None:
            return

        allowed = {"action", "target", "source", "event_type", "details"}
        unknown = set(payload) - allowed
        if unknown:
            self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
            return

        if "action" not in payload or "target" not in payload:
            self._send_json(400, {"error": "action_and_target_required"})
            return

        raw_details = payload.get("details")
        if raw_details is not None and not isinstance(raw_details, dict):
            self._send_json(400, {"error": "details_must_be_object"})
            return
        details = dict(raw_details or {})
        reserved = {"application_id", "authenticated", "trust", "granted_scopes"}
        if reserved.intersection(details):
            self._send_json(400, {"error": "reserved_identity_fields"})
            return

        authorization_context = None
        if application is not None:
            authorization_context = AuthorizationContext.authenticated_application(
                application.application_id,
                scopes=application.scopes,
                trusted=application.trusted,
            )

        try:
            result = check_action(
                action=payload["action"],
                target=payload["target"],
                source=application.application_id if application is not None else payload.get("source", "local_client"),
                event_type=payload.get("event_type", "application_action"),
                details=details,
                authorization_context=authorization_context,
                approval_provider=self.server.approval_provider,
            )
        except AuditLogError:
            self._send_json(503, {"error": "audit_unavailable"})
            return
        except ApprovalProviderError:
            self._send_json(503, {"error": "approval_unavailable"})
            return
        except (TypeError, ValueError) as exc:
            self._send_json(400, {"error": "invalid_request", "message": str(exc)})
            return

        self._send_json(200, result)

    def _handle_register(self):
        payload = self._read_json_payload()
        if payload is None:
            return
        unknown = set(payload) - {"application_id", "scopes", "trusted"}
        if unknown:
            self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
            return
        try:
            credential = self.server.application_registry.register(
                payload.get("application_id", ""),
                scopes=payload.get("scopes"),
                trusted=payload.get("trusted", False),
            )
        except (TypeError, ValueError) as exc:
            self._send_json(400, {"error": "invalid_registration", "message": str(exc)})
            return
        self._send_json(201, {
            "application_id": payload["application_id"].strip(),
            "credential": credential,
        })

    def _read_json_payload(self):
        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"error": "content_type_must_be_application_json"})
            return None
        if self.headers.get_content_charset() not in (None, "utf-8"):
            self._send_json(415, {"error": "charset_must_be_utf8"})
            return None
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length or not raw_length.isascii() or not raw_length.isdecimal():
            self._send_json(400, {"error": "invalid_content_length"})
            return None
        # Avoid converting attacker-controlled, unbounded decimal integers.
        if len(raw_length) > 10:
            self._send_json(413, {"error": "invalid_request_size"})
            return None
        length = int(raw_length)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "invalid_request_size"})
            return None
        try:
            raw_body = self.rfile.read(length)
        except (TimeoutError, OSError):
            self._send_json(408, {"error": "request_timeout"})
            return None
        if self._read_expired or time.monotonic() >= self._read_deadline:
            self._send_json(408, {"error": "request_timeout"})
            return None
        if len(raw_body) != length:
            self._send_json(400, {"error": "incomplete_body"})
            return None
        self._body_consumed = True
        self._stop_reading()
        try:
            payload = strict_json_loads(raw_body.decode("utf-8"))
        except (UnicodeError, ValueError):
            self._send_json(400, {"error": "invalid_json"})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "request_must_be_object"})
            return None
        return payload

    def _handle_admin_application_action(self, path):
        payload = self._read_json_payload()
        if payload is None:
            return
        registry = self.server.application_registry
        application_id = payload.get("application_id", "")
        if not application_id:
            self._send_json(400, {"error": "application_id_required"})
            return
        try:
            application_id = validate_application_id(application_id)
            if path == "/rotate":
                unknown = set(payload) - {"application_id"}
                if unknown:
                    self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
                    return
                credential = registry.rotate_credential(application_id)
                self._send_json(200, {"application_id": application_id, "credential": credential})
                return
            if path == "/revoke":
                unknown = set(payload) - {"application_id"}
                if unknown:
                    self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
                    return
                if not registry.revoke(application_id):
                    self._send_json(404, {"error": "application_not_found"})
                    return
                self._send_json(200, {"application_id": application_id, "revoked": True})
                return
            unknown = set(payload) - {"application_id", "scopes", "trusted"}
            if unknown:
                self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
                return
            application = registry.update_permissions(
                application_id,
                **{key: payload[key] for key in ("scopes", "trusted") if key in payload},
            )
            self._send_json(200, {
                "application_id": application.application_id,
                "scopes": sorted(application.scopes),
                "trusted": application.trusted,
            })
        except KeyError:
            self._send_json(404, {"error": "application_not_found"})
        except (TypeError, ValueError) as exc:
            self._send_json(400, {"error": "invalid_application_update", "message": str(exc)})

    def log_message(self, format, *args):
        return


def create_server(host=HOST, port=PORT, token=None, registry=None, *, approval_provider=None):
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("SecurityBrightness service must bind to a loopback address")
    if token is None:
        token = os.environ.get(TOKEN_ENV, secrets.token_urlsafe(32))
    if not isinstance(token, str) or not token or any(not 33 <= ord(c) <= 126 for c in token):
        raise ValueError("service token must be nonempty printable ASCII without spaces")
    server = HTTPServer((host, port), SecurityBrightnessHandler)
    server.securitybrightness_token = token
    server.approval_provider = approval_provider
    server.request_read_timeout = REQUEST_TIMEOUT_SECONDS
    server.application_registry = registry or ApplicationRegistry()
    return server


def run(host=HOST, port=PORT):
    server = create_server(host, port)
    print(f"SecurityBrightness listening on http://{host}:{port}")
    if not os.environ.get(TOKEN_ENV):
        print(f"Session token: {server.securitybrightness_token}")
    else:
        print(f"Using token from {TOKEN_ENV}.")
    print("Keep this token private. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
