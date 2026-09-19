import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

from .api import check_action

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 64 * 1024
TOKEN_ENV = "SECURITYBRIGHTNESS_TOKEN"


class SecurityBrightnessHandler(BaseHTTPRequestHandler):
    server_version = "SecurityBrightness/0.2"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        expected = getattr(self.server, "securitybrightness_token", "")
        supplied = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not supplied.startswith(prefix):
            return False
        return hmac.compare_digest(supplied[len(prefix):], expected)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "SecurityBrightness"})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/check":
            self._send_json(404, {"error": "not_found"})
            return

        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return

        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._send_json(415, {"error": "content_type_must_be_application_json"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid_content_length"})
            return

        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "invalid_request_size"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid_json"})
            return

        if not isinstance(payload, dict):
            self._send_json(400, {"error": "request_must_be_object"})
            return

        allowed = {"action", "target", "source", "event_type", "details"}
        unknown = set(payload) - allowed
        if unknown:
            self._send_json(400, {"error": "unknown_fields", "fields": sorted(unknown)})
            return

        if "action" not in payload or "target" not in payload:
            self._send_json(400, {"error": "action_and_target_required"})
            return

        try:
            result = check_action(
                action=payload["action"],
                target=payload["target"],
                source=payload.get("source", "local_client"),
                event_type=payload.get("event_type", "application_action"),
                details=payload.get("details"),
            )
        except (TypeError, ValueError) as exc:
            self._send_json(400, {"error": "invalid_request", "message": str(exc)})
            return

        self._send_json(200, result)

    def log_message(self, format, *args):
        return


def create_server(host=HOST, port=PORT, token=None):
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("SecurityBrightness service must bind to a loopback address")
    server = HTTPServer((host, port), SecurityBrightnessHandler)
    server.securitybrightness_token = token or os.environ.get(TOKEN_ENV) or secrets.token_urlsafe(32)
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
