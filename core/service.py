import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .api import check_action

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 64 * 1024


class SecurityBrightnessHandler(BaseHTTPRequestHandler):
    server_version = "SecurityBrightness/0.1"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "SecurityBrightness"})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/check":
            self._send_json(404, {"error": "not_found"})
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
            self._send_json(
                400,
                {"error": "unknown_fields", "fields": sorted(unknown)},
            )
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


def run(host=HOST, port=PORT):
    server = ThreadingHTTPServer((host, port), SecurityBrightnessHandler)
    print(f"SecurityBrightness listening on http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
