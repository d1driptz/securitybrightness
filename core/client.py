import json
from urllib import error, request

from .service import HOST, PORT


class SecurityBrightnessClientError(RuntimeError):
    pass


def check(action, target, token, source="local_client", event_type="application_action", details=None, host=HOST, port=PORT, timeout=5, application_id=None):
    if not token:
        raise ValueError("token is required")

    payload = {
        "action": action,
        "target": target,
        "source": source,
        "event_type": event_type,
        "details": details or {},
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if application_id:
        headers["X-SecurityBrightness-App"] = application_id

    req = request.Request(
        f"http://{host}:{port}/check",
        data=body,
        method="POST",
        headers=headers,
    )

    try:
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            message = payload.get("error", "request_failed")
        except (UnicodeDecodeError, json.JSONDecodeError):
            message = "request_failed"
        raise SecurityBrightnessClientError(message) from exc
    except error.URLError as exc:
        raise SecurityBrightnessClientError("service_unavailable") from exc
