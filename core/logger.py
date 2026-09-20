import json
import os
import re
import tempfile
from pathlib import Path
from threading import RLock

from .json_input import loads as strict_json_loads

LOG_FILE = Path("security_events.json")
_LOG_LOCK = RLock()
SENSITIVE_KEY_MARKERS = (
    "authorization", "credential", "password", "passwd", "privatekey",
    "secret", "token", "apikey", "cookie", "sessionid",
)


class AuditLogError(RuntimeError):
    """Audit persistence failed; no successful authorization may be returned."""


def _sanitize_details(value):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            sanitized[key] = "[REDACTED]" if any(marker in normalized for marker in SENSITIVE_KEY_MARKERS) else _sanitize_details(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_details(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_details(item) for item in value]
    return value


def _record(event, result):
    return {
        "request_id": event.request_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source": event.source,
        "action": event.action,
        "target": event.target,
        "details": _sanitize_details(event.details),
        "decision": result.decision.value,
        "decision_source": result.decision_source,
        "policy_rule": result.policy_rule,
        "human_control": result.human_control,
        "application_id": result.application_id,
        "application_trust": result.application_trust,
        "authenticated": result.authenticated,
        "required_scope": result.required_scope,
        "scope_granted": result.scope_granted,
        "reason": result.reason,
    }


def log_event(event, result):
    temp_path = None
    try:
        record = _record(event, result)
        with _LOG_LOCK:
            try:
                text = LOG_FILE.read_text(encoding="utf-8")
            except FileNotFoundError:
                existing_events = []
            else:
                existing_events = strict_json_loads(text, max_depth=64)
                if not isinstance(existing_events, list) or not all(isinstance(item, dict) for item in existing_events):
                    raise ValueError("audit history must be an array of records")
            existing_events.append(record)
            serialized = json.dumps(existing_events, indent=2, ensure_ascii=True, allow_nan=False)
            strict_json_loads(serialized, max_depth=64)
            descriptor, filename = tempfile.mkstemp(
                prefix=LOG_FILE.name + ".", suffix=".tmp", dir=LOG_FILE.parent,
            )
            temp_path = Path(filename)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            temp_path.replace(LOG_FILE)
            temp_path = None
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise AuditLogError("audit record could not be persisted") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
