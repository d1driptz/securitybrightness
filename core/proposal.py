"""Immutable, validated proposals for the registered-application SDK.

A proposal contains caller intent, never identity, permission or an executor.
"""
import json
from dataclasses import dataclass, field

from .events import SecurityEvent
from .json_input import loads as strict_json_loads

MAX_MESSAGE_BYTES = 64 * 1024
_RESERVED = {"application_id", "authenticated", "trust", "granted_scopes"}


@dataclass(frozen=True, init=False)
class ActionProposal:
    """Snapshot the existing action/target/details HTTP contract without sending it.

    JSON bytes detach nested values from the caller. to_payload() returns a fresh
    copy; this is not a capability or a downstream operation-binding guarantee.
    """
    action: str
    target: str
    _body: bytes = field(repr=False)

    def __init__(self, action, target, *, details=None):
        event = SecurityEvent.create("application_action", "proposal", action, target, details)
        if not event.action or not event.target:
            raise ValueError("action and target must be nonempty")
        if _RESERVED.intersection(event.details):
            raise ValueError("identity and scopes are owned by the service")
        payload = {"action": event.action, "target": event.target, "details": event.details}
        try:
            body = json.dumps(payload, allow_nan=False, ensure_ascii=True).encode("utf-8")
            strict_json_loads(body.decode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise ValueError("details must contain finite UTF-8 JSON values within the nesting limit") from None
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("request is too large")
        object.__setattr__(self, "action", event.action)
        object.__setattr__(self, "target", event.target)
        object.__setattr__(self, "_body", body)

    def to_payload(self):
        """Return an independent JSON-compatible view for inspection."""
        return strict_json_loads(self._body.decode("utf-8"))
