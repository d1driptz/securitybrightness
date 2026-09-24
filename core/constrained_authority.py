"""Constrained authority data model.

This module validates immutable authority constraints but is not consulted by
the authorization engine yet. Constructing a grant never grants permission.
"""
import json
from dataclasses import dataclass, field

from .json_input import loads as strict_json_loads
from .proposal import MAX_MESSAGE_BYTES
from .scopes import normalize_scopes
from .validation import application_id as validate_application_id

_ALLOWED_LIFETIMES = frozenset({"session"})
_ALLOWED_USES = frozenset({"unlimited"})


def _text(value, name, *, lower=False):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    value = value.strip()
    if not value:
        raise ValueError(f"{name} must be nonempty")
    return value.lower() if lower else value


@dataclass(frozen=True, init=False)
class ConstrainedAuthority:
    """Immutable constraint snapshot; inert until a later authorization decision."""
    application_id: str
    operation: str
    resource_type: str
    resource_reference: str
    lifetime: str
    uses: str
    _body: bytes = field(repr=False)

    def __init__(self, application_id, operation, resource_type, resource_reference,
                 *, lifetime="session", uses="unlimited"):
        application_id = validate_application_id(application_id)
        operation = _text(operation, "operation", lower=True)
        resource_type = _text(resource_type, "resource_type", lower=True)
        resource_reference = _text(resource_reference, "resource_reference")
        lifetime = _text(lifetime, "lifetime", lower=True)
        uses = _text(uses, "uses", lower=True)
        if lifetime not in _ALLOWED_LIFETIMES:
            raise ValueError("unsupported authority lifetime")
        if uses not in _ALLOWED_USES:
            raise ValueError("unsupported authority use-count mode")
        # Reuse scope validation rules for operation vocabulary without implying a grant.
        normalize_scopes([operation])
        payload = {
            "version": 1,
            "application_id": application_id,
            "operation": operation,
            "resource": {"type": resource_type, "reference": resource_reference},
            "lifetime": lifetime,
            "uses": uses,
        }
        try:
            body = json.dumps(payload, allow_nan=False, ensure_ascii=True,
                              sort_keys=True, separators=(",", ":")).encode("utf-8")
            strict_json_loads(body.decode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise ValueError("authority constraint is not valid finite UTF-8 JSON") from None
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("authority constraint is too large")
        for name, value in (
            ("application_id", application_id), ("operation", operation),
            ("resource_type", resource_type), ("resource_reference", resource_reference),
            ("lifetime", lifetime), ("uses", uses),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_body", body)

    def to_payload(self):
        return strict_json_loads(self._body.decode("utf-8"))
