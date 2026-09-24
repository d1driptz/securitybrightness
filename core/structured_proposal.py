"""Structured proposal v2 draft.

Immutable requester intent only. This type is not accepted by the authorization
service and contains no identity, grant, approval, or executor.
"""
import json
from dataclasses import dataclass, field

from .json_input import loads as strict_json_loads
from .proposal import MAX_MESSAGE_BYTES\nfrom .protocol_identifiers import protocol_identifier

_AUTHORITY_KEYS = frozenset({
    "application_id", "authenticated", "trust", "trusted", "granted_scopes",
    "credential", "authorization", "approved", "human_approval", "grant_id",
})
_RESOURCE_FIELDS = frozenset({"type", "reference", "attributes"})


def _normalized_text(value, name):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    value = value.strip()
    if not value:
        raise ValueError(f"{name} must be nonempty")
    return value


def _contains_authority_key(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.strip().lower() in _AUTHORITY_KEYS:
                return True
            if _contains_authority_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_authority_key(item) for item in value)
    return False


def _resource(resource):
    if not isinstance(resource, dict):
        raise TypeError("each resource must be an object")
    if set(resource) - _RESOURCE_FIELDS:
        raise ValueError("unknown resource fields")
    if {"type", "reference"} - set(resource):
        raise ValueError("resource requires type and reference")
    result = {
        "type": protocol_identifier(resource["type"], "resource type"),
        "reference": _normalized_text(resource["reference"], "resource reference"),
    }
    if "attributes" in resource:
        if not isinstance(resource["attributes"], dict):
            raise TypeError("resource attributes must be an object")
        result["attributes"] = resource["attributes"]
    return result


@dataclass(frozen=True, init=False)
class StructuredActionProposal:
    """Canonical immutable snapshot of proposed operation and material effects."""
    version: int
    operation: str
    _body: bytes = field(repr=False)

    def __init__(self, operation, resources, *, effects=None, requester_context=None):
        operation = protocol_identifier(operation, "operation")
        if not isinstance(resources, (list, tuple)) or not resources:
            raise ValueError("resources must be a nonempty list or tuple")
        normalized_resources = [_resource(item) for item in resources]
        effects = {} if effects is None else effects
        requester_context = {} if requester_context is None else requester_context
        if not isinstance(effects, dict):
            raise TypeError("effects must be an object")
        if not isinstance(requester_context, dict):
            raise TypeError("requester_context must be an object")
        payload = {
            "version": 2,
            "operation": operation,
            "resources": normalized_resources,
            "effects": effects,
            "requester_context": requester_context,
        }
        if _contains_authority_key(payload):
            raise ValueError("proposal data must not contain authority fields")
        try:
            body = json.dumps(payload, allow_nan=False, ensure_ascii=True,
                              sort_keys=True, separators=(",", ":")).encode("utf-8")
            strict_json_loads(body.decode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise ValueError("proposal must contain finite UTF-8 JSON values within the nesting limit") from None
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("proposal is too large")
        object.__setattr__(self, "version", 2)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "_body", body)

    def to_payload(self):
        return strict_json_loads(self._body.decode("utf-8"))

    def canonical_bytes(self):
        """Canonical snapshot bytes; not an authorization token."""
        return bytes(self._body)
