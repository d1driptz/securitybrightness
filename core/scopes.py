from dataclasses import dataclass
from typing import Iterable
from collections.abc import Mapping

from .events import SecurityEvent
from .actions import ACTIONS, describe_action


@dataclass
class ScopeResult:
    required_scope: str
    granted: bool


ACTION_SCOPES = {name: item.required_scope for name, item in ACTIONS.items()}


def normalize_scopes(scopes: Iterable[str] | None) -> set[str]:
    if scopes is None:
        return set()
    if isinstance(scopes, (str, bytes, Mapping)):
        raise TypeError("scopes must be an iterable of strings, not a string or mapping")
    normalized = set()
    for scope in scopes:
        if not isinstance(scope, str):
            raise TypeError("each scope must be a string")
        scope = scope.strip().lower()
        if not scope or any(ord(c) < 32 or ord(c) == 127 for c in scope):
            raise ValueError("scopes must be nonempty strings without control characters")
        normalized.add(scope)
    return normalized


def check_scope(event: SecurityEvent) -> ScopeResult:
    required = describe_action(event.action).required_scope
    context = event.authorization_context
    granted_scopes = (context.granted_scopes if context is not None
                      else normalize_scopes(event.details.get("granted_scopes")))

    return ScopeResult(
        required_scope=required,
        granted=required in granted_scopes or "*" in granted_scopes,
    )
