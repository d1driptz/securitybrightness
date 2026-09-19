from dataclasses import dataclass
from typing import Iterable
from collections.abc import Mapping

from .events import SecurityEvent


@dataclass
class ScopeResult:
    required_scope: str
    granted: bool


ACTION_SCOPES = {
    "read": "files.read",
    "open": "files.read",
    "view": "files.read",
    "write": "files.write",
    "modify": "files.write",
    "overwrite": "files.write",
    "delete": "files.delete",
    "remove": "files.delete",
    "execute": "process.execute",
    "run": "process.execute",
    "send_message": "communications.send",
    "post": "communications.publish",
    "publish": "communications.publish",
    "share": "data.share",
    "purchase": "payments.purchase",
    "pay": "payments.pay",
    "transfer_money": "payments.transfer",
    "change_account": "account.change",
    "delete_account": "account.delete",
}


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
    action = (event.action or "").strip().lower()
    required = ACTION_SCOPES.get(action, f"action.{action or 'unknown'}")
    granted_scopes = normalize_scopes(event.details.get("granted_scopes"))

    return ScopeResult(
        required_scope=required,
        granted=required in granted_scopes or "*" in granted_scopes,
    )
