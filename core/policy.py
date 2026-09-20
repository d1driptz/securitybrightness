from dataclasses import dataclass
from enum import Enum

from .events import SecurityEvent
from .actions import ACTIONS


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    rule: str


SAFE_ACTIONS = {name for name, item in ACTIONS.items() if item.baseline_control == "automatic"}
DENIED_ACTIONS = {name for name, item in ACTIONS.items() if item.baseline_control == "blocked"}
SENSITIVE_MARKERS = {
    "password",
    "passwd",
    "credential",
    "credentials",
    "secret",
    "secrets",
    "token",
    "private_key",
    ".ssh",
    ".env",
}
DESTRUCTIVE_ACTIONS = {name for name, item in ACTIONS.items() if item.baseline_control == "approval"}


def evaluate(event: SecurityEvent) -> PolicyResult:
    """Evaluate an event using conservative, context-aware rules."""

    action = (event.action or "").strip().lower()
    target = (event.target or "").strip().lower()
    sensitivity = str(event.details.get("sensitivity", "")).strip().lower()

    if not action:
        return PolicyResult(
            Decision.ASK,
            "The action is missing, so explicit approval is required.",
            "missing_action",
        )

    if action in DENIED_ACTIONS:
        return PolicyResult(
            Decision.DENY,
            "The requested action is explicitly blocked by security policy.",
            "blocked_action",
        )

    sensitive_target = (
        sensitivity in {"sensitive", "secret", "private", "credential"}
        or any(marker in target for marker in SENSITIVE_MARKERS)
    )

    if sensitive_target:
        return PolicyResult(
            Decision.ASK,
            "The target appears sensitive and requires explicit user approval.",
            "sensitive_target",
        )

    if action in DESTRUCTIVE_ACTIONS:
        return PolicyResult(
            Decision.ASK,
            "The action can change or execute resources and requires approval.",
            "change_or_execute",
        )

    if action in SAFE_ACTIONS:
        return PolicyResult(
            Decision.ALLOW,
            "The action is read-only and the target is not marked sensitive.",
            "safe_read",
        )

    return PolicyResult(
        Decision.ASK,
        "No policy rule safely allows this action automatically.",
        "unknown_action",
    )
