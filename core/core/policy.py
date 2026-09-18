from enum import Enum

from .events import SecurityEvent


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def evaluate(event: SecurityEvent) -> Decision:
    """
    Evaluate a security event against the current baseline policy.
    """

    # For now, unknown actions require approval.
    if not event.action:
        return Decision.ASK

    # Safe baseline examples.
    safe_actions = {
        "read",
        "open",
        "view",
    }

    if event.action.lower() in safe_actions:
        return Decision.ALLOW

    # Everything else requires a decision rather than
    # allowing the AI or application to decide by itself.
    return Decision.ASK
