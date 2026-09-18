from dataclasses import dataclass

from .events import SecurityEvent
from .policy import Decision, evaluate


@dataclass
class PermissionResult:
    decision: Decision
    reason: str


def request_permission(event: SecurityEvent) -> PermissionResult:
    """
    Ask SecurityBrightness whether an action should be allowed.
    """

    decision = evaluate(event)

    if decision == Decision.ALLOW:
        reason = "Action is permitted by the current security policy."

    elif decision == Decision.DENY:
        reason = "Action is blocked by the current security policy."

    else:
        reason = "Action requires further approval or review."

    return PermissionResult(
        decision=decision,
        reason=reason,
    )
