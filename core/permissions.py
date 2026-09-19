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
        answer = input(
            f"SecurityBrightness requires approval for '{event.action}'. "
            "Allow this action? (yes/no): "
        ).strip().lower()

        if answer in ("yes", "y"):
            decision = Decision.ALLOW
            reason = "Action was approved by the user."
        else:
            decision = Decision.DENY
            reason = "Action was denied by the user."

    return PermissionResult(
        decision=decision,
        reason=reason,
    )
