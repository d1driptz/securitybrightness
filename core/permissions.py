from dataclasses import dataclass

from .approval import TerminalApprovalProvider
from .events import SecurityEvent
from .policy import Decision, evaluate


@dataclass
class PermissionResult:
    decision: Decision
    reason: str
    decision_source: str


def request_permission(
    event: SecurityEvent,
    approval_provider=None,
) -> PermissionResult:
    """
    Ask SecurityBrightness whether an action should be allowed.
    """

    decision = evaluate(event)

    if decision == Decision.ALLOW:
        reason = "Action is permitted by the current security policy."
        decision_source = "policy"

    elif decision == Decision.DENY:
        reason = "Action is blocked by the current security policy."
        decision_source = "policy"

    else:
        provider = approval_provider or TerminalApprovalProvider()
        approved = provider.request_approval(event)
        decision_source = "user"

        if approved:
            decision = Decision.ALLOW
            reason = "Action was approved by the user."
        else:
            decision = Decision.DENY
            reason = "Action was denied by the user."

    return PermissionResult(
        decision=decision,
        reason=reason,
        decision_source=decision_source,
    )
