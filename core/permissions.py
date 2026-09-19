from dataclasses import dataclass

from .approval import TerminalApprovalProvider
from .events import SecurityEvent
from .policy import Decision, evaluate


@dataclass
class PermissionResult:
    decision: Decision
    reason: str
    decision_source: str
    policy_rule: str


def request_permission(event: SecurityEvent, approval_provider=None) -> PermissionResult:
    policy_result = evaluate(event)
    decision = policy_result.decision

    if decision in (Decision.ALLOW, Decision.DENY):
        reason = policy_result.reason
        decision_source = "policy"
    else:
        provider = approval_provider or TerminalApprovalProvider()
        approved = provider.request_approval(event)
        decision_source = "user"
        decision = Decision.ALLOW if approved else Decision.DENY
        outcome = "approved" if approved else "denied"
        reason = f"User {outcome} the action after policy review."

    return PermissionResult(
        decision=decision,
        reason=reason,
        decision_source=decision_source,
        policy_rule=policy_result.rule,
    )
