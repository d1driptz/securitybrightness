from dataclasses import dataclass

from .approval import TerminalApprovalProvider
from .events import SecurityEvent
from .human_control import HumanControlLevel, classify
from .policy import Decision, evaluate


@dataclass
class PermissionResult:
    decision: Decision
    reason: str
    decision_source: str
    policy_rule: str
    human_control: str = "automatic"


def request_permission(event: SecurityEvent, approval_provider=None) -> PermissionResult:
    policy_result = evaluate(event)
    control = classify(event, policy_result)
    decision = policy_result.decision

    needs_approval = control.level in {
        HumanControlLevel.APPROVAL,
        HumanControlLevel.STRONG_CONFIRM,
    }

    if decision == Decision.DENY:
        reason = policy_result.reason
        decision_source = "policy"
    elif needs_approval:
        provider = approval_provider or TerminalApprovalProvider()
        approved = provider.request_approval(event)
        decision_source = "user"
        decision = Decision.ALLOW if approved else Decision.DENY
        outcome = "approved" if approved else "denied"
        reason = f"User {outcome} the action after human-control review."
    else:
        reason = policy_result.reason
        decision_source = "policy"

    return PermissionResult(
        decision=decision,
        reason=reason,
        decision_source=decision_source,
        policy_rule=policy_result.rule,
        human_control=control.level.value,
    )
