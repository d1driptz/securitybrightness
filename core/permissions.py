from dataclasses import dataclass

from .approval import TerminalApprovalProvider
from .events import SecurityEvent
from .human_control import HumanControlLevel, classify
from .policy import Decision, evaluate
from .scopes import check_scope


@dataclass
class PermissionResult:
    decision: Decision
    reason: str
    decision_source: str
    policy_rule: str
    human_control: str = "automatic"


def _ask_provider(provider, event, strong):
    try:
        return provider.request_approval(event, strong=strong)
    except TypeError:
        # Compatibility with simple/custom providers implementing the original interface.
        return provider.request_approval(event)


def request_permission(event: SecurityEvent, approval_provider=None) -> PermissionResult:
    policy_result = evaluate(event)
    control = classify(event, policy_result)
    decision = policy_result.decision
    scope_result = check_scope(event)
    identity_participates = bool(event.details.get("application_id"))

    needs_approval = control.level in {
        HumanControlLevel.APPROVAL,
        HumanControlLevel.STRONG_CONFIRM,
    }

    if decision == Decision.DENY:
        reason = policy_result.reason
        decision_source = "policy"
    elif identity_participates and not scope_result.granted:
        decision = Decision.DENY
        reason = (
            f"Application lacks required permission scope "
            f"'{scope_result.required_scope}'."
        )
        decision_source = "scope"
    elif needs_approval:
        provider = approval_provider or TerminalApprovalProvider()
        strong = control.level == HumanControlLevel.STRONG_CONFIRM
        approved = _ask_provider(provider, event, strong)
        decision_source = "user"
        decision = Decision.ALLOW if approved else Decision.DENY
        outcome = "approved" if approved else "denied"
        review = "strong human confirmation" if strong else "human-control review"
        reason = f"User {outcome} the action after {review}."
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
