from dataclasses import dataclass
import inspect

from .approval import TerminalApprovalProvider
from .actions import CONTROL_RISKS, describe_action
from .events import SecurityEvent
from .human_control import HumanControlLevel, classify
from .identity import identify
from .policy import Decision, evaluate
from .scopes import check_scope


@dataclass
class PermissionResult:
    decision: Decision
    reason: str
    decision_source: str
    policy_rule: str
    human_control: str = "automatic"
    application_id: str = ""
    application_trust: str = "unknown"
    authenticated: bool = False
    required_scope: str = ""
    scope_granted: bool = False
    action_category: str = "unknown"
    risk_level: str = "elevated"
    review_reason: str = ""


class ApprovalProviderError(RuntimeError):
    """The configured human approval channel cannot safely answer this request."""


def _ask_provider(provider, event, strong):
    try:
        method = provider.request_approval
        signature = inspect.signature(method)
        try:
            signature.bind(event, strong=strong)
            kwargs = {"strong": strong}
        except TypeError:
            if strong:
                raise ApprovalProviderError("provider must support strong confirmation")
            signature.bind(event)
            kwargs = {}
    except (AttributeError, TypeError, ValueError) as exc:
        raise ApprovalProviderError("invalid approval provider signature") from exc
    try:
        approved = method(event, **kwargs)
    except EOFError:
        return False
    if type(approved) is not bool:
        raise ApprovalProviderError("approval provider must return a boolean")
    return approved


def request_permission(event: SecurityEvent, approval_provider=None) -> PermissionResult:
    policy_result = evaluate(event)
    control = classify(event, policy_result)
    decision = policy_result.decision
    scope_result = check_scope(event)
    identity = identify(event)
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
        provider = TerminalApprovalProvider() if approval_provider is None else approval_provider
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
        application_id=identity.application_id,
        application_trust=identity.trust.value,
        authenticated=identity.authenticated,
        required_scope=scope_result.required_scope,
        scope_granted=scope_result.granted,
        action_category=describe_action(event.action).category,
        risk_level=CONTROL_RISKS[control.level.value],
        review_reason=control.reason,
    )
