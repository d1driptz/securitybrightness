from typing import Any, Dict

from .events import SecurityEvent
from .security import process_event


def check_action(
    action: str,
    target: str,
    source: str = "external_application",
    event_type: str = "application_action",
    details: Dict[str, Any] | None = None,
    approval_provider=None,
    authorization_context=None,
    authorization_guard=None,
):
    event = SecurityEvent.create(
        event_type=event_type,
        source=source,
        action=action,
        target=target,
        details=details,
        authorization_context=authorization_context,
    )
    result = process_event(event, approval_provider, authorization_guard)
    return {
        "request_id": event.request_id,
        "timestamp": event.timestamp,
        "decision": result.decision.value,
        "decision_source": result.decision_source,
        "policy_rule": result.policy_rule,
        "human_control": result.human_control,
        "application_id": result.application_id,
        "application_trust": result.application_trust,
        "authenticated": result.authenticated,
        "required_scope": result.required_scope,
        "scope_granted": result.scope_granted,
        "reason": result.reason,
        "action_category": result.action_category,
        "risk_level": result.risk_level,
        "review_reason": result.review_reason,
    }
