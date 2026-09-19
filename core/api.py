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
):
    event = SecurityEvent.create(
        event_type=event_type,
        source=source,
        action=action,
        target=target,
        details=details,
    )
    result = process_event(event, approval_provider)
    return {
        "request_id": event.request_id,
        "timestamp": event.timestamp,
        "decision": result.decision.value,
        "decision_source": result.decision_source,
        "policy_rule": result.policy_rule,
        "human_control": result.human_control,
        "reason": result.reason,
    }
