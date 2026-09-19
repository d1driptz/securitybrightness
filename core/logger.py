import json
from pathlib import Path

LOG_FILE = Path("security_events.json")


def log_event(event, result):
    record = {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source": event.source,
        "action": event.action,
        "target": event.target,
        "details": event.details,
        "decision": result.decision.value,
        "decision_source": result.decision_source,
        "policy_rule": result.policy_rule,
        "reason": result.reason,
    }

    existing_events = []

    if LOG_FILE.exists():
        try:
            existing_events = json.loads(LOG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            existing_events = []

    existing_events.append(record)

    LOG_FILE.write_text(json.dumps(existing_events, indent=2))
