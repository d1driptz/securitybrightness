import json
from pathlib import Path

LOG_FILE = Path("security_events.json")


def log_event(event, decision, decision_source):
    record = {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source": event.source,
        "action": event.action,
        "target": event.target,
        "details": event.details,
        "decision": decision.value,
        "decision_source": decision_source,
    }

    existing_events = []

    if LOG_FILE.exists():
        try:
            existing_events = json.loads(LOG_FILE.read_text())
        except json.JSONDecodeError:
            existing_events = []

    existing_events.append(record)

    LOG_FILE.write_text(
        json.dumps(existing_events, indent=2)
    )
