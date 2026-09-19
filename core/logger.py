import json
from pathlib import Path

LOG_FILE = Path("security_events.json")


def log_event(event, result):
    record = {
        "request_id": event.request_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source": event.source,
        "action": event.action,
        "target": event.target,
        "details": event.details,
        "decision": result.decision.value,
        "decision_source": result.decision_source,
        "policy_rule": result.policy_rule,
        "human_control": result.human_control,
        "reason": result.reason,
    }

    existing_events = []
    if LOG_FILE.exists():
        try:
            loaded = json.loads(LOG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing_events = loaded
        except (json.JSONDecodeError, OSError):
            existing_events = []

    existing_events.append(record)

    temp_file = LOG_FILE.with_suffix(LOG_FILE.suffix + ".tmp")
    temp_file.write_text(
        json.dumps(existing_events, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temp_file.replace(LOG_FILE)
