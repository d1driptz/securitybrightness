from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4


MAX_TEXT_LENGTH = 2048


@dataclass
class SecurityEvent:
    request_id: str
    event_type: str
    source: str
    action: str
    target: str
    details: Dict[str, Any]
    timestamp: str

    @classmethod
    def create(
        cls,
        event_type: str,
        source: str,
        action: str,
        target: str,
        details: Dict[str, Any] | None = None,
    ):
        values = {
            "event_type": event_type,
            "source": source,
            "action": action,
            "target": target,
        }
        for name, value in values.items():
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if len(value) > MAX_TEXT_LENGTH:
                raise ValueError(f"{name} is too long")

        if details is not None and not isinstance(details, dict):
            raise TypeError("details must be a dictionary")

        return cls(
            request_id=str(uuid4()),
            event_type=event_type.strip(),
            source=source.strip(),
            action=action.strip(),
            target=target.strip(),
            details=dict(details or {}),
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
