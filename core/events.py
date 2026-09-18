from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass
class SecurityEvent:
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
        return cls(
            event_type=event_type,
            source=source,
            action=action,
            target=target,
            details=details or {},
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
