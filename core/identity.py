from dataclasses import dataclass
from enum import Enum

from .events import SecurityEvent


class TrustLevel(Enum):
    UNKNOWN = "unknown"
    RECOGNIZED = "recognized"
    TRUSTED = "trusted"


@dataclass
class IdentityResult:
    application_id: str
    trust: TrustLevel
    authenticated: bool


def identify(event: SecurityEvent) -> IdentityResult:
    context = event.authorization_context
    if context is not None:
        application_id = context.application_id
        claimed_trust = "trusted" if context.trusted else "recognized"
        authenticated = context.authenticated
    else:
        # Compatibility for trusted in-process callers only, never HTTP identity.
        application_id = str(event.details.get("application_id", "")).strip()
        claimed_trust = str(event.details.get("trust", "")).strip().lower()
        authenticated = event.details.get("authenticated") is True

    # A caller cannot become trusted merely by claiming that it is trusted.
    if authenticated and application_id and claimed_trust == "trusted":
        trust = TrustLevel.TRUSTED
    elif authenticated and application_id:
        trust = TrustLevel.RECOGNIZED
    else:
        trust = TrustLevel.UNKNOWN

    return IdentityResult(
        application_id=application_id or event.source,
        trust=trust,
        authenticated=authenticated,
    )


def has_application_identity(event: SecurityEvent) -> bool:
    return event.authorization_context is not None or bool(event.details.get("application_id"))
