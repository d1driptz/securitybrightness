from dataclasses import dataclass
from enum import Enum

from .events import SecurityEvent
from .actions import ACTIONS
from .identity import TrustLevel, identify
from .policy import Decision, PolicyResult


class HumanControlLevel(Enum):
    AUTOMATIC = "automatic"
    NOTIFY = "notify"
    APPROVAL = "approval"
    STRONG_CONFIRM = "strong_confirm"
    BLOCKED = "blocked"


@dataclass
class HumanControlResult:
    level: HumanControlLevel
    reason: str


HIGH_IMPACT_ACTIONS = {name for name, item in ACTIONS.items() if item.baseline_control == "strong_confirm"}


def classify(event: SecurityEvent, policy_result: PolicyResult) -> HumanControlResult:
    action = (event.action or "").strip().lower()
    impact = str(event.details.get("impact", "")).strip().lower()
    identity = identify(event)

    if policy_result.decision == Decision.DENY:
        return HumanControlResult(
            HumanControlLevel.BLOCKED,
            "Security policy blocks the action.",
        )

    if action in HIGH_IMPACT_ACTIONS or impact in {"high", "critical"}:
        return HumanControlResult(
            HumanControlLevel.STRONG_CONFIRM,
            "The action can significantly affect the user or another person.",
        )

    if (
        identity.trust == TrustLevel.UNKNOWN
        and policy_result.decision == Decision.ALLOW
        and event.details.get("application_id")
    ):
        return HumanControlResult(
            HumanControlLevel.APPROVAL,
            "An identified but unauthenticated application requires human approval.",
        )

    if policy_result.decision == Decision.ASK:
        return HumanControlResult(
            HumanControlLevel.APPROVAL,
            "The action requires explicit human approval.",
        )

    if event.details.get("notify") is True:
        return HumanControlResult(
            HumanControlLevel.NOTIFY,
            "Human notification is required in addition to applicable authorization checks.",
        )

    return HumanControlResult(
        HumanControlLevel.AUTOMATIC,
        "No additional human interaction is required by this classification.",
    )
