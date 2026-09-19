from dataclasses import dataclass
from enum import Enum

from .events import SecurityEvent
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


HIGH_IMPACT_ACTIONS = {
    "purchase",
    "pay",
    "transfer_money",
    "send_message",
    "post",
    "publish",
    "share",
    "change_account",
    "delete_account",
}


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

    if identity.trust == TrustLevel.UNKNOWN and policy_result.decision == Decision.ALLOW:
        return HumanControlResult(
            HumanControlLevel.APPROVAL,
            "An unknown or unauthenticated application requires human approval.",
        )

    if policy_result.decision == Decision.ASK:
        return HumanControlResult(
            HumanControlLevel.APPROVAL,
            "The action requires explicit human approval.",
        )

    if event.details.get("notify") is True:
        return HumanControlResult(
            HumanControlLevel.NOTIFY,
            "The action is allowed but the human should be informed.",
        )

    return HumanControlResult(
        HumanControlLevel.AUTOMATIC,
        "The action can proceed without additional human interaction.",
    )
