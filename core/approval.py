import json

from .actions import describe_action
from .events import SecurityEvent


def _display(value):
    # Untrusted labels must not emit terminal escapes, newlines, or bidi controls.
    return json.dumps(str(value), ensure_ascii=True)


class TerminalApprovalProvider:
    """Request explicit human approval through the terminal."""

    def request_approval(self, event: SecurityEvent, strong: bool = False) -> bool:
        descriptor = describe_action(event.action)
        heading = "STRONG CONFIRMATION" if strong else "APPROVAL"
        print(f"\nSecurityBrightness {heading}")
        print(f"Request ID: {_display(event.request_id)}")
        print(f"Source: {_display(event.source)}")
        print(f"Action: {_display(event.action)}")
        print(f"Target: {_display(event.target)}")
        print(f"Action category: {_display(descriptor.category)}")
        print(f"Required scope (not a grant): {_display(descriptor.required_scope)}")
        purpose = event.details.get("purpose") or event.details.get("reason")
        if purpose:
            print(f"Requester explanation (unverified): {_display(purpose)}")
        print("Review this proposal only. Approval does not grant ongoing authority.")
        print("SecurityBrightness records authorization; it does not execute this action.")
        if strong:
            answer = input("Type ALLOW to authorize this high-impact action: ").strip()
            return answer == "ALLOW"

        while True:
            answer = input(
                f"SecurityBrightness requires approval for {_display(event.action)} "
                f"on {_display(event.target)}. Allow this action? (yes/no): "
            ).strip().lower()

            if answer in ("yes", "y"):
                return True
            if answer in ("no", "n"):
                return False

            print("Please answer yes or no.")
