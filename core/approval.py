from .events import SecurityEvent


class TerminalApprovalProvider:
    """
    Request human approval through the terminal.

    Other approval providers can later use a desktop UI, notification,
    API, or another trusted interface without changing the policy engine.
    """

    def request_approval(self, event: SecurityEvent) -> bool:
        answer = input(
            f"SecurityBrightness requires approval for '{event.action}'. "
            "Allow this action? (yes/no): "
        ).strip().lower()

        return answer in ("yes", "y")
