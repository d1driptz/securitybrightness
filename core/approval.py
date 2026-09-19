from .events import SecurityEvent


class TerminalApprovalProvider:
    """Request explicit human approval through the terminal."""

    def request_approval(self, event: SecurityEvent) -> bool:
        while True:
            answer = input(
                f"SecurityBrightness requires approval for '{event.action}' "
                f"on '{event.target}'. Allow this action? (yes/no): "
            ).strip().lower()

            if answer in ("yes", "y"):
                return True
            if answer in ("no", "n"):
                return False

            print("Please answer yes or no.")
