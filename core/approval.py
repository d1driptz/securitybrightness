from .events import SecurityEvent


class TerminalApprovalProvider:
    """Request explicit human approval through the terminal."""

    def request_approval(self, event: SecurityEvent, strong: bool = False) -> bool:
        if strong:
            print("\nSecurityBrightness STRONG CONFIRMATION")
            print(f"Source: {event.source}")
            print(f"Action: {event.action}")
            print(f"Target: {event.target}")
            purpose = event.details.get("purpose") or event.details.get("reason")
            if purpose:
                print(f"Purpose: {purpose}")
            answer = input("Type ALLOW to authorize this high-impact action: ").strip()
            return answer == "ALLOW"

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
