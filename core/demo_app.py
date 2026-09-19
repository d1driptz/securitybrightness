from core.events import SecurityEvent
from core.security import process_event


def main():
    event = SecurityEvent.create(
        event_type="file_access",
        source="demo_application",
        action="read",
        target="example.txt",
        details={"purpose": "testing SecurityBrightness"},
    )

    result = process_event(event)

    print("SecurityBrightness decision:")
    print("Decision:", result.decision.value)
    print("Source:", result.decision_source)
    print("Policy rule:", result.policy_rule)
    print("Reason:", result.reason)


if __name__ == "__main__":
    main()
