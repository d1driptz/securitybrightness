from core.events import SecurityEvent
from core.security import process_event


def run_tests():
    # A normal read should be allowed.
    read_event = SecurityEvent.create(
        event_type="file_access",
        source="demo_app",
        action="read",
        target="example.txt",
    )

    result = process_event(read_event)

    print("READ TEST")
    print("Decision:", result.decision.value)
    print("Source:", result.decision_source)
    print("Reason:", result.reason)
    print()

    # An unknown action should require review.
    unknown_event = SecurityEvent.create(
        event_type="system_action",
        source="demo_app",
        action="unknown_action",
        target="system_resource",
    )

    result = process_event(unknown_event)

    print("UNKNOWN ACTION TEST")
    print("Decision:", result.decision.value)
    print("Source:", result.decision_source)
    print("Reason:", result.reason)
    print()

    # A dangerous action should be denied.
    deny_event = SecurityEvent.create(
        event_type="system_action",
        source="demo_app",
        action="disable_security",
        target="system_resource",
    )

    result = process_event(deny_event)

    print("DENY TEST")
    print("Decision:", result.decision.value)
    print("Source:", result.decision_source)
    print("Reason:", result.reason)
    print()


if __name__ == "__main__":
    run_tests()
