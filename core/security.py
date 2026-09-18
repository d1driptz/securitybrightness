from .events import SecurityEvent
from .permissions import request_permission
from .logger import log_event


def process_event(event: SecurityEvent):
    """
    Process a security event through the SecurityBrightness pipeline.
    """

    result = request_permission(event)

    log_event(event, result.decision)

    return result
