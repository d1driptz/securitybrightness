from .events import SecurityEvent
from .permissions import request_permission
from .logger import log_event


def process_event(event: SecurityEvent, approval_provider=None):
    result = request_permission(event, approval_provider)
    log_event(event, result)
    return result
