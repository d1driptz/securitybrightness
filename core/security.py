from contextlib import nullcontext

from .events import SecurityEvent
from .permissions import request_permission
from .logger import log_event


def process_event(event: SecurityEvent, approval_provider=None, authorization_guard=None):
    result = request_permission(event, approval_provider)
    with authorization_guard() if authorization_guard is not None else nullcontext():
        log_event(event, result)
    return result
