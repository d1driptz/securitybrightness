"""Trusted operator review boundary. No application-facing approval endpoint.

The in-process channel assumes a trusted local OS session. A future isolated
transport may replace this provider without changing /check or the policy core.
"""
import math
import threading
import time
from dataclasses import dataclass
from uuid import uuid4

from .actions import describe_action
from .human_control import classify
from .identity import identify
from .permissions import ApprovalProviderError
from .policy import evaluate


@dataclass(frozen=True)
class ReviewRequest:
    review_id: str
    request_id: str
    application_id: str
    authenticated: bool
    action: str
    target: str
    category: str
    required_scope: str
    policy_reason: str
    review_reason: str
    explanation: str
    strong: bool


class _Pending:
    def __init__(self, request, deadline):
        self.request = request
        self.deadline = deadline
        self.answer = None


class OperatorReviewChannel:
    """Ephemeral bounded handoff from the service worker to the trusted UI.

    Only the trusted operator adapter receives this object. Its respond method
    is not an HTTP route, a permission grant or an execution hook.
    """
    def __init__(self, *, timeout=120, capacity=16):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("review timeout must be positive and finite")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("review capacity must be a positive integer")
        self._timeout = timeout
        self._capacity = capacity
        self._condition = threading.Condition()
        self._pending = {}
        self._closed = False

    def request_approval(self, event, *, strong=False):
        if type(strong) is not bool:
            raise TypeError("strong must be a boolean")
        policy = evaluate(event)
        control = classify(event, policy)
        identity = identify(event)
        descriptor = describe_action(event.action)
        review = ReviewRequest(
            str(uuid4()), event.request_id, identity.application_id, identity.authenticated,
            event.action, event.target, descriptor.category, descriptor.required_scope,
            policy.reason, control.reason,
            str(event.details.get("purpose") or event.details.get("reason") or ""),
            strong or control.level.value == "strong_confirm",
        )
        with self._condition:
            if self._closed or len(self._pending) >= self._capacity:
                raise ApprovalProviderError("operator review unavailable")
            pending = _Pending(review, time.monotonic() + self._timeout)
            self._pending[review.review_id] = pending
            self._condition.notify_all()
            try:
                while pending.answer is None:
                    remaining = pending.deadline - time.monotonic()
                    if self._closed or remaining <= 0:
                        raise ApprovalProviderError("operator review closed or expired")
                    self._condition.wait(remaining)
                return pending.answer
            finally:
                self._pending.pop(review.review_id, None)

    def pending_reviews(self):
        with self._condition:
            now = time.monotonic()
            return tuple(p.request for p in self._pending.values()
                         if p.answer is None and p.deadline > now and not self._closed)

    def respond(self, review_id, approved, *, confirmation=""):
        if not isinstance(review_id, str) or type(approved) is not bool or not isinstance(confirmation, str):
            raise TypeError("invalid operator response")
        with self._condition:
            pending = self._pending.get(review_id)
            if (self._closed or pending is None or pending.answer is not None
                    or time.monotonic() >= pending.deadline):
                return False
            if approved and pending.request.strong and confirmation.strip() != "ALLOW":
                return False
            pending.answer = approved
            self._condition.notify_all()
            return True

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
