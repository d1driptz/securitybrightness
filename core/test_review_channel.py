import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict

from core.events import SecurityEvent
from core.permissions import ApprovalProviderError, request_permission
from core.review_channel import OperatorReviewChannel


class ReviewChannelTests(unittest.TestCase):
    def setUp(self):
        self.channel = OperatorReviewChannel(timeout=2)
        self.pool = ThreadPoolExecutor(max_workers=3)
        self.addCleanup(self.pool.shutdown, wait=True)
        self.addCleanup(self.channel.close)

    def pending(self):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            reviews = self.channel.pending_reviews()
            if reviews:
                return reviews[0]
            time.sleep(0.005)
        self.fail("review did not arrive")

    def event(self, action="write", details=None):
        return SecurityEvent.create("test", "app", action, "notes", details)

    def test_snapshot_has_no_authority_secrets_and_is_bound_to_one_review(self):
        event = self.event(details={"purpose": "edit notes", "credential": "SECRET",
                                   "application_id": "app", "authenticated": True,
                                   "granted_scopes": ["files.write"]})
        future = self.pool.submit(request_permission, event, self.channel)
        review = self.pending()
        event.details["purpose"] = "changed"
        self.assertEqual(review.explanation, "edit notes")
        self.assertTrue(review.authenticated)
        self.assertNotIn("SECRET", repr(asdict(review)))
        self.assertNotIn("granted_scopes", asdict(review))
        with self.assertRaises(FrozenInstanceError):
            review.target = "other"
        self.assertFalse(self.channel.respond("wrong-review", True))
        self.assertTrue(self.channel.respond(review.review_id, False))
        self.assertFalse(self.channel.respond(review.review_id, True))
        self.assertEqual(future.result(timeout=1).decision.value, "deny")
        self.assertFalse(self.channel.respond(review.review_id, True))

    def test_strong_confirmation_is_enforced_at_channel_not_only_ui(self):
        future = self.pool.submit(request_permission, self.event("send_message"), self.channel)
        review = self.pending()
        self.assertTrue(review.strong)
        for text in ("", "yes", "allow"):
            self.assertFalse(self.channel.respond(review.review_id, True, confirmation=text))
        self.assertFalse(future.done())
        with self.assertRaises(TypeError):
            self.channel.respond(review.review_id, "yes", confirmation="ALLOW")
        self.assertTrue(self.channel.respond(review.review_id, True, confirmation="ALLOW"))
        self.assertEqual(future.result(timeout=1).decision.value, "allow")

    def test_scope_and_policy_denials_never_enter_review_channel(self):
        for event in (self.event("disable_security"), self.event(details={"application_id": "app"})):
            self.assertEqual(request_permission(event, self.channel).decision.value, "deny")
        self.assertEqual(self.channel.pending_reviews(), ())

    def test_timeout_close_and_capacity_fail_without_permission(self):
        short = OperatorReviewChannel(timeout=0.02)
        with self.assertRaises(ApprovalProviderError):
            short.request_approval(self.event())
        self.assertEqual(short.pending_reviews(), ())
        closed = OperatorReviewChannel()
        closed.close()
        with self.assertRaises(ApprovalProviderError):
            closed.request_approval(self.event())
        self.channel = OperatorReviewChannel(timeout=2, capacity=1)
        self.addCleanup(self.channel.close)
        future = self.pool.submit(self.channel.request_approval, self.event())
        review = self.pending()
        with self.assertRaises(ApprovalProviderError):
            self.channel.request_approval(self.event())
        self.channel.close()
        self.assertFalse(self.channel.respond(review.review_id, True))
        with self.assertRaises(ApprovalProviderError):
            future.result(timeout=1)

    def test_expired_review_cannot_accept_late_response(self):
        self.channel = OperatorReviewChannel(timeout=0.08)
        self.addCleanup(self.channel.close)
        future = self.pool.submit(self.channel.request_approval, self.event())
        review = self.pending()
        with self.assertRaises(ApprovalProviderError):
            future.result(timeout=1)
        self.assertFalse(self.channel.respond(review.review_id, True))

    def test_channel_configuration_is_strict(self):
        for kwargs in ({"timeout": True}, {"timeout": 0}, {"timeout": float("nan")},
                       {"capacity": False}, {"capacity": 0}):
            with self.assertRaises(ValueError):
                OperatorReviewChannel(**kwargs)
