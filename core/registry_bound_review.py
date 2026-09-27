"""Inactive review evidence tied to existing authenticated registry liveness.

Never evaluates policy, records human approval, activates grants or returns allow.
Not integrated with /check. File references remain unverified requester text.
"""
from dataclasses import dataclass
from threading import RLock

from .file_read_review import FileReadReviewLedger, FileReadReviewTicket, ReviewFreshness
from .registry import ApplicationRegistry, AuthorityInactiveError
from .structured_proposal import StructuredActionProposal
from .validation import application_id as validate_application_id


@dataclass(frozen=True)
class RegistryBoundReviewTicket:
    review: FileReadReviewTicket
    grant_id: str

    def __bool__(self):
        raise TypeError("Registry-bound review evidence is not permission")


class RegistryBoundFileReadReviews:
    """Trusted-process freshness coordinator with one pending ticket per draft.

    Lock order is coordinator, registry lease, then draft ledger. Existing live
    registry behavior is unchanged. No credential is retained by this coordinator.
    """
    def __init__(self, registry, ledger):
        if not isinstance(registry, ApplicationRegistry):
            raise TypeError("registry must be an ApplicationRegistry")
        if not isinstance(ledger, FileReadReviewLedger):
            raise TypeError("ledger must be a FileReadReviewLedger")
        self._registry = registry
        self._ledger = ledger
        self._pending = {}
        self._lock = RLock()

    def begin_review(self, application_id, credential, proposal, draft_id, expected_revision):
        """Authenticate existing application state and capture review evidence only."""
        application_id = validate_application_id(application_id)
        with self._lock:
            app = self._registry.authenticate(application_id, credential)
            if app is None:
                raise AuthorityInactiveError("application authentication unavailable")
            lease = self._registry.authorization_lease(app)
            with lease():
                review = self._ledger.begin_review(app.application_id, proposal, draft_id, expected_revision)
                ticket = RegistryBoundReviewTicket(review, app.grant_id)
                self._pending[draft_id] = (ticket, lease)
                return ticket

    def check_review(self, ticket, application_id, proposal):
        """Point-in-time freshness, never permission or a downstream execution lease."""
        if not isinstance(ticket, RegistryBoundReviewTicket):
            raise TypeError("ticket must be a RegistryBoundReviewTicket")
        application_id = validate_application_id(application_id)
        if not isinstance(proposal, StructuredActionProposal):
            raise TypeError("proposal must be a StructuredActionProposal")
        if not isinstance(ticket.review, FileReadReviewTicket):
            raise TypeError("ticket must contain a FileReadReviewTicket")
        with self._lock:
            pending = self._pending.get(ticket.review.draft_id)
            if pending is None or pending[0] is not ticket:
                return ReviewFreshness(False, "unknown_or_stale_registry_review")
            try:
                with pending[1]():
                    result = self._ledger.check_review(ticket.review, application_id, proposal)
            except AuthorityInactiveError:
                self._pending.pop(ticket.review.draft_id, None)
                self._ledger.discard_review(ticket.review)
                return ReviewFreshness(False, "registry_authority_changed")
            except Exception:
                # Infrastructure/corrupt-state failures cannot leave evidence
                # reusable after recovery. Do not expose internal exception text.
                self._pending.pop(ticket.review.draft_id, None)
                self._ledger.discard_review(ticket.review)
                return ReviewFreshness(False, "review_state_unavailable")
            # Do not retire valid evidence solely because a caller supplied a
            # mismatched proposal/owner. The original snapshot remains checkable.
            if not result.current and result.reason in {
                "session_mismatch", "unknown_or_stale_review", "draft_changed"
            }:
                self._pending.pop(ticket.review.draft_id, None)
            return result

    def discard_review(self, ticket):
        if not isinstance(ticket, RegistryBoundReviewTicket):
            raise TypeError("ticket must be a RegistryBoundReviewTicket")
        if not isinstance(ticket.review, FileReadReviewTicket):
            raise TypeError("ticket must contain a FileReadReviewTicket")
        with self._lock:
            pending = self._pending.get(ticket.review.draft_id)
            if pending is not None and pending[0] is ticket:
                self._pending.pop(ticket.review.draft_id)
                self._ledger.discard_review(ticket.review)
