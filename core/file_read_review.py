"""Process-local draft/review freshness model; never active authorization.

There is no approve, unlock, activate, allow, persist, or execute operation. A
current review only means its draft and proposal have not changed in this ledger.
All callers are trusted in-process components, not authenticated human operators.
"""
from dataclasses import dataclass
from threading import RLock
from uuid import uuid4

from .file_read_constraint import FileReadConstraint, evaluate_file_read_constraint
from .proposal_identity import proposal_identity
from .structured_proposal import StructuredActionProposal
from .validation import application_id as validate_application_id


@dataclass(frozen=True)
class FileReadDraft:
    draft_id: str
    revision: int
    constraint: FileReadConstraint
    revoked: bool = False

    def __bool__(self):
        raise TypeError("A draft is not permission")


@dataclass(frozen=True)
class FileReadReviewTicket:
    session_id: str
    draft_id: str
    revision: int
    application_id: str
    proposal_id: str

    def __bool__(self):
        raise TypeError("A review ticket is not permission")


@dataclass(frozen=True)
class ReviewFreshness:
    current: bool
    reason: str

    def __bool__(self):
        raise TypeError("Review freshness is not permission")


class FileReadReviewLedger:
    """Bounded session-only draft store, isolated from the live grant registry.

    One outstanding review per draft. Starting another review supersedes the old
    one. Revoked drafts occupy capacity until this ledger is discarded, ensuring
    their IDs cannot be reused during its lifetime.
    """
    def __init__(self, *, capacity=128):
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError("capacity must be an integer between 1 and 4096")
        self._capacity = capacity
        self._session_id = str(uuid4())
        self._drafts = {}
        self._reviews = {}
        self._lock = RLock()

    def create(self, constraint):
        if not isinstance(constraint, FileReadConstraint):
            raise TypeError("constraint must be a FileReadConstraint")
        with self._lock:
            if len(self._drafts) >= self._capacity:
                raise ValueError("draft capacity reached")
            draft_id = str(uuid4())
            if draft_id in self._drafts:
                raise RuntimeError("duplicate draft identity")
            draft = FileReadDraft(draft_id, 1, constraint)
            self._drafts[draft.draft_id] = draft
            return draft

    def _existing(self, draft_id):
        if not isinstance(draft_id, str):
            raise TypeError("draft_id must be a string")
        draft = self._drafts.get(draft_id)
        if draft is None:
            raise ValueError("unknown draft")
        return draft

    def _editable(self, draft_id, expected_revision):
        if type(expected_revision) is not int or expected_revision < 1:
            raise ValueError("expected_revision must be a positive integer")
        draft = self._existing(draft_id)
        if draft.revoked:
            raise ValueError("draft is revoked")
        if draft.revision != expected_revision:
            raise ValueError("stale draft revision")
        return draft

    def replace(self, draft_id, expected_revision, constraint):
        if not isinstance(constraint, FileReadConstraint):
            raise TypeError("constraint must be a FileReadConstraint")
        with self._lock:
            draft = self._editable(draft_id, expected_revision)
            if constraint.application_id != draft.constraint.application_id:
                raise ValueError("replacement cannot change draft ownership")
            updated = FileReadDraft(draft_id, draft.revision + 1, constraint)
            self._drafts[draft_id] = updated
            self._reviews.pop(draft_id, None)
            return updated

    def revoke(self, draft_id, expected_revision):
        with self._lock:
            draft = self._editable(draft_id, expected_revision)
            updated = FileReadDraft(draft_id, draft.revision + 1, draft.constraint, True)
            self._drafts[draft_id] = updated
            self._reviews.pop(draft_id, None)
            return updated

    def begin_review(self, application_id, proposal, draft_id, expected_revision):
        """Capture exact current intent for review, without accepting a decision."""
        application_id = validate_application_id(application_id)
        with self._lock:
            draft = self._editable(draft_id, expected_revision)
            result = evaluate_file_read_constraint(application_id, proposal, draft.constraint)
            if not result.applicable:
                raise ValueError("proposal does not fit the draft constraint")
            ticket = FileReadReviewTicket(self._session_id, draft_id, draft.revision,
                                         application_id, proposal_identity(proposal))
            self._reviews[draft_id] = ticket
            return ticket

    def check_review(self, ticket, application_id, proposal):
        """Return freshness evidence only; callers must never use it as allow."""
        if not isinstance(ticket, FileReadReviewTicket):
            raise TypeError("ticket must be a FileReadReviewTicket")
        application_id = validate_application_id(application_id)
        if not isinstance(proposal, StructuredActionProposal):
            raise TypeError("proposal must be a StructuredActionProposal")
        with self._lock:
            if ticket.session_id != self._session_id:
                return ReviewFreshness(False, "session_mismatch")
            # Value equality alone cannot establish this ledger issued a ticket.
            if self._reviews.get(ticket.draft_id) is not ticket:
                return ReviewFreshness(False, "unknown_or_stale_review")
            draft = self._existing(ticket.draft_id)
            if draft.revoked or draft.revision != ticket.revision:
                return ReviewFreshness(False, "draft_changed")
            if application_id != ticket.application_id:
                return ReviewFreshness(False, "application_mismatch")
            if proposal_identity(proposal) != ticket.proposal_id:
                return ReviewFreshness(False, "proposal_changed")
            return ReviewFreshness(True, "current_review_snapshot")

    def discard_review(self, ticket):
        """Retire only the exact issued ticket, without consuming any authority."""
        if not isinstance(ticket, FileReadReviewTicket):
            raise TypeError("ticket must be a FileReadReviewTicket")
        with self._lock:
            if self._reviews.get(ticket.draft_id) is ticket:
                del self._reviews[ticket.draft_id]
