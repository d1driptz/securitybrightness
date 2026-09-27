import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

from core.file_read_constraint import FileReadConstraint
from core.file_read_schema import make_file_read_proposal
from core.file_read_review import FileReadReviewLedger
from core.proposal import ActionProposal


class FileReadReviewTests(unittest.TestCase):
    def setUp(self):
        self.ledger = FileReadReviewLedger()
        self.constraint = FileReadConstraint("app", "notes.txt", max_bytes=16)
        self.draft = self.ledger.create(self.constraint)
        self.proposal = make_file_read_proposal("notes.txt", max_bytes=8)

    def begin(self):
        return self.ledger.begin_review("app", self.proposal, self.draft.draft_id, self.draft.revision)

    def current(self, ticket):
        return self.ledger.check_review(ticket, "app", self.proposal).current

    def test_creation_and_review_are_immutable_nonpermission_data(self):
        ticket = self.begin()
        self.assertEqual(self.draft.revision, 1)
        self.assertFalse(self.draft.revoked)
        self.assertTrue(self.current(ticket))
        for value in (self.draft, ticket, self.ledger.check_review(ticket, "app", self.proposal)):
            with self.assertRaises(TypeError):
                bool(value)
        with self.assertRaises(FrozenInstanceError):
            self.draft.revoked = False
        with self.assertRaises(FrozenInstanceError):
            ticket.proposal_id = "changed"
        self.assertNotIn("notes.txt", repr(ticket))

    def test_same_content_replacement_stales_review_and_prevents_aba(self):
        ticket = self.begin()
        updated = self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.assertEqual(updated.revision, 2)
        self.assertFalse(self.current(ticket))
        self.ledger.replace(updated.draft_id, 2, self.constraint)
        self.assertFalse(self.current(ticket))
        with self.assertRaises(ValueError):
            self.ledger.replace(updated.draft_id, 1, self.constraint)
        with self.assertRaises(ValueError):
            self.begin()

    def test_replacement_cannot_transfer_ownership(self):
        ticket = self.begin()
        other = FileReadConstraint("other", "notes.txt", max_bytes=16)
        with self.assertRaises(ValueError):
            self.ledger.replace(self.draft.draft_id, 1, other)
        self.assertTrue(self.current(ticket))

    def test_revocation_is_terminal_and_invalidates_outstanding_review(self):
        ticket = self.begin()
        revoked = self.ledger.revoke(self.draft.draft_id, 1)
        self.assertTrue(revoked.revoked)
        self.assertEqual(revoked.revision, 2)
        self.assertFalse(self.current(ticket))
        with self.assertRaises(ValueError):
            self.ledger.replace(revoked.draft_id, 2, self.constraint)
        with self.assertRaises(ValueError):
            self.ledger.begin_review("app", self.proposal, revoked.draft_id, 2)
        with self.assertRaises(ValueError):
            self.ledger.revoke(revoked.draft_id, 2)

    def test_application_reference_limit_and_context_changes_stale_exact_review(self):
        ticket = self.begin()
        self.assertFalse(self.ledger.check_review(ticket, "other", self.proposal).current)
        for proposal in (make_file_read_proposal("other.txt", max_bytes=8),
                         make_file_read_proposal("notes.txt", max_bytes=1),
                         make_file_read_proposal("notes.txt", max_bytes=8, requester_context={"purpose": "new"})):
            self.assertFalse(self.ledger.check_review(ticket, "app", proposal).current)
        self.assertTrue(self.current(ticket))

    def test_only_issued_ticket_from_current_ledger_is_recognized(self):
        ticket = self.begin()
        self.assertFalse(self.current(replace(ticket)))
        other = FileReadReviewLedger()
        self.assertFalse(other.check_review(ticket, "app", self.proposal).current)
        self.assertFalse(self.current(replace(ticket, revision=100)))
        self.assertTrue(self.current(ticket))

    def test_new_review_supersedes_previous_and_discard_cannot_retire_new_ticket(self):
        old = self.begin()
        new = self.begin()
        self.assertFalse(self.current(old))
        self.ledger.discard_review(old)
        self.ledger.discard_review(replace(new))
        self.assertTrue(self.current(new))
        self.ledger.discard_review(new)
        self.assertFalse(self.current(new))

    def test_inapplicable_review_does_not_overwrite_current_ticket(self):
        ticket = self.begin()
        for app, proposal in (("other", self.proposal),
                              ("app", make_file_read_proposal("notes.txt", max_bytes=17)),
                              ("app", make_file_read_proposal("other.txt", max_bytes=8))):
            with self.assertRaises(ValueError):
                self.ledger.begin_review(app, proposal, self.draft.draft_id, 1)
            self.assertTrue(self.current(ticket))

    def test_capacity_is_bounded_and_revoked_ids_are_not_reused(self):
        for capacity in (True, 0, -1, 1.0, "1", 4097):
            with self.assertRaises(ValueError):
                FileReadReviewLedger(capacity=capacity)
        ledger = FileReadReviewLedger(capacity=1)
        draft = ledger.create(self.constraint)
        ledger.revoke(draft.draft_id, 1)
        with self.assertRaises(ValueError):
            ledger.create(self.constraint)

    def test_stale_or_malformed_revisions_and_inputs_cannot_mutate_state(self):
        ticket = self.begin()
        for revision in (True, False, 1.0, "1", None, 0, -1, 2):
            with self.assertRaises(ValueError):
                self.ledger.replace(self.draft.draft_id, revision, self.constraint)
            with self.assertRaises(ValueError):
                self.ledger.revoke(self.draft.draft_id, revision)
        with self.assertRaises(ValueError):
            self.ledger.revoke("unknown", 1)
        with self.assertRaises(TypeError):
            self.ledger.create({})
        with self.assertRaises(TypeError):
            self.ledger.check_review({}, "app", self.proposal)
        with self.assertRaises(TypeError):
            self.ledger.check_review(ticket, "app", ActionProposal("read", "notes.txt"))
        self.assertTrue(self.current(ticket))

    def test_concurrent_replacements_only_one_can_use_expected_revision(self):
        ticket = self.begin()
        def attempt(_):
            try:
                return self.ledger.replace(self.draft.draft_id, 1, self.constraint).revision
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(results.count(2), 1)
        self.assertEqual(results.count(None), 1)
        self.assertFalse(self.current(ticket))

    def test_draft_lifecycle_never_opens_files_or_resolves_references(self):
        with patch("builtins.open", side_effect=AssertionError("file opened")), \
             patch("os.open", side_effect=AssertionError("file opened")), \
             patch("pathlib.Path.resolve", side_effect=AssertionError("path resolved")), \
             patch("pathlib.Path.stat", side_effect=AssertionError("file inspected")):
            ticket = self.begin()
            self.assertTrue(self.current(ticket))
            self.ledger.revoke(self.draft.draft_id, 1)
            self.assertFalse(self.current(ticket))

    def test_generated_id_collision_cannot_overwrite_or_restore_a_draft(self):
        ticket = self.begin()
        with patch("core.file_read_review.uuid4", return_value=self.draft.draft_id):
            with self.assertRaises(RuntimeError):
                self.ledger.create(self.constraint)
        self.assertTrue(self.current(ticket))
        self.ledger.revoke(self.draft.draft_id, 1)
        with patch("core.file_read_review.uuid4", return_value=self.draft.draft_id):
            with self.assertRaises(RuntimeError):
                self.ledger.create(self.constraint)
        self.assertFalse(self.current(ticket))
        with self.assertRaises(ValueError):
            self.ledger.begin_review("app", self.proposal, self.draft.draft_id, 2)

    def test_duplicate_review_race_retains_one_ticket_and_revocation_wins_final_state(self):
        from threading import Barrier
        start = Barrier(2)
        def begin(_):
            start.wait(timeout=5)
            return self.begin()
        with ThreadPoolExecutor(max_workers=2) as pool:
            tickets = list(pool.map(begin, range(2)))
        self.assertEqual(sum(self.current(ticket) for ticket in tickets), 1)
        self.ledger.revoke(self.draft.draft_id, 1)
        self.assertFalse(any(self.current(ticket) for ticket in tickets))
        for ticket in tickets:
            self.ledger.discard_review(ticket)
            self.assertFalse(self.current(ticket))

    def test_requester_context_and_copied_state_cannot_restore_or_widen_draft(self):
        ticket = self.begin()
        inspected = self.draft.constraint.to_payload()
        inspected["effects"]["max_bytes"] = 100
        inspected["application_id"] = "other"
        widened = make_file_read_proposal("notes.txt", max_bytes=17,
                                         requester_context={"revision": 1, "revoked": False,
                                                            "max_bytes": 100, "owner": "app"})
        with self.assertRaises(ValueError):
            self.ledger.begin_review("app", widened, self.draft.draft_id, 1)
        self.assertTrue(self.current(ticket))
        revoked = self.ledger.revoke(self.draft.draft_id, 1)
        forged = replace(revoked, revoked=False, revision=1)
        with self.assertRaises(ValueError):
            self.ledger.begin_review("app", self.proposal, forged.draft_id, forged.revision)
        self.assertFalse(self.current(ticket))

    def test_revocation_racing_begin_review_cannot_leave_a_current_ticket(self):
        from threading import Barrier
        start = Barrier(2)
        def begin():
            start.wait(timeout=5)
            try:
                return self.begin()
            except ValueError:
                return None
        def revoke():
            start.wait(timeout=5)
            return self.ledger.revoke(self.draft.draft_id, 1)
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(begin)
            revocation = pool.submit(revoke)
            ticket = pending.result(timeout=10)
            self.assertTrue(revocation.result(timeout=10).revoked)
        if ticket is not None:
            self.assertFalse(self.current(ticket))
        with self.assertRaises(ValueError):
            self.begin()
