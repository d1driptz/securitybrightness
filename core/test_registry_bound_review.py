import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from core.authority_store import SQLiteAuthorityStore, AuthorityStoreError
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry, AuthorityInactiveError
from core.registry_bound_review import RegistryBoundFileReadReviews


class RegistryBoundReviewTests(unittest.TestCase):
    def setUp(self):
        self.registry = ApplicationRegistry()
        self.addCleanup(self.registry.close)
        self.credential = self.registry.register("app", ["files.read"])
        self.ledger = FileReadReviewLedger()
        self.draft = self.ledger.create(FileReadConstraint("app", "notes.txt", max_bytes=16))
        self.proposal = make_file_read_proposal("notes.txt", max_bytes=8)
        self.reviews = RegistryBoundFileReadReviews(self.registry, self.ledger)

    def begin(self):
        return self.reviews.begin_review("app", self.credential, self.proposal, self.draft.draft_id, 1)

    def current(self, ticket):
        return self.reviews.check_review(ticket, "app", self.proposal).current

    def persistent(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        store = SQLiteAuthorityStore(Path(folder.name) / "authority.db")
        registry = ApplicationRegistry(store=store)
        self.addCleanup(registry.close)
        credential = registry.register("app", ["files.read"])
        reviews = RegistryBoundFileReadReviews(registry, self.ledger)
        return registry, credential, reviews, store

    def test_authentication_required_and_credentials_not_in_ticket(self):
        for credential in (None, "", "wrong", True):
            with self.assertRaises(AuthorityInactiveError):
                self.reviews.begin_review("app", credential, self.proposal, self.draft.draft_id, 1)
        ticket = self.begin()
        self.assertTrue(self.current(ticket))
        self.assertEqual(ticket.grant_id, self.registry.get("app").grant_id)
        self.assertNotIn(self.credential, repr(ticket))
        self.assertNotIn(self.registry.get("app").credential_hash, repr(ticket))
        with self.assertRaises(TypeError):
            bool(ticket)

    def test_rotation_invalidates_old_ticket_and_new_credential_requires_new_review(self):
        ticket = self.begin()
        fresh = self.registry.rotate_credential("app")
        self.assertFalse(self.current(ticket))
        with self.assertRaises(AuthorityInactiveError):
            self.begin()
        self.credential = fresh
        new = self.begin()
        self.assertTrue(self.current(new))
        self.assertFalse(self.current(ticket))

    def test_permission_and_trust_changes_invalidate_even_when_proposal_still_fits(self):
        for changes in ({"scopes": ["files.read"]}, {"scopes": ["*"]}, {"trusted": True}):
            ticket = self.begin()
            self.registry.update_permissions("app", **changes)
            self.assertFalse(self.current(ticket))

    def test_revocation_and_same_name_reregistration_do_not_revive_ticket(self):
        ticket = self.begin()
        self.registry.revoke("app")
        self.credential = self.registry.register("app", ["files.read"])
        self.assertFalse(self.current(ticket))
        self.assertTrue(self.current(self.begin()))
        self.assertFalse(self.current(ticket))

    def test_persistent_lock_and_reunlock_cannot_revive_review(self):
        registry, credential, reviews, _ = self.persistent()
        with self.assertRaises(AuthorityInactiveError):
            reviews.begin_review("app", credential, self.proposal, self.draft.draft_id, 1)
        grant_id = registry.get("app").grant_id
        self.assertTrue(registry.operator_unlock("app", grant_id))
        ticket = reviews.begin_review("app", credential, self.proposal, self.draft.draft_id, 1)
        registry.lock_all()
        self.assertTrue(registry.operator_unlock("app", grant_id))
        self.assertFalse(reviews.check_review(ticket, "app", self.proposal).current)

    def test_storage_failure_and_registry_close_fail_closed(self):
        registry, credential, reviews, store = self.persistent()
        registry.operator_unlock("app", registry.get("app").grant_id)
        ticket = reviews.begin_review("app", credential, self.proposal, self.draft.draft_id, 1)
        with patch.object(store, "save", side_effect=AuthorityStoreError("unavailable")):
            with self.assertRaises(AuthorityStoreError):
                registry.set_scopes("app", ["files.read"])
        self.assertFalse(reviews.check_review(ticket, "app", self.proposal).current)
        local = self.begin()
        self.registry.close()
        self.assertFalse(self.current(local))

    def test_draft_revocation_replacement_and_supersession_remain_effective(self):
        old = self.begin()
        new = self.begin()
        self.assertFalse(self.current(old))
        self.reviews.discard_review(old)
        self.assertTrue(self.current(new))
        self.ledger.replace(self.draft.draft_id, 1, self.draft.constraint)
        self.assertFalse(self.current(new))
        updated = self.reviews.begin_review("app", self.credential, self.proposal, self.draft.draft_id, 2)
        self.ledger.revoke(self.draft.draft_id, 2)
        self.assertFalse(self.current(updated))

    def test_exact_owner_proposal_and_ticket_identity_are_required(self):
        ticket = self.begin()
        self.assertFalse(self.current(replace(ticket)))
        other = RegistryBoundFileReadReviews(self.registry, self.ledger)
        self.assertFalse(other.check_review(ticket, "app", self.proposal).current)
        self.assertFalse(self.reviews.check_review(ticket, "other", self.proposal).current)
        for proposal in (make_file_read_proposal("notes.txt", max_bytes=1),
                         make_file_read_proposal("other.txt", max_bytes=8),
                         make_file_read_proposal("notes.txt", max_bytes=8, requester_context={"purpose": "new"})):
            self.assertFalse(self.reviews.check_review(ticket, "app", proposal).current)
        self.assertTrue(self.current(ticket))
        self.reviews.discard_review(replace(ticket))
        self.assertTrue(self.current(ticket))
        self.reviews.discard_review(ticket)
        self.assertFalse(self.current(ticket))

    def test_revocation_between_authentication_and_lease_capture_fails(self):
        original = self.registry.authorization_lease
        def revoked_lease(app):
            self.registry.revoke(app.application_id)
            return original(app)
        with patch.object(self.registry, "authorization_lease", side_effect=revoked_lease):
            with self.assertRaises(AuthorityInactiveError):
                self.begin()

    def test_freshness_is_not_scope_permission_and_does_not_access_files(self):
        self.registry.set_scopes("app", [])
        with patch("builtins.open", side_effect=AssertionError("file opened")), \
             patch("os.open", side_effect=AssertionError("file opened")), \
             patch("pathlib.Path.resolve", side_effect=AssertionError("path resolved")):
            ticket = self.begin()
            result = self.reviews.check_review(ticket, "app", self.proposal)
            # Authentication/record liveness is evidence, not a policy or scope decision.
            self.assertTrue(result.current)
            with self.assertRaises(TypeError):
                bool(result)
        self.assertEqual(self.registry.get("app").scopes, frozenset())

    def test_lookup_failure_retires_ticket_even_after_recovery(self):
        ticket = self.begin()
        with patch.object(self.registry, "_is_active", side_effect=RuntimeError("private registry failure")):
            result = self.reviews.check_review(ticket, "app", self.proposal)
        self.assertFalse(result.current)
        self.assertEqual(result.reason, "review_state_unavailable")
        self.assertNotIn("private", repr(result))
        self.assertFalse(self.current(ticket))
        self.assertTrue(self.current(self.begin()))

    def test_missing_or_replaced_registry_record_cannot_restore_old_evidence(self):
        # Fault injection models corrupt or rolled-back registry state, not a
        # supported API for callers to mutate private registry internals.
        for corrupt in (None, object(), "corrupt"):
            ticket = self.begin()
            app = self.registry._applications.pop("app")
            if corrupt is not None:
                self.registry._applications["app"] = corrupt
            self.assertFalse(self.current(ticket))
            self.registry._applications["app"] = app
            self.assertFalse(self.current(ticket))

    def test_reused_grant_id_does_not_mask_a_new_registry_snapshot(self):
        ticket = self.begin()
        old_id = self.registry.get("app").grant_id
        with patch("core.registry.uuid4", return_value=old_id):
            self.registry.set_scopes("app", ["files.read"])
        self.assertEqual(self.registry.get("app").grant_id, old_id)
        self.assertFalse(self.current(ticket))

    def test_authority_change_after_freshness_requires_revalidation_not_replay(self):
        from core.decision_binding import ProposalDecisionBinding
        ticket = self.begin()
        evidence = self.reviews.check_review(ticket, "app", self.proposal)
        binding = ProposalDecisionBinding.for_proposal(self.proposal, "allow")
        self.assertTrue(evidence.current)
        self.registry.revoke("app")
        # Neither an old immutable result nor a caller-constructed binding
        # tracks current authority. Neither is accepted as a registry ticket.
        self.assertTrue(evidence.current)
        self.assertTrue(binding.applies_to(self.proposal))
        self.assertFalse(self.current(ticket))
        for forged in (binding, evidence):
            with self.assertRaises(TypeError):
                self.reviews.check_review(forged, "app", self.proposal)

    def test_registry_mutation_serializes_with_freshness_check(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        entered, mutation_started, release = Event(), Event(), Event()
        ticket = self.begin()
        original = self.ledger.check_review
        def held_check(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test release deadline")
            return original(*args)
        def revoke():
            mutation_started.set()
            self.registry.revoke("app")
        with ThreadPoolExecutor(max_workers=2) as pool:
            with patch.object(self.ledger, "check_review", side_effect=held_check):
                pending = pool.submit(self.current, ticket)
                try:
                    self.assertTrue(entered.wait(5))
                    mutation = pool.submit(revoke)
                    self.assertTrue(mutation_started.wait(5))
                    self.assertFalse(mutation.done())
                finally:
                    release.set()
                self.assertTrue(pending.result(timeout=5))
                mutation.result(timeout=5)
        self.assertFalse(self.current(ticket))

    def test_bad_request_types_do_not_retire_unrelated_valid_evidence(self):
        ticket = self.begin()
        for value in (None, {}, "proposal"):
            with self.assertRaises(TypeError):
                self.reviews.check_review(ticket, "app", value)
        self.assertTrue(self.current(ticket))
        with self.assertRaises(ValueError):
            make_file_read_proposal("notes.txt", max_bytes=8,
                                    requester_context={"grant_id": ticket.grant_id})
