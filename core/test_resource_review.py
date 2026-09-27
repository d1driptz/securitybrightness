import os
from dataclasses import replace, FrozenInstanceError
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry
from core.registry_bound_review import RegistryBoundFileReadReviews
from core.resource_review import ResourceReviewEnvelopes
from core.windows_identity import WindowsIdentityCollector


@unittest.skipUnless(os.name == 'nt', 'Windows native fixture tests')
class ResourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.txt'
        self.path.write_bytes(b'fixture')
        self.collector = WindowsIdentityCollector()
        self.addCleanup(self.collector.close)
        self.observation = self.collector.collect(str(self.path))
        self.registry = ApplicationRegistry()
        self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', [])  # No scope permission!
        self.ledger = FileReadReviewLedger()
        self.draft = self.ledger.create(FileReadConstraint('app', 'label', max_bytes=16))
        self.proposal = make_file_read_proposal('label', max_bytes=16)
        self.reviews = RegistryBoundFileReadReviews(self.registry, self.ledger)
        self.ticket = self.reviews.begin_review('app', self.credential, self.proposal, self.draft.draft_id, 1)
        self.envelopes = ResourceReviewEnvelopes(self.reviews, self.collector)

    def capture(self):
        return self.envelopes.capture(self.ticket, 'app', self.proposal, self.observation)

    def current(self, envelope):
        return self.envelopes.inspect(envelope, 'app', self.proposal).current

    def test_current_envelope_cannot_grant_permission_even_without_granted_scopes(self):
        envelope = self.capture()
        self.assertTrue(self.current(envelope))
        self.assertEqual(self.registry.get('app').scopes, frozenset())
        for value in [envelope, self.envelopes.inspect(envelope, 'app', self.proposal)]:
            with self.assertRaises(TypeError):
                bool(value)
        with self.assertRaises(FrozenInstanceError):
            envelope.schema = 'resource_review.v2'

    def test_copied_modified_serialized_and_cross_coordinator_envelopes_rejected(self):
        envelope = self.capture()
        for other in [replace(envelope), replace(envelope, schema='resource_review.v2'),
                      replace(envelope, envelope_id=[]), envelope.__dict__, None]:
            self.assertFalse(self.current(other))
        other = ResourceReviewEnvelopes(self.reviews, self.collector)
        self.assertFalse(other.inspect(envelope, 'app', self.proposal).current)
        self.assertTrue(self.current(envelope))

    def test_proposal_effect_owner_and_context_mismatch_cannot_transfer_evidence(self):
        envelope = self.capture()
        self.assertFalse(self.envelopes.inspect(envelope, 'other', self.proposal).current)
        for proposal in [make_file_read_proposal('other', max_bytes=16),
                         make_file_read_proposal('label', max_bytes=15),
                         make_file_read_proposal('label', max_bytes=16, requester_context={'note': 'new'})]:
            self.assertFalse(self.envelopes.inspect(envelope, 'app', proposal).current)
        self.assertTrue(self.current(envelope))

    def test_rotation_between_review_and_capture_fails(self):
        self.registry.rotate_credential('app')
        with self.assertRaises(ValueError):
            self.capture()

    def test_registry_change_during_native_binding_prevents_capture(self):
        bind = self.collector.bind
        def racing_bind(*args):
            value = bind(*args)
            self.registry.update_permissions('app', scopes=['files.read'])
            return value
        with patch.object(self.collector, 'bind', side_effect=racing_bind):
            with self.assertRaises(ValueError):
                self.capture()
        self.assertEqual(self.envelopes._issued, {})

    def test_registry_change_during_resource_validation_is_detected(self):
        envelope = self.capture()
        matches = self.collector.matches
        def racing_match(*args):
            value = matches(*args)
            self.registry.rotate_credential('app')
            return value
        with patch.object(self.collector, 'matches', side_effect=racing_match):
            self.assertFalse(self.current(envelope))
        self.assertFalse(self.current(envelope))

    def test_draft_change_during_resource_validation_is_detected(self):
        envelope = self.capture()
        matches = self.collector.matches
        def racing_match(*args):
            value = matches(*args)
            self.ledger.revoke(self.draft.draft_id, 1)
            return value
        with patch.object(self.collector, 'matches', side_effect=racing_match):
            self.assertFalse(self.current(envelope))

    def test_delayed_consumers_must_recheck_old_positive_sample_is_not_a_lease(self):
        envelope = self.capture()
        sample = self.envelopes.inspect(envelope, 'app', self.proposal)
        self.registry.revoke('app')
        self.assertTrue(sample.current)  # Historical sample, deliberately not live authority.
        self.assertFalse(self.current(envelope))
        self.credential = self.registry.register('app', [])
        self.assertFalse(self.current(envelope))

    def test_rebinding_and_review_supersession_invalidate_envelopes(self):
        first = self.capture()
        second = self.capture()
        self.assertFalse(self.current(first))
        self.assertTrue(self.current(second))
        self.reviews.begin_review('app', self.credential, self.proposal, self.draft.draft_id, 1)
        self.assertFalse(self.current(second))

    def test_resource_mutation_retirement_and_recreation_cannot_restore_evidence(self):
        envelope = self.capture()
        self.path.write_bytes(b'different size fixture')
        self.assertFalse(self.current(envelope))
        self.path.write_bytes(b'fixture')
        self.observation = self.collector.collect(str(self.path))
        self.assertFalse(self.current(envelope))

    def test_failure_recovery_cannot_restore_retired_envelope(self):
        envelope = self.capture()
        with patch.object(self.reviews, 'check_review', side_effect=OSError('secret registry path')):
            self.assertFalse(self.current(envelope))
        self.assertFalse(self.current(envelope))

    def test_duplicate_ids_retired_tombstones_capacity_and_close(self):
        with patch('core.resource_review.uuid4', return_value='same'):
            envelope = self.capture()
            self.envelopes.discard(replace(envelope))
            self.assertTrue(self.current(envelope))
            self.envelopes.discard(envelope)
            with self.assertRaises(ValueError):
                self.capture()
        limited = ResourceReviewEnvelopes(self.reviews, self.collector, capacity=1)
        envelope = limited.capture(self.ticket, 'app', self.proposal, self.observation)
        limited.discard(envelope)
        with self.assertRaises(ValueError):
            limited.capture(self.ticket, 'app', self.proposal, self.observation)
        self.envelopes.close()
        self.assertFalse(self.current(envelope))
        with self.assertRaises(ValueError):
            self.capture()

    def test_requester_cannot_supply_approval_or_fabricate_observations(self):
        for observation in [replace(self.observation), self.observation.__dict__]:
            with self.assertRaises((ValueError, TypeError)):
                self.envelopes.capture(self.ticket, 'app', self.proposal, observation)
        with self.assertRaises(TypeError):
            self.envelopes.capture(self.ticket, 'app', self.proposal, self.observation, approved=True)
        with self.assertRaises(ValueError):
            self.envelopes.capture(replace(self.ticket), 'app', self.proposal, self.observation)

    def test_concurrent_captures_leave_only_one_resource_binding_current(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            envelopes = list(pool.map(lambda _: self.capture(), range(2)))
        self.assertEqual(sum(self.current(envelope) for envelope in envelopes), 1)

    def test_collector_closure_and_draft_version_change_retire_envelope(self):
        envelope = self.capture()
        self.ledger.replace(self.draft.draft_id, 1, self.draft.constraint)
        self.assertFalse(self.current(envelope))
        self.ticket = self.reviews.begin_review('app', self.credential, self.proposal, self.draft.draft_id, 2)
        new = self.capture()
        self.collector.close()
        self.assertFalse(self.current(new))

    def test_capture_rejects_non_native_providers_and_invalid_bounds(self):
        for provider in [None, {}, object()]:
            with self.assertRaises(TypeError):
                ResourceReviewEnvelopes(self.reviews, provider)
        for capacity in [True, 0, 4097, '128']:
            with self.assertRaises(ValueError):
                ResourceReviewEnvelopes(self.reviews, self.collector, capacity=capacity)


if __name__ == '__main__':
    unittest.main()
