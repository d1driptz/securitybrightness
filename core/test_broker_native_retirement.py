"""Generated native fixtures only; this composition never reads content."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch
from core import test_broker_live_review as helpers
from core.broker_acquisition_draft import AcquisitionDraft
from core.broker_native_retirement import NativeRetirementDraft, NativeRetirementError
from core.broker_session import BrokerResourceSession
from core.file_read_schema import make_file_read_proposal


class NativeRetirementTests(unittest.TestCase):
    def setUp(self):
        helpers.LiveReviewMappingTests.setUp(self)
        request = self.peer.receive(helpers.LiveReviewMappingTests.begin(self))
        self.resources = BrokerResourceSession(capacity=1)
        self.addCleanup(self.resources.close)
        self.observation = self.resources.issue('app', self.proposal, request['decision_id'])
        d = self.observation.description
        frame = self.peer.send(dict(registry_session=self.observation.session_id,
            observation=dict(owner_session=d.session, resource_token=d.resource_token,
                volume_serial=d.volume_serial, file_id=d.file_id.hex(), size_bytes=d.size_bytes,
                display_path=d.display_path)))
        self.model.coordinator.observe(frame)
        self.display = self.model.operator.display()
        self.model.operator.record(self.display, 'ALLOW ONCE')
        self.acquisition = AcquisitionDraft(self.model)
        self.addCleanup(self.acquisition.close)
        self.token = self.acquisition.coordinator.reserve()
        self.gate = NativeRetirementDraft(self.acquisition, self.resources, self.observation)
        self.addCleanup(self.gate.close)

    def retire(self, **changes):
        args = dict(reservation=self.token, application_id='app', credential=self.credential,
                    proposal=self.proposal)
        args.update(changes)
        return self.gate.retire_once(**args)

    def rejected(self, **changes):
        with self.assertRaises(NativeRetirementError): self.retire(**changes)
        with self.assertRaises(NativeRetirementError): self.retire()
        self.assertTrue(self.resources._closed)
        self.assertEqual(self.model._state, 'closed')

    def test_native_retirement_returns_no_data_or_permission(self):
        result = self.retire()
        self.assertFalse(hasattr(result, 'data'))
        self.assertIn('no read or delivery authorized', result.meaning)
        with self.assertRaises(TypeError): bool(result)
        self.assertTrue(self.resources._closed)
        self.rejected()

    def test_copied_reservation(self): self.rejected(reservation=replace(self.token))
    def test_wrong_application(self): self.rejected(application_id='other')
    def test_wrong_credential(self): self.rejected(credential='wrong')
    def test_oversized_credential(self): self.rejected(credential='x'*513)
    def test_changed_effect(self): self.rejected(proposal=make_file_read_proposal('untrusted label', max_bytes=64))
    def test_changed_request(self): self.rejected(proposal=make_file_read_proposal('different', max_bytes=128))

    def test_copied_observation_is_not_local_ownership(self):
        self.gate._observation = replace(self.observation)
        self.rejected()

    def test_other_session_cannot_supply_ownership(self):
        other = BrokerResourceSession(capacity=1)
        self.addCleanup(other.close)
        gate = NativeRetirementDraft(self.acquisition, other, self.observation)
        self.addCleanup(gate.close)
        with self.assertRaises(NativeRetirementError):
            gate.retire_once(self.token, 'app', self.credential, self.proposal)
        self.assertTrue(other._closed)
        self.assertEqual(self.model._state, 'closed')

    def test_revoked_authority(self):
        self.registry.revoke('app')
        self.rejected()

    def test_rotated_credential(self):
        self.credential = self.registry.rotate_credential('app')
        self.rejected()

    def test_changed_permissions(self):
        self.registry.update_permissions('app', scopes=['*'])
        self.rejected()

    def test_stale_draft(self):
        self.ledger.replace(self.draft.draft_id, 1, self.constraint)
        self.rejected()

    def test_different_owned_fixture_does_not_inherit_review(self):
        other = BrokerResourceSession(capacity=1)
        self.addCleanup(other.close)
        observation = other.issue('app', self.proposal, self.display.request_id)
        gate = NativeRetirementDraft(self.acquisition, other, observation)
        self.addCleanup(gate.close)
        with self.assertRaises(NativeRetirementError):
            gate.retire_once(self.token, 'app', self.credential, self.proposal)
        self.assertTrue(other._closed)
        self.assertEqual(self.model._state, 'closed')

    def test_changed_native_metadata(self):
        owner = self.resources._records[self.observation.resource_token][0]
        with patch.object(owner._native, 'metadata', return_value=None): self.rejected()

    def test_review_mutation_during_native_retirement(self):
        original = self.resources.verify_once
        def verify(*args):
            result = original(*args)
            object.__setattr__(self.display, 'max_bytes', 4096)
            return result
        with patch.object(self.resources, 'verify_once', side_effect=verify): self.rejected()

    def test_closed_resource(self):
        self.resources.close()
        self.rejected()

    def test_expired_resource(self):
        self.resources._deadline = 0
        self.rejected()

    def test_native_failure(self):
        owner = self.resources._records[self.observation.resource_token][0]
        with patch.object(owner, 'inspect_binding', side_effect=OSError('native failure')):
            self.rejected()

    def test_revocation_during_native_retirement(self):
        original = self.resources.verify_once
        def verify(*args):
            result = original(*args)
            self.registry.revoke('app')
            return result
        with patch.object(self.resources, 'verify_once', side_effect=verify): self.rejected()

    def test_expiry_during_native_retirement(self):
        original = self.resources.verify_once
        def verify(*args):
            result = original(*args)
            self.model._deadline = 0
            return result
        with patch.object(self.resources, 'verify_once', side_effect=verify): self.rejected()

    def test_mutation_during_native_retirement(self):
        original = self.resources.verify_once
        def verify(*args):
            result = original(*args)
            object.__setattr__(self.token, 'canonical_context', b'{}')
            return result
        with patch.object(self.resources, 'verify_once', side_effect=verify): self.rejected()

    def test_cleanup_failure_never_returns_evidence(self):
        original = self.resources.close
        def close():
            original()
            raise OSError('cleanup uncertain')
        with patch.object(self.resources, 'close', side_effect=close):
            with self.assertRaises((NativeRetirementError, OSError)): self.retire()
        self.rejected()

    def test_concurrent_attempts_have_one_receipt(self):
        def attempt(_):
            try: self.retire(); return 1
            except NativeRetirementError: return 0
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)

    def test_requester_dictionary_is_not_an_owner(self):
        with self.assertRaises(TypeError): NativeRetirementDraft(self.acquisition, {}, self.observation)

    def test_cancel_retires_both_owners(self):
        self.gate.close()
        self.rejected()
