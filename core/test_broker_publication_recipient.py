"""Inactive logical recipients cannot authenticate peers or grant permission."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import time
import unittest
from unittest.mock import patch
from core import broker_publication_recipient as recipient


class LogicalRecipientTests(unittest.TestCase):
    def setUp(self):
        self.owner = recipient.LogicalPublicationRecipient('app')
        self.addCleanup(self.owner.close)

    def test_bootstrap_generates_exact_distinct_one_use_descriptor(self):
        value = self.owner.descriptor
        self.assertIs(self.owner.descriptor, value)
        self.assertEqual(value.application_id, 'app')
        self.assertEqual(value.recipient_revision, 1)
        self.assertEqual(len(value.recipient_session), 64)
        self.assertEqual(len(value.recipient_id), 64)
        self.assertNotEqual(value.recipient_session, value.recipient_id)
        with self.assertRaises(TypeError): bool(value)
        claimant = object()
        with self.owner._lock:
            self.owner._claim_for(claimant)
            self.owner._current_for(claimant)
            with self.assertRaises(recipient.PublicationRecipientError): self.owner._current_for(object())

    def test_descriptor_data_cannot_recreate_or_claim_owner(self):
        value = self.owner.descriptor
        self.owner._descriptor = replace(value)
        with self.assertRaises(recipient.PublicationRecipientError): self.owner.descriptor

    def test_application_and_revision_mutation_rejected(self):
        for field, value in [('application_id', 'other'), ('recipient_revision', 2)]:
            with self.subTest(field=field):
                owner = recipient.LogicalPublicationRecipient('app'); self.addCleanup(owner.close)
                object.__setattr__(owner.descriptor, field, value)
                with self.assertRaises(recipient.PublicationRecipientError): owner.descriptor

    def test_equal_valued_type_confusion_rejected(self):
        class DerivedString(str): pass
        for field, value in [('recipient_revision', True), ('recipient_revision', 1.0),
                             ('application_id', DerivedString('app'))]:
            owner = recipient.LogicalPublicationRecipient('app'); self.addCleanup(owner.close)
            object.__setattr__(owner.descriptor, field, value)
            with self.assertRaises(recipient.PublicationRecipientError): owner.descriptor

    def test_close_is_irreversible_even_after_state_rollback(self):
        value = self.owner.descriptor
        self.owner.close(); self.owner._state = 'new'
        with self.assertRaises(recipient.PublicationRecipientError): self.owner.descriptor
        with self.assertRaises(recipient.PublicationRecipientError): self.owner._claim_for(object())
        self.assertEqual(value.recipient_revision, 1)

    def test_bound_state_rollback_cannot_allow_second_claim(self):
        self.owner._claim_for(object()); self.owner._state = 'new'; self.owner._claim = None
        with self.assertRaises(recipient.PublicationRecipientError): self.owner._claim_for(object())

    def test_close_after_claim_retires_owner_without_callback(self):
        claimant = object(); self.owner._claim_for(claimant); self.owner.close()
        self.assertIsNone(self.owner._claim)
        with self.assertRaises(recipient.PublicationRecipientError): self.owner._current_for(claimant)

    def test_actual_timer_retires_even_unclaimed_owner(self):
        owner = recipient.LogicalPublicationRecipient('app', timeout=.04)
        self.addCleanup(owner.close); time.sleep(.08)
        self.assertTrue(owner._terminal)
        with self.assertRaises(recipient.PublicationRecipientError): owner.descriptor

    def test_deadline_extension_is_rejected(self):
        self.owner._deadline += 100
        with self.assertRaises(recipient.PublicationRecipientError): self.owner.descriptor

    def test_two_claims_have_at_most_one_success(self):
        def claim(value):
            with self.owner._lock: self.owner._claim_for(value)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(claim, object()) for _ in range(2)]
        self.assertEqual(sum(value.exception() is None for value in futures), 1)

    def test_invalid_applications_rejected_without_owner(self):
        for value in (None, True, '', ' app', 'app\n', 'a'*257, {'application_id': 'app'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recipient.LogicalPublicationRecipient(value)

    def test_invalid_lifetimes_rejected(self):
        for value in (True, 0, 6, float('nan'), float('inf'), '5'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recipient.LogicalPublicationRecipient('app', timeout=value)

    def test_collision_and_malformed_ids_rejected_without_retry(self):
        for identities in (['a'*64, 'a'*64], ['bad', 'b'*64], [True, 'b'*64]):
            with patch.object(recipient.secrets, 'token_hex', side_effect=identities) as generate:
                with self.assertRaises(recipient.PublicationRecipientError):
                    recipient.LogicalPublicationRecipient('app')
                self.assertEqual(generate.call_count, 2)

    def test_no_requester_endpoint_or_delivery_api(self):
        for name in ('approve', 'allow', 'read', 'publish', 'release', 'execute', 'rotate', 'restore', 'reset'):
            self.assertFalse(hasattr(self.owner, name))
        with self.assertRaises(TypeError):
            recipient.LogicalPublicationRecipient('app', recipient_id='a'*64)


if __name__ == '__main__': unittest.main()
