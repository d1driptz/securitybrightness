"""Inactive pending review tests: generated fixtures only, no read adapter."""
from dataclasses import replace
from pathlib import Path
import threading
import tempfile
import unittest
from unittest.mock import patch
from core import broker_pending_review as pending
from core.broker_pending_review import PendingBrokerReview,PendingReviewError
from core.broker_session import BrokerResourceSession
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry
from core.authority_store import SQLiteAuthorityStore


class PendingBrokerReviewTests(unittest.TestCase):
    def setUp(self):
        self.registry=ApplicationRegistry();self.addCleanup(self.registry.close)
        self.credential=self.registry.register('app',['files.read'])
        self.ledger=FileReadReviewLedger()
        self.constraint=FileReadConstraint('app','label',max_bytes=128)
        self.draft=self.ledger.create(self.constraint)
        self.proposal=make_file_read_proposal('label',max_bytes=128)
        self.model=PendingBrokerReview(self.registry,self.ledger);self.addCleanup(self.model.close)

    def begin(self):
        return self.model.application.propose('app',self.credential,self.proposal,self.draft.draft_id,1)

    def approve(self):
        request=self.begin();display=self.model.operator.display(request)
        self.model.operator.record(display,'allow_once')
        return request,display

    def consume(self,request):
        return self.model.application.consume_evidence(request,'app',self.credential,self.proposal)

    def test_review_evidence_never_changes_authority_or_releases_bytes(self):
        before=self.registry.get('app')
        request,display=self.approve()
        result=self.consume(request)
        self.assertEqual(result.decision,'allow_once')
        self.assertEqual(result.lifecycle,'retired')
        self.assertFalse(hasattr(result,'data'))
        self.assertIs(self.registry.get('app'),before)
        self.assertFalse(Path(display.display_path).exists())
        self.assertNotIn(self.credential,repr(display)+repr(result)+display.proposal_json)
        for value in [request,display,result]:
            with self.assertRaises(TypeError): bool(value)
        with self.assertRaises(PendingReviewError): self.consume(request)

    def test_application_port_has_no_operator_controls(self):
        for name in ['record','display','cancel','operator']:
            self.assertFalse(hasattr(self.model.application,name))
        self.assertFalse(hasattr(self.model.operator,'propose'))

    def test_authority_alone_cannot_consume(self):
        request=self.begin()
        with self.assertRaises(PendingReviewError): self.consume(request)
        with self.assertRaises(PendingReviewError): self.model.operator.display(request)

    def test_scope_missing_cannot_create_review(self):
        self.registry.update_permissions('app',scopes=[])
        with self.assertRaises(PendingReviewError): self.begin()
        self.assertFalse(self.model._broker._records)

    def test_bad_credential_prevents_resource_creation(self):
        self.credential='wrong'
        with self.assertRaises(PendingReviewError): self.begin()
        self.assertFalse(self.model._broker._records)

    def test_deny_is_terminal_and_closes_fixture(self):
        request=self.begin();display=self.model.operator.display(request)
        result=self.model.operator.record(display,'deny')
        self.assertEqual(result.decision,'deny')
        with self.assertRaises(TypeError):bool(result)
        self.assertFalse(Path(display.display_path).exists())
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_copied_display_and_request_are_rejected(self):
        request=self.begin();display=self.model.operator.display(request)
        with self.assertRaises(PendingReviewError):self.model.operator.record(replace(display),'allow_once')
        self.assertFalse(Path(display.display_path).exists())
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_mutated_display_is_rejected(self):
        request=self.begin();display=self.model.operator.display(request)
        object.__setattr__(display,'max_bytes',4096)
        with self.assertRaises(PendingReviewError):self.model.operator.record(display,'allow_once')

    def test_duplicate_review_is_terminal(self):
        request,display=self.approve()
        with self.assertRaises(PendingReviewError):self.model.operator.record(display,'allow_once')
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_redisplay_discards_prior_review_evidence(self):
        request,old=self.approve()
        current=self.model.operator.display(request)
        self.assertIsNot(old,current)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_redisplay_can_receive_fresh_evidence(self):
        request,old=self.approve();current=self.model.operator.display(request)
        self.model.operator.record(current,'allow_once');self.consume(request)

    def test_credential_rotation_cannot_restore_prior_review(self):
        request,display=self.approve()
        self.credential=self.registry.rotate_credential('app')
        with self.assertRaises(PendingReviewError):self.consume(request)
        self.assertFalse(Path(display.display_path).exists())

    def test_permission_change_invalidates_even_same_scope(self):
        request,_=self.approve();self.registry.update_permissions('app',scopes=['files.read'])
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_revoke_and_same_name_registration_do_not_restore_review(self):
        request,_=self.approve();self.registry.revoke('app')
        self.credential=self.registry.register('app',['files.read'])
        with self.assertRaises(PendingReviewError):self.consume(request)

    def persistent(self):
        self.model.close()
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.registry=ApplicationRegistry(store=SQLiteAuthorityStore(Path(folder.name)/'authority.db'))
        self.addCleanup(self.registry.close)
        self.credential=self.registry.register('app',['files.read'])
        self.assertTrue(self.registry.operator_unlock('app',self.registry.get('app').grant_id))
        self.model=PendingBrokerReview(self.registry,self.ledger);self.addCleanup(self.model.close)

    def test_lock_invalidates_review(self):
        self.persistent()
        request,_=self.approve();self.registry.lock_all()
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_unlock_after_lock_cannot_restore_old_review(self):
        self.persistent()
        request,_=self.approve();grant=self.registry.get('app').grant_id
        self.registry.lock_all();self.registry.operator_unlock('app',grant)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_draft_revision_change_invalidates(self):
        request,_=self.approve();self.ledger.replace(self.draft.draft_id,1,self.constraint)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_final_draft_revocation_invalidates(self):
        request,_=self.approve();self.ledger.revoke(self.draft.draft_id,1)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_registry_lookup_failure_is_terminal(self):
        request,display=self.approve()
        with patch.object(self.registry,'get',side_effect=OSError('unavailable')):
            with self.assertRaises(PendingReviewError):self.consume(request)
        self.assertFalse(Path(display.display_path).exists())
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_proposal_change_cannot_inherit_review(self):
        request,_=self.approve()
        changed=make_file_read_proposal('changed',max_bytes=128)
        with self.assertRaises(PendingReviewError):
            self.model.application.consume_evidence(request,'app',self.credential,changed)

    def test_expiry_during_metadata_sample_closes_everything(self):
        request=self.begin();original=self.model._broker.inspect
        clock=[self.model._deadline-1]
        def inspect(*args):
            result=original(*args);clock[0]=self.model._deadline;return result
        with patch.object(pending,'monotonic',side_effect=lambda:clock[0]),patch.object(self.model._broker,'inspect',inspect):
            with self.assertRaises(PendingReviewError):self.model.operator.display(request)

    def test_revocation_during_resource_verification_rejected(self):
        request,_=self.approve();original=self.model._broker.verify_once
        def verify(*args):
            result=original(*args);self.registry.revoke('app');return result
        with patch.object(self.model._broker,'verify_once',verify):
            with self.assertRaises(PendingReviewError):self.consume(request)

    def test_draft_change_during_review_retirement_rejected(self):
        request,_=self.approve();original=self.model._reviews.discard_review
        def discard(ticket):
            original(ticket)
            if not self.ledger._existing(self.draft.draft_id).revoked:self.ledger.revoke(self.draft.draft_id,1)
        with patch.object(self.model._reviews,'discard_review',discard):
            with self.assertRaises(PendingReviewError):self.consume(request)

    def test_registry_change_during_review_retirement_rejected(self):
        request,_=self.approve();original=self.model._reviews.discard_review
        def discard(ticket):
            original(ticket);self.registry.revoke('app')
        with patch.object(self.model._reviews,'discard_review',discard):
            with self.assertRaises(PendingReviewError):self.consume(request)

    def test_expiry_during_final_retirement_rejected(self):
        request,_=self.approve();original=self.model._reviews.discard_review;clock=[self.model._deadline-1]
        def discard(ticket):
            original(ticket);clock[0]=self.model._deadline
        with patch.object(pending,'monotonic',side_effect=lambda:clock[0]),patch.object(self.model._reviews,'discard_review',discard):
            with self.assertRaises(PendingReviewError):self.consume(request)

    def test_concurrent_evidence_consumption_at_most_once(self):
        request,_=self.approve();barrier=threading.Barrier(3);results=[]
        def consume():
            barrier.wait()
            try:results.append(self.consume(request))
            except PendingReviewError:results.append(None)
        workers=[threading.Thread(target=consume) for _ in range(2)]
        for worker in workers:worker.start()
        barrier.wait()
        for worker in workers:worker.join(3);self.assertFalse(worker.is_alive())
        self.assertEqual(sum(value is not None for value in results),1)

    def test_cancel_is_final(self):
        request,display=self.approve();self.model.operator.cancel()
        self.assertFalse(Path(display.display_path).exists())
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_local_observation_copy_cannot_become_live(self):
        request=self.begin()
        observation=self.model._observation
        with self.assertRaises(ValueError):
            self.model._broker.inspect(replace(observation),'app',self.proposal,self.model._identity)
        with self.assertRaises(PendingReviewError):self.model.operator.display(request)

    def test_retired_or_serialized_observation_is_not_accepted(self):
        request=self.begin()
        with self.assertRaises(ValueError):self.model._broker.inspect({},'app',self.proposal,self.model._identity)
        with self.assertRaises(PendingReviewError):self.model.operator.display(request)

    def test_ticket_and_constraint_mutation_invalidate(self):
        request=self.begin();object.__setattr__(self.model._ticket,'grant_id','fake')
        with self.assertRaises(PendingReviewError):self.model.operator.display(request)

    def test_copied_request_is_terminal(self):
        request,_=self.approve()
        with self.assertRaises(PendingReviewError):self.consume(replace(request))
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_same_revision_constraint_mutation_is_rejected(self):
        request,_=self.approve()
        changed=FileReadConstraint('app','label',max_bytes=4096)
        object.__setattr__(self.constraint,'_body',changed._body)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_resource_metadata_change_invalidates_review(self):
        request,_=self.approve()
        record=next(record for record in self.model._broker._records.values() if record is not None)
        owner=record[0]
        with patch.object(owner._native,'metadata',side_effect=OSError('changed')):
            with self.assertRaises(PendingReviewError):self.consume(request)

    def test_invalid_operator_decision_does_not_become_approval(self):
        request=self.begin();display=self.model.operator.display(request)
        with self.assertRaises(PendingReviewError):self.model.operator.record(display,True)
        with self.assertRaises(PendingReviewError):self.consume(request)

    def test_credential_not_stored_in_review_state(self):
        request=self.begin();display=self.model.operator.display(request)
        self.assertNotIn(self.credential,repr(self.model.__dict__))
        self.assertNotIn(self.credential,repr(display))
