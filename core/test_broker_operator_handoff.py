"""Trusted-local operator handoff tests, not completion of a human demonstration."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from core import broker_operator_handoff as handoff
from core.broker_pending_review import PendingBrokerReview,PendingReviewError
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry
from core.json_input import loads


class BrokerOperatorHandoffTests(unittest.TestCase):
    def setUp(self):
        self.registry=ApplicationRegistry();self.addCleanup(self.registry.close)
        self.credential=self.registry.register('app',['files.read'])
        self.ledger=FileReadReviewLedger()
        self.draft=self.ledger.create(FileReadConstraint('app','label',max_bytes=128))
        self.proposal=make_file_read_proposal('label',max_bytes=128)
        self.model=PendingBrokerReview(self.registry,self.ledger);self.addCleanup(self.model.close)
        self.request=self.model.application.propose('app',self.credential,self.proposal,self.draft.draft_id,1)
        self.channel=handoff.BrokerOperatorHandoff(self.model,timeout=2)
        self.pool=ThreadPoolExecutor(max_workers=2)
        self.addCleanup(self.pool.shutdown,wait=True)
        self.addCleanup(self.channel.close)

    def start(self):
        future=self.pool.submit(self.channel.worker.request_review,self.request)
        deadline=time.monotonic()+1
        while time.monotonic()<deadline:
            prompts=self.channel.operator.pending()
            if prompts:return future,prompts[0]
            time.sleep(.002)
        self.fail('prompt not published')

    def consume(self):
        return self.model.application.consume_evidence(self.request,'app',self.credential,self.proposal)

    def test_allow_records_evidence_and_consumes_without_bytes_or_grant(self):
        before=self.registry.get('app');future,prompt=self.start()
        queued=self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(TypeError):bool(queued)
        result=future.result(timeout=1)
        self.assertEqual(result.decision,'allow_once')
        evidence=self.consume()
        self.assertFalse(hasattr(evidence,'data'))
        self.assertIs(self.registry.get('app'),before)
        self.assertEqual(self.channel.operator.pending(),())

    def test_display_contains_exact_binding_without_credentials(self):
        future,prompt=self.start();display=loads(prompt.canonical_display)
        self.assertEqual(display['application_id'],'app')
        self.assertEqual(display['proposal_json'],self.proposal.canonical_bytes().decode())
        self.assertEqual(display['draft_revision'],1)
        self.assertEqual(display['size_bytes'],37)
        self.assertNotIn(self.credential,prompt.canonical_display.decode()+repr(prompt))
        with self.assertRaises(TypeError):bool(prompt)
        self.channel.operator.respond(prompt,'DENY');future.result(timeout=1)

    def test_deny_closes_resource(self):
        future,prompt=self.start();path=Path(loads(prompt.canonical_display)['display_path'])
        self.channel.operator.respond(prompt,'DENY')
        self.assertEqual(future.result(timeout=1).decision,'deny')
        self.assertFalse(path.exists())
        with self.assertRaises(PendingReviewError):self.consume()

    def test_worker_port_cannot_respond_or_fetch_prompt(self):
        for name in ['respond','pending','operator','record']:
            self.assertFalse(hasattr(self.channel.worker,name))

    def test_copied_prompt_is_rejected(self):
        future,prompt=self.start()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(replace(prompt),'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        with self.assertRaises(PendingReviewError):self.consume()

    def test_mutated_prompt_is_rejected(self):
        future,prompt=self.start();object.__setattr__(prompt,'canonical_display',b'{}')
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_requester_string_or_dict_is_not_operator_prompt(self):
        future,prompt=self.start()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond({'review_id':prompt.review_id},'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_forged_confirmation_does_not_record_evidence(self):
        future,prompt=self.start()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,True)
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        with self.assertRaises(PendingReviewError):self.consume()

    def test_confirmation_requires_exact_visible_choice(self):
        future,prompt=self.start()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,'allow once')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_replay_cannot_record_again(self):
        future,prompt=self.start();self.channel.operator.respond(prompt,'ALLOW ONCE');future.result(timeout=1)
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(PendingReviewError):self.consume()

    def test_second_worker_request_is_terminal(self):
        future,prompt=self.start()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.worker.request_review(self.request)
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_expiry_wakes_waiter_and_removes_fixture(self):
        self.channel=handoff.BrokerOperatorHandoff(self.model,timeout=.2);self.addCleanup(self.channel.close)
        future,prompt=self.start();path=Path(loads(prompt.canonical_display)['display_path'])
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        self.assertFalse(path.exists())
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,'ALLOW ONCE')

    def test_expiry_after_record_still_retires_unconsumed_evidence(self):
        self.channel=handoff.BrokerOperatorHandoff(self.model,timeout=.2);self.addCleanup(self.channel.close)
        future,prompt=self.start();self.channel.operator.respond(prompt,'ALLOW ONCE');future.result(timeout=1)
        path=Path(loads(prompt.canonical_display)['display_path']);deadline=time.monotonic()+1
        while path.exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertFalse(path.exists())
        with self.assertRaises(PendingReviewError):self.consume()

    def test_operator_cancel_wakes_waiter(self):
        future,_=self.start();self.channel.operator.cancel()
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        with self.assertRaises(PendingReviewError):self.consume()

    def test_rotation_before_response_fails_freshness(self):
        future,prompt=self.start();self.registry.rotate_credential('app')
        self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_draft_revocation_before_response_fails_freshness(self):
        future,prompt=self.start();self.ledger.revoke(self.draft.draft_id,1)
        self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_expiry_during_record_never_returns_success(self):
        future,prompt=self.start();original=self.model.operator.record
        def record(*args):
            result=original(*args)
            self.channel._deadline=time.monotonic()-1
            return result
        with patch.object(self.model.operator,'record',record):
            self.channel.operator.respond(prompt,'ALLOW ONCE')
            with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        with self.assertRaises(PendingReviewError):self.consume()

    def test_redisplay_invalidates_queued_prompt(self):
        future,prompt=self.start();self.model.operator.display(self.request)
        self.channel.operator.respond(prompt,'ALLOW ONCE')
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_pending_cannot_extend_deadline(self):
        future,prompt=self.start();deadline=self.channel._deadline
        for _ in range(10):self.assertIs(self.channel.operator.pending()[0],prompt)
        self.assertEqual(self.channel._deadline,deadline)
        self.channel.operator.cancel()
        with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)

    def test_invalid_lifetime_rejected(self):
        for timeout in [True,0,-1,31,float('nan'),float('inf'),'1']:
            with self.assertRaises(ValueError):handoff.BrokerOperatorHandoff(self.model,timeout=timeout)

    def test_closed_handoff_cannot_restart(self):
        self.channel.close()
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.worker.request_review(self.request)
        self.assertEqual(self.channel.operator.pending(),())

    def test_oversized_display_is_never_published(self):
        self.channel.close()
        self.model=PendingBrokerReview(self.registry,self.ledger);self.addCleanup(self.model.close)
        self.proposal=make_file_read_proposal('label',max_bytes=128,requester_context={'note':'x'*20000})
        self.request=self.model.application.propose('app',self.credential,self.proposal,self.draft.draft_id,1)
        self.channel=handoff.BrokerOperatorHandoff(self.model);self.addCleanup(self.channel.close)
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.worker.request_review(self.request)
        self.assertEqual(self.channel.operator.pending(),())
        with self.assertRaises(PendingReviewError):self.consume()

    def test_invalid_generated_nonce_fails_closed(self):
        with patch.object(handoff.secrets,'token_hex',return_value='z'*64):
            with self.assertRaises(handoff.BrokerOperatorError):self.channel.worker.request_review(self.request)
        self.assertEqual(self.channel.operator.pending(),())

    def test_cleanup_failure_cannot_complete_pending_review(self):
        future,prompt=self.start();original=self.model.close
        def close():
            original();raise PendingReviewError('cleanup failure')
        with patch.object(self.model,'close',close):
            self.channel.close()
            with self.assertRaises(handoff.BrokerOperatorError):future.result(timeout=1)
        self.assertTrue(self.channel._cleanup_failed)
        with self.assertRaises(handoff.BrokerOperatorError):self.channel.operator.respond(prompt,'ALLOW ONCE')
