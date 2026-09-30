"""Generated fixture session tests; neither tokens nor matches authorize reads."""
from dataclasses import replace
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from core import broker_session as session
from core import broker_resource as resource
from core.file_read_schema import make_file_read_proposal


class BrokerSessionTests(unittest.TestCase):
    def setUp(self):
        self.session = session.BrokerResourceSession(capacity=2)
        self.addCleanup(self.session.close)
        self.proposal = make_file_read_proposal('descriptive only',max_bytes=128)

    def issue(self, target=None):
        return (self.session if target is None else target).issue('app',self.proposal,'d'*64)

    def consume(self, observation, target=None):
        return (self.session if target is None else target).verify_once(observation.session_id,
            observation.resource_token,'app',self.proposal,'d'*64)

    def test_bounded_live_handles_close_on_consumption(self):
        first,second = self.issue(),self.issue()
        self.assertTrue(Path(first.description.display_path).exists())
        self.assertTrue(Path(second.description.display_path).exists())
        with self.assertRaises(TypeError): bool(first)
        result = self.consume(first)
        self.assertFalse(hasattr(result,'data'))
        self.assertFalse(Path(first.description.display_path).exists())
        self.assertTrue(Path(second.description.display_path).exists())
        self.consume(second)
        self.assertFalse(Path(second.description.display_path).exists())

    def test_capacity_counts_retired_tokens(self):
        first,second = self.issue(),self.issue()
        self.consume(first)
        with self.assertRaises(resource.BrokerResourceError): self.issue()
        self.assertFalse(Path(second.description.display_path).exists())

    def test_replay_closes_remaining_ownership(self):
        first,second = self.issue(),self.issue()
        self.consume(first)
        with self.assertRaises(resource.BrokerResourceError): self.consume(first)
        self.assertFalse(Path(second.description.display_path).exists())
        with self.assertRaises(resource.BrokerResourceError): self.consume(second)

    def test_cross_session_transfer_rejected(self):
        first = self.issue()
        with session.BrokerResourceSession() as other:
            second = self.issue(other)
            with self.assertRaises(resource.BrokerResourceError): self.consume(first,other)
            self.assertFalse(Path(second.description.display_path).exists())
        self.consume(first)

    def test_unknown_or_malformed_token_retires_session(self):
        for token in [None,{},True,'x','0'*64]:
            with session.BrokerResourceSession() as target:
                observation = self.issue(target)
                with self.assertRaises(resource.BrokerResourceError):
                    target.verify_once(observation.session_id,token,'app',self.proposal,'d'*64)
                self.assertFalse(Path(observation.description.display_path).exists())

    def test_application_proposal_and_decision_substitution(self):
        for app,proposal,decision in [('other',self.proposal,'d'*64),
            ('app',make_file_read_proposal('changed',max_bytes=128),'d'*64),('app',self.proposal,'e'*64)]:
            with session.BrokerResourceSession() as target:
                observation = self.issue(target)
                with self.assertRaises(resource.BrokerResourceError):
                    target.verify_once(observation.session_id,observation.resource_token,app,proposal,decision)
                self.assertFalse(Path(observation.description.display_path).exists())

    def test_cancel_closes_all_and_cannot_restore(self):
        observations = [self.issue(),self.issue()]
        self.session.close(); self.session.close()
        for observation in observations:
            self.assertFalse(Path(observation.description.display_path).exists())
            with self.assertRaises(resource.BrokerResourceError): self.consume(observation)
        with self.assertRaises(resource.BrokerResourceError): self.issue()

    def test_expiry_retires_all(self):
        first,second = self.issue(),self.issue()
        with patch.object(session,'monotonic',return_value=self.session._deadline):
            with self.assertRaises(resource.BrokerResourceError): self.consume(first)
        self.assertFalse(Path(first.description.display_path).exists())
        self.assertFalse(Path(second.description.display_path).exists())

    def test_expiry_during_cleanup_prevents_receipt(self):
        observation = self.issue()
        clock = [self.session._deadline-1]
        original = resource.BrokerFixtureOwner.verify_once
        def verify(owner,*args):
            result=original(owner,*args); clock[0]=self.session._deadline; return result
        with patch.object(session,'monotonic',side_effect=lambda:clock[0]),patch.object(resource.BrokerFixtureOwner,'verify_once',verify):
            with self.assertRaises(resource.BrokerResourceError): self.consume(observation)

    def test_mutated_description_invalidates_owner(self):
        observation=self.issue()
        object.__setattr__(observation.description,'file_id',b'x'*16)
        with self.assertRaises(resource.BrokerResourceError): self.consume(observation)

    def test_token_snapshot_mutation_cannot_retarget(self):
        first,second=self.issue(),self.issue()
        changed=replace(first,resource_token='0'*64)
        with self.assertRaises(resource.BrokerResourceError): self.consume(changed)
        self.assertFalse(Path(second.description.display_path).exists())

    def test_concurrent_consume_has_one_receipt(self):
        observation=self.issue(); barrier=threading.Barrier(3); results=[]
        def consume():
            barrier.wait()
            try: results.append(self.consume(observation))
            except resource.BrokerResourceError: results.append(None)
        workers=[threading.Thread(target=consume) for _ in range(2)]
        for worker in workers: worker.start()
        barrier.wait()
        for worker in workers: worker.join(3); self.assertFalse(worker.is_alive())
        self.assertEqual(sum(value is not None for value in results),1)

    def test_invalid_capacity(self):
        for capacity in [True,0,9,'1']:
            with self.assertRaises(resource.BrokerResourceError): session.BrokerResourceSession(capacity=capacity)

    def test_invalid_issue_closes_existing_handles(self):
        observation=self.issue()
        with self.assertRaises(resource.BrokerResourceError): self.session.issue('app',{},'d'*64)
        self.assertFalse(Path(observation.description.display_path).exists())

    def test_duplicate_owner_session_rejected_and_both_closed(self):
        first=self.issue()
        original=resource.BrokerFixtureOwner.describe
        def describe(owner):
            value=original(owner)
            return replace(value,session=first.description.session)
        with patch.object(resource.BrokerFixtureOwner,'describe',describe):
            with self.assertRaises(resource.BrokerResourceError): self.issue()
        self.assertFalse(Path(first.description.display_path).exists())
    def test_tombstone_collision_cannot_reissue_token(self):
        first=self.issue(); self.consume(first)
        original=resource.BrokerFixtureOwner.describe
        def describe(owner):
            return replace(original(owner),resource_token=first.resource_token)
        with patch.object(resource.BrokerFixtureOwner,'describe',describe):
            with self.assertRaises(resource.BrokerResourceError): self.issue()
        with self.assertRaises(resource.BrokerResourceError): self.issue()

    def test_cleanup_failure_still_closes_every_owner(self):
        first,second=self.issue(),self.issue()
        original=resource.BrokerFixtureOwner.close
        def close(owner):
            original(owner)
            raise resource.BrokerResourceError('injected')
        with patch.object(resource.BrokerFixtureOwner,'close',close):
            with self.assertRaises(resource.BrokerResourceError): self.session.close()
        self.assertFalse(Path(first.description.display_path).exists())
        self.assertFalse(Path(second.description.display_path).exists())
        with self.assertRaises(resource.BrokerResourceError): self.consume(first)
