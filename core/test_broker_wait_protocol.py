"""Inactive bounded-wait codec tests; synthetic claims never human permission."""
import base64
from dataclasses import asdict
import hashlib
import unittest

from core import broker_wait_protocol as wait_protocol
from core import test_broker_publication_protocol as publication_tests
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_protocol import BrokerProtocolError
from core.broker_publication_protocol import PublicationCheckExchange
from core.file_read_schema import make_file_read_proposal
from core.test_broker_live import observed
from core.test_broker_quarantine import context


class WaitAcquisitionProtocolTests(publication_tests.PublicationProtocolTests):
    """Run the complete existing quarantine invariants against the new domain."""

    def pair(self, timeout=5, key=b'k'*32, session=b's'*32):
        endpoints = [wait_protocol._WaitAcquisitionExchange(
            role=role, key=key, session=session, timeout=timeout)
            for role in ('coordinator', 'broker')]
        for endpoint in endpoints:
            self.addCleanup(endpoint.close)
        return endpoints

    def test_old_publication_request_cannot_enter_wait_profile(self):
        _, broker = self.pair()
        old = PublicationCheckExchange(role='coordinator', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError):
            broker.accept_request(old.request(context(), publication_tests.recipient()))
        self.terminal(broker)

    def test_new_request_cannot_enter_old_publication_profile(self):
        coordinator, _ = self.pair()
        old = PublicationCheckExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError):
            old.accept_request(coordinator.request(context(), publication_tests.recipient()))
        self.terminal(old)

    def test_old_publication_reply_and_ack_cannot_enter_wait_profile(self):
        for phase in ('reply', 'ack'):
            with self.subTest(phase=phase):
                coordinator, broker, _ = self.opened()
                if phase == 'reply':
                    value = dict(binding_digest=broker._binding_digest, outcome='staged',
                        data=base64.b64encode(b'x'*37).decode())
                    direction = 'reply'
                else:
                    coordinator.accept_reply(broker.reply(outcome='staged', data=b'x'*37))
                    broker.accept_retirement(coordinator.retire_for_check())
                    value = broker._retirement_ack()
                    direction = 'reply'
                old = PublicationCheckExchange(role='broker', key=b'k'*32, session=b's'*32)
                self.addCleanup(old.close)
                # Use the genuine current transcript position, but the old MAC
                # domain. Validating a domain is independent of claimed fields.
                old._step, old._previous = broker._step, broker._previous
                frame = old._frame(direction, value)
                method = coordinator.accept_reply if phase == 'reply' else coordinator.accept_retirement_ack
                with self.assertRaises(BrokerProtocolError):
                    method(frame)
                self.terminal(coordinator)

    def test_wait_opening_domain_cannot_create_acquisition_frame(self):
        coordinator, broker = self.pair()
        opening = wait_protocol._WaitOpeningExchange(role='coordinator', key=b'k'*32, session=b's'*32)
        self.addCleanup(opening.close)
        frame = opening._encode('request', dict(step=0, previous='0'*64, message_json='{}'))
        with self.assertRaises(BrokerProtocolError):
            broker.accept_request(frame)
        self.terminal(broker)

    def test_metadata_and_retirement_evidence_expose_no_permission_or_delivery(self):
        coordinator, _, _, summary, receipt = self.retired()
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(summary.staged_bytes, 37)
        self.assertEqual(summary.staged_digest, hashlib.sha256(b'x'*37).hexdigest())
        for evidence in (summary, receipt):
            self.assertNotIn('permission', asdict(evidence))
            self.assertNotIn('data', asdict(evidence))
            with self.assertRaises(TypeError):
                bool(evidence)
        for name in ('authorize', 'allow', 'publish', 'release', 'read', 'execute'):
            self.assertFalse(hasattr(coordinator, name))


class WaitOpeningProtocolTests(unittest.TestCase):
    def pair(self):
        endpoints = [wait_protocol._WaitOpeningExchange(role=role, key=b'k'*32, session=b's'*32)
            for role in ('coordinator', 'broker')]
        for endpoint in endpoints:
            self.addCleanup(endpoint.close)
        return endpoints

    def request(self):
        return dict(application_id='app', decision_id='2'*64,
            proposal_json=make_file_read_proposal('unverified fixture label', max_bytes=128).canonical_bytes().decode())

    def test_open_and_observe_are_metadata_without_authorization(self):
        coordinator, broker = self.pair()
        self.assertEqual(broker.receive(coordinator.send(self.request())), self.request())
        metadata = coordinator.receive(broker.send(observed()))
        self.assertEqual(metadata, observed())
        self.assertNotIn('permission', metadata)
        self.assertNotIn('data', metadata)
        for name in ('authorize', 'allow', 'publish', 'release', 'read', 'execute'):
            self.assertFalse(hasattr(broker, name))

    def test_original_live_opening_is_rejected(self):
        _, broker = self.pair()
        old = LiveMetadataExchange(role='coordinator', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError):
            broker.receive(old.send(self.request()))
        self.assertEqual(broker._state, 'closed')

    def test_wait_opening_is_rejected_by_original_live_profile(self):
        coordinator, _ = self.pair()
        old = LiveMetadataExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError):
            old.receive(coordinator.send(self.request()))
        self.assertEqual(old._state, 'closed')

    def test_old_live_observation_cannot_pass_new_opening_domain(self):
        coordinator, broker = self.pair()
        broker.receive(coordinator.send(self.request()))
        old = LiveMetadataExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        old._step, old._previous = broker._step, broker._previous
        frame = old.send(observed())
        with self.assertRaises(BrokerProtocolError):
            coordinator.receive(frame)
        self.assertEqual(coordinator._state, 'closed')

    def test_malformed_or_requester_authority_opening_is_terminal(self):
        for bad in (None, {}, bytearray(b'x'*100), b'x'*9000, b'\0'*36):
            _, broker = self.pair()
            with self.subTest(value=type(bad).__name__), self.assertRaises(BrokerProtocolError):
                broker.receive(bad)
            self.assertEqual(broker._state, 'closed')
        for field, value in (('approved', True), ('expires_at', 'never'), ('resource_identity', 'verified')):
            coordinator, _ = self.pair()
            request = self.request(); request[field] = value
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                coordinator.send(request)
            self.assertEqual(coordinator._state, 'closed')

    def test_opening_replay_cannot_create_second_observation(self):
        coordinator, broker = self.pair()
        first = coordinator.send(self.request()); broker.receive(first)
        with self.assertRaises(BrokerProtocolError):
            broker.receive(first)
        self.assertEqual(broker._state, 'closed')

    def test_wrong_key_or_session_opening_rejects(self):
        for field in ('key', 'session'):
            _, broker = self.pair()
            values = dict(key=b'k'*32, session=b's'*32); values[field] = b'x'*32
            foreign = wait_protocol._WaitOpeningExchange(role='coordinator', **values)
            self.addCleanup(foreign.close)
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                broker.receive(foreign.send(self.request()))
            self.assertEqual(broker._state, 'closed')
