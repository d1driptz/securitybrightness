"""Pure synthetic-byte tests; never launches a broker or opens a resource."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import time
import unittest
from unittest.mock import patch
from core import broker_quarantine as quarantine
from core.broker_protocol import BrokerProtocolError, FixtureBrokerExchange


def context(size=37):
    return dict(application_id='app', proposal_id='sbp2_sha256_'+'a'*64,
                grant_id='00000000-0000-4000-8000-000000000001', draft_id='00000000-0000-4000-8000-000000000002',
                draft_revision=1, review_id='1'*64, decision_id='2'*64,
                registry_session='3'*64, owner_session='4'*64, resource_token='5'*64,
                volume_serial=42, file_id='6'*32, size_bytes=size, max_bytes=max(1, size),
                operation='files.read', recipient='requesting_application')


class BrokerQuarantineTests(unittest.TestCase):
    def pair(self, timeout=5, key=b'k'*32, session=b's'*32):
        pair = [quarantine.QuarantinedReadExchange(role=role, key=key, session=session, timeout=timeout)
                for role in ('coordinator', 'broker')]
        for endpoint in pair: self.addCleanup(endpoint.close)
        return pair

    def opened(self, value=None, **kwargs):
        coordinator, broker = self.pair(**kwargs)
        broker.accept_request(coordinator.request(context() if value is None else value))
        return coordinator, broker

    def staged(self, size=37):
        coordinator, broker = self.opened(context(size))
        frame = broker.reply(outcome='staged', data=b'x'*size)
        summary = coordinator.accept_reply(frame)
        return coordinator, broker, frame, summary

    def terminal(self, endpoint):
        self.assertEqual(endpoint._state, 'closed')
        self.assertEqual(endpoint._buffer, bytearray())

    def test_staging_returns_only_metadata_then_authenticated_discard(self):
        coordinator, broker, frame, summary = self.staged()
        self.assertFalse(hasattr(summary, 'data'))
        self.assertEqual(summary.staged_bytes, 37)
        self.assertEqual(summary.staged_digest, hashlib.sha256(b'x'*37).hexdigest())
        with self.assertRaises(TypeError): bool(summary)
        self.assertEqual(bytes(coordinator._buffer), b'x'*37)
        broker.accept_discard(coordinator.discard())
        self.assertEqual(coordinator._buffer, bytearray())
        receipt = coordinator.accept_discard_ack(broker.acknowledge_discard())
        self.assertEqual(receipt.released_bytes, 0)
        self.assertFalse(hasattr(receipt, 'data'))
        with self.assertRaises(TypeError): bool(receipt)
        self.terminal(coordinator); self.terminal(broker)

    def test_denial_carries_no_bytes(self):
        coordinator, broker = self.opened()
        summary = coordinator.accept_reply(broker.reply(outcome='denied'))
        self.assertEqual(summary.staged_bytes, 0)
        self.assertEqual(coordinator._buffer, bytearray())
        broker.accept_discard(coordinator.discard())
        self.assertEqual(coordinator.accept_discard_ack(broker.acknowledge_discard()).released_bytes, 0)

    def test_denial_with_bytes_is_terminal(self):
        _, broker = self.opened()
        with self.assertRaises(BrokerProtocolError): broker.reply(outcome='denied', data=b'x')
        self.terminal(broker)

    def test_exact_zero_and_maximum_byte_boundaries(self):
        for size in (0, 1, 4095, 4096):
            with self.subTest(size=size):
                coordinator, broker, _, summary = self.staged(size)
                self.assertEqual(summary.staged_bytes, size)
                coordinator.close(); broker.close()
                self.terminal(coordinator)

    def test_partial_or_oversized_staging_is_terminal(self):
        for size in (0, 36, 38, 4097):
            _, broker = self.opened()
            with self.subTest(size=size), self.assertRaises(BrokerProtocolError): broker.reply(outcome='staged', data=b'x'*size)
            self.terminal(broker)

    def test_unknown_authority_effect_path_or_release_fields_are_rejected(self):
        for name in ('approved', 'human_approval', 'authority', 'path', 'reference', 'release', 'attributes'):
            coordinator, _ = self.pair()
            value = context(); value[name] = True
            with self.subTest(name=name), self.assertRaises(BrokerProtocolError): coordinator.request(value)
            self.terminal(coordinator)

    def test_type_confusion_and_malformed_binding(self):
        for name, value in [('draft_revision', True), ('size_bytes', True), ('volume_serial', True),
                            ('max_bytes', True), ('max_bytes', 4097), ('draft_revision', 0),
                            ('draft_revision', 2**31), ('volume_serial', 2**64), ('file_id', 'bad'),
                            ('grant_id', 'BAD'), ('recipient', 'other'), ('operation', 'files.write'),
                            ('application_id', ' app'), ('proposal_id', 'v1'), ('review_id', 'A'*64)]:
            coordinator, _ = self.pair(); payload = context(); payload[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(BrokerProtocolError): coordinator.request(payload)
            self.terminal(coordinator)

    def test_identifier_collisions_rejected(self):
        for field in ('review_id', 'registry_session', 'owner_session', 'resource_token'):
            coordinator, _ = self.pair(); value = context(); value[field] = value['decision_id']
            with self.assertRaises(BrokerProtocolError): coordinator.request(value)
        coordinator, _ = self.pair(); value = context(); value['grant_id'] = value['draft_id']
        with self.assertRaises(BrokerProtocolError): coordinator.request(value)

    def test_context_mutation_does_not_change_captured_request(self):
        coordinator, broker = self.pair(); value = context()
        frame = coordinator.request(value); value['max_bytes'] = 4096
        evidence = broker.accept_request(frame)
        self.assertEqual(evidence.inspect()['max_bytes'], 37)
        changed = evidence.inspect(); changed['max_bytes'] = 4096
        with self.assertRaises(BrokerProtocolError): broker.reply(outcome='staged', data=b'x'*4096)

    def test_mutation_between_context_capture_and_size_capture_uses_snapshot(self):
        coordinator, broker = self.pair(); value = context(); original = quarantine._context
        def capture(candidate):
            snapshot = original(candidate); candidate['size_bytes'] = 1; return snapshot
        with patch.object(quarantine, '_context', side_effect=capture): frame = coordinator.request(value)
        broker.accept_request(frame)
        summary = coordinator.accept_reply(broker.reply(outcome='staged', data=b'x'*37))
        self.assertEqual(summary.staged_bytes, 37)

    def test_validation_detaches_caller_dictionary(self):
        coordinator, broker = self.pair(); value = context(); original = quarantine._binding
        def validate(binding):
            result = original(binding); value['operation'] = 'files.write'; return result
        with patch.object(quarantine, '_binding', side_effect=validate): frame = coordinator.request(value)
        self.assertEqual(broker.accept_request(frame).inspect()['operation'], 'files.read')

    def test_changed_grant_draft_review_application_resource_effect_cannot_splice(self):
        for name, value in [('grant_id', '00000000-0000-4000-8000-000000000009'), ('draft_revision', 2),
                            ('review_id', '9'*64), ('application_id', 'other'), ('file_id', '9'*32),
                            ('resource_token', '9'*64), ('max_bytes', 128), ('proposal_id', 'sbp2_sha256_'+'9'*64)]:
            coordinator, _ = self.opened()
            changed = context(); changed[name] = value
            _, other = self.opened(changed)
            with self.subTest(name=name), self.assertRaises(BrokerProtocolError):
                coordinator.accept_reply(other.reply(outcome='staged', data=b'x'*37))
            self.terminal(coordinator)

    def test_replay_after_staging_clears_buffer(self):
        coordinator, _, frame, _ = self.staged()
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
        self.terminal(coordinator)

    def test_out_of_order_discard_fails_closed(self):
        coordinator, _ = self.opened()
        with self.assertRaises(BrokerProtocolError): coordinator.discard()
        self.terminal(coordinator)

    def test_wrong_role_after_staging_clears_buffer(self):
        coordinator, _, _, _ = self.staged()
        with self.assertRaises(BrokerProtocolError): coordinator.reply(outcome='staged', data=b'x'*37)
        self.terminal(coordinator)

    def test_close_is_irreversible_and_clears_buffer(self):
        coordinator, _, _, _ = self.staged(); coordinator.close()
        self.terminal(coordinator)
        with self.assertRaises(BrokerProtocolError): coordinator.request(context())

    def test_idle_expiry_clears_retained_buffer(self):
        coordinator, broker = self.opened(timeout=.03)
        coordinator.accept_reply(broker.reply(outcome='staged', data=b'x'*37))
        deadline = time.monotonic()+1
        while coordinator._state != 'closed' and time.monotonic() < deadline: time.sleep(.005)
        self.terminal(coordinator)

    def test_expiry_during_frame_validation_never_returns_summary(self):
        coordinator, broker = self.opened(); frame = broker.reply(outcome='staged', data=b'x'*37)
        original = coordinator._stage
        clock = [coordinator._deadline-1]
        def stage(*args):
            result = original(*args); clock[0] = coordinator._deadline; return result
        with patch.object(coordinator, '_stage', side_effect=stage), patch.object(quarantine, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
        self.terminal(coordinator)

    def test_release_or_commit_commands_are_rejected_even_when_signed(self):
        for action in ('release', 'commit', 'read', 'allow'):
            coordinator, broker, _, _ = self.staged()
            message = coordinator._discard_message(); message['action'] = action
            with self.assertRaises(BrokerProtocolError): broker.accept_discard(coordinator._frame('request', message))
            self.terminal(broker)
            coordinator.close(); self.terminal(coordinator)

    def test_release_ack_and_bool_count_are_rejected_even_when_signed(self):
        for changes in (dict(outcome='released'), dict(released_bytes=37), dict(released_bytes=False), dict(data='secret')):
            coordinator, broker, _, _ = self.staged(); broker.accept_discard(coordinator.discard())
            message = broker._ack(); message.update(changes)
            with self.assertRaises(BrokerProtocolError): coordinator.accept_discard_ack(broker._frame('reply', message))
            self.terminal(coordinator)

    def test_noncanonical_or_invalid_base64_is_rejected(self):
        for encoded in ('@@', 'eA==\n', 'eB==', 'x'*5465):
            coordinator, broker = self.opened(context(1))
            message = dict(binding_digest=broker._binding_digest, outcome='staged', data=encoded)
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker._frame('reply', message))
            self.terminal(coordinator)

    def test_signed_data_on_deny_is_rejected(self):
        coordinator, broker = self.opened()
        message = dict(binding_digest=broker._binding_digest, outcome='denied', data=base64.b64encode(b'secret').decode())
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker._frame('reply', message))
        self.terminal(coordinator)

    def test_wrong_mac_or_session_is_terminal(self):
        for option in (dict(key=b'z'*32), dict(session=b'z'*32)):
            coordinator, _ = self.opened()
            _, broker = self.opened(**option)
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker.reply(outcome='staged', data=b'x'*37))
            self.terminal(coordinator)

    def test_old_read_codec_domain_cannot_stage(self):
        coordinator, _ = self.opened()
        old = FixtureBrokerExchange(role='broker', key=b'k'*32, session=b's'*32)
        frame = old._encode('reply', dict(outcome='buffered', data=''))
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
        self.terminal(coordinator)

    def test_concurrent_discard_is_single_use(self):
        coordinator, _, _, _ = self.staged()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(coordinator.discard) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.terminal(coordinator)

    def test_discard_ack_replay_never_restores_buffer(self):
        coordinator, broker, _, _ = self.staged(); broker.accept_discard(coordinator.discard())
        ack = broker.acknowledge_discard(); coordinator.accept_discard_ack(ack)
        with self.assertRaises(BrokerProtocolError): coordinator.accept_discard_ack(ack)
        self.terminal(coordinator)

    def test_invalid_lifetime_and_oversized_frames(self):
        for value in (True, 0, -1, 6, float('inf'), float('nan')):
            with self.assertRaises(ValueError): self.pair(timeout=value)
        coordinator, _ = self.opened()
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(b'x'*9000)
        self.terminal(coordinator)

    def test_oversized_lifecycle_identity_rejected_before_uuid_parsing(self):
        coordinator, _ = self.pair(); value = context(); value['grant_id'] = 'x'*10000
        with patch.object(quarantine, 'UUID') as parse:
            with self.assertRaises(BrokerProtocolError): coordinator.request(value)
            parse.assert_not_called()
        self.terminal(coordinator)

    def test_signed_version_or_sequence_confusion_is_rejected(self):
        for step in (True, 0, 2):
            coordinator, broker = self.opened()
            message = dict(binding_digest=broker._binding_digest, outcome='denied', data='')
            frame = broker._encode('reply', dict(step=step, previous=broker._previous,
                                                 message_json=quarantine._canonical(message).decode()))
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
            self.terminal(coordinator)

    def test_no_release_or_executor_api_exists(self):
        coordinator, _, _, summary = self.staged()
        for name in ('release', 'commit', 'execute', 'read', 'data', 'take_buffer'):
            self.assertFalse(hasattr(coordinator, name))
        self.assertNotIn('data', asdict(summary))
