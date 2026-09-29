import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
import unittest

from core.broker_protocol import FixtureBrokerExchange, BrokerProtocolError


class BrokerProtocolTests(unittest.TestCase):
    def pair(self, *, session=b's' * 32, key=b'k' * 32):
        return (FixtureBrokerExchange(role='coordinator', key=key, session=session),
                FixtureBrokerExchange(role='broker', key=key, session=session))

    def binding(self):
        return dict(application_id='fixture-app', proposal_id='sbp2_sha256_' + 'a' * 64,
                    resource_token='b' * 64, decision_id='c' * 64, max_bytes=4096)

    def ready(self):
        coordinator, broker = self.pair()
        broker.accept_request(coordinator.request(self.binding()))
        return coordinator, broker

    def test_exact_roundtrip_returns_staged_evidence_not_permission(self):
        coordinator, broker = self.pair()
        evidence = broker.accept_request(coordinator.request(self.binding()))
        self.assertEqual(evidence.inspect(), self.binding())
        with self.assertRaises(TypeError):
            bool(evidence)
        result = coordinator.accept_reply(broker.reply(outcome='buffered', data=b'fixture'))
        self.assertEqual(result.data, b'fixture')
        with self.assertRaises(TypeError):
            bool(result)
        with self.assertRaises(FrozenInstanceError):
            result.outcome = 'allow'
        self.assertNotIn('fixture', repr(result))

    def test_deny_can_never_carry_protected_bytes(self):
        coordinator, broker = self.ready()
        result = coordinator.accept_reply(broker.reply(outcome='denied'))
        self.assertEqual(result.data, b'')
        self.assertEqual(result.outcome, 'denied')
        _, broker = self.ready()
        with self.assertRaises(BrokerProtocolError):
            broker.reply(outcome='denied', data=b'leak')
        with self.assertRaises(BrokerProtocolError):
            broker.reply(outcome='denied')

    def test_request_snapshot_is_detached_from_input_and_inspection_mutation(self):
        coordinator, broker = self.pair()
        binding = self.binding()
        frame = coordinator.request(binding)
        binding['application_id'] = 'other'
        evidence = broker.accept_request(frame)
        inspected = evidence.inspect()
        inspected['max_bytes'] = 1
        self.assertEqual(evidence.inspect(), self.binding())
        self.assertEqual(coordinator.accept_reply(broker.reply(outcome='buffered', data=b'x' * 100)).data, b'x' * 100)

    def test_reply_and_request_replay_are_terminal(self):
        coordinator, broker = self.pair()
        frame = coordinator.request(self.binding())
        broker.accept_request(frame)
        with self.assertRaises(BrokerProtocolError):
            broker.accept_request(frame)
        with self.assertRaises(BrokerProtocolError):
            broker.reply(outcome='denied')
        coordinator, broker = self.ready()
        frame = broker.reply(outcome='buffered', data=b'x')
        coordinator.accept_reply(frame)
        with self.assertRaises(BrokerProtocolError):
            coordinator.accept_reply(frame)
        with self.assertRaises(BrokerProtocolError):
            coordinator.request(self.binding())

    def test_tampering_truncation_extra_frames_and_huge_prefix_fail_closed(self):
        source, _ = self.pair()
        frame = source.request(self.binding())
        attacks = [b'', None, bytearray(frame), frame[:-1], frame + b'x', frame + frame,
                   b'\xff' * 4 + frame[4:], frame[:5] + bytes([frame[5] ^ 1]) + frame[6:],
                   frame[:-1] + bytes([frame[-1] ^ 1]), b'x' * 10000]
        for bad in attacks:
            _, target = self.pair()
            with self.subTest(attack=type(bad)), self.assertRaises(BrokerProtocolError):
                target.accept_request(bad)
            with self.assertRaises(BrokerProtocolError):
                target.accept_request(frame)

    def test_keys_sessions_and_direction_cannot_be_substituted(self):
        coordinator, _ = self.pair()
        frame = coordinator.request(self.binding())
        for options in [dict(key=b'z' * 32), dict(session=b'z' * 32)]:
            _, target = self.pair(**options)
            with self.assertRaises(BrokerProtocolError):
                target.accept_request(frame)
        with self.assertRaises(BrokerProtocolError):
            coordinator.accept_reply(frame)  # Reflection is not a broker reply.

    def test_each_binding_field_is_matched_even_with_valid_peer_mac(self):
        for key, value in [('application_id', 'other'), ('proposal_id', 'sbp2_sha256_' + 'd' * 64),
                           ('resource_token', 'd' * 64), ('decision_id', 'd' * 64), ('max_bytes', 4095)]:
            coordinator, broker = self.ready()
            binding = self.binding()
            binding[key] = value
            forged = broker._encode('reply', dict(binding=binding, outcome='buffered', data='eA=='))
            with self.subTest(key=key), self.assertRaises(BrokerProtocolError):
                coordinator.accept_reply(forged)

    def test_byte_boundaries_and_type_confusion(self):
        for data in [b'', b'x', b'x' * 4096]:
            coordinator, broker = self.ready()
            self.assertEqual(coordinator.accept_reply(broker.reply(outcome='buffered', data=data)).data, data)
        for data in [b'x' * 4097, bytearray(b'x'), 'x', None]:
            _, broker = self.ready()
            with self.assertRaises(BrokerProtocolError):
                broker.reply(outcome='buffered', data=data)
        for limit in [True, 0, -1, 4097, 1.0, '1']:
            coordinator, _ = self.pair()
            with self.assertRaises(BrokerProtocolError):
                coordinator.request({**self.binding(), 'max_bytes': limit})

    def test_unsupported_fields_authority_injection_paths_and_invalid_identity(self):
        for key in ['approved', 'grant_id', 'path', 'operation', 'callback']:
            coordinator, _ = self.pair()
            with self.assertRaises(BrokerProtocolError):
                coordinator.request({**self.binding(), key: 'injected'})
        for key, value in [('application_id', '\ud800'), ('application_id', 'x' * 257),
                           ('application_id', 'a\n'), ('resource_token', 'C:/file'),
                           ('decision_id', 'A' * 64), ('proposal_id', 'legacy')]:
            coordinator, _ = self.pair()
            with self.assertRaises(BrokerProtocolError):
                coordinator.request({**self.binding(), key: value})

    def test_signed_malformed_json_versions_and_schema_are_rejected(self):
        for mutate in [lambda v: {**v, 'version': True}, lambda v: {**v, 'version': 2},
                       lambda v: {**v, 'extra': 1}, lambda v: {**v, 'payload': []}]:
            _, broker = self.pair()
            body = json.dumps(mutate(dict(version=1, session=(b's' * 32).hex(), direction='request',
                                         payload=self.binding())), sort_keys=True, separators=(',', ':')).encode()
            raw = body + broker._mac('request', body)
            with self.assertRaises(BrokerProtocolError):
                broker.accept_request(len(raw).to_bytes(4, 'big') + raw)
        for body in [b'{"version":1,"version":1}', b'{"version":NaN}', b'[' * 500 + b']' * 500]:
            _, broker = self.pair()
            raw = body + broker._mac('request', body)
            with self.assertRaises(BrokerProtocolError):
                broker.accept_request(len(raw).to_bytes(4, 'big') + raw)

    def test_signed_bad_reply_encoding_and_denial_payload_fail_closed(self):
        for outcome, data in [('allow', ''), ('denied', 'eA=='), ('buffered', 'eB=='),
                               ('buffered', 'eA==\n'), ('buffered', True), ('buffered', '!' * 20),
                               ('buffered', base64.b64encode(b'x' * 4097).decode())]:
            coordinator, broker = self.ready()
            frame = broker._encode('reply', dict(binding=self.binding(), outcome=outcome, data=data))
            with self.assertRaises(BrokerProtocolError):
                coordinator.accept_reply(frame)

    def test_close_bad_order_and_role_misuse_cannot_be_recovered(self):
        coordinator, broker = self.pair()
        with self.assertRaises(BrokerProtocolError):
            broker.request(self.binding())
        coordinator.close()
        with self.assertRaises(BrokerProtocolError):
            coordinator.request(self.binding())
        with self.assertRaises(BrokerProtocolError):
            broker.accept_request(b'')
        _, broker = self.pair()
        with self.assertRaises(BrokerProtocolError):
            broker.reply(outcome='denied')

    def test_concurrent_reply_consumption_returns_at_most_one_buffer(self):
        coordinator, broker = self.ready()
        frame = broker.reply(outcome='buffered', data=b'fixture')
        def consume(_):
            try:
                return coordinator.accept_reply(frame).data
            except BrokerProtocolError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, range(2)))
        self.assertEqual(results.count(b'fixture'), 1)
        self.assertEqual(results.count(None), 1)

    def test_bootstrap_types_and_lengths_are_strict(self):
        for arguments in [dict(role='application', key=b'k' * 32, session=b's' * 32),
                          dict(role='broker', key=b'k' * 31, session=b's' * 32),
                          dict(role='broker', key=bytearray(b'k' * 32), session=b's' * 32),
                          dict(role='broker', key=b'k' * 32, session='s' * 32)]:
            with self.assertRaises(BrokerProtocolError):
                FixtureBrokerExchange(**arguments)


if __name__ == '__main__':
    unittest.main()
