"""Inactive codec tests; no processes, reads or permission issuance."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import unittest
from unittest.mock import patch
from core.broker_binding_protocol import AcquisitionBindingExchange
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_protocol import BrokerProtocolError, _canonical
from core.test_broker_quarantine import context


class AcquisitionBindingTests(unittest.TestCase):
    def pair(self, **kwargs):
        values = dict(key=b'k'*32, session=b's'*32)
        values.update(kwargs)
        result = [AcquisitionBindingExchange(role=role, **values) for role in ('coordinator', 'broker')]
        for endpoint in result: self.addCleanup(endpoint.close)
        return result

    def message(self): return dict(context=context(), display_digest='a'*64)

    def bound(self):
        coordinator, broker = self.pair()
        message = self.message()
        first = coordinator.send(message)
        self.assertEqual(broker.receive(first), message)
        digest = hashlib.sha256(_canonical(message)).hexdigest()
        reply = broker.send(dict(outcome='bound', binding_digest=digest))
        coordinator.receive(reply)
        return coordinator, broker, digest

    def terminal(self, endpoint):
        self.assertEqual(endpoint._state, 'closed')
        self.assertEqual(endpoint._key, b'')
        self.assertIsNone(endpoint._digest)

    def test_retire_and_cancel_release_zero_bytes(self):
        for action in ('retire', 'cancel'):
            with self.subTest(action=action):
                c, b, digest = self.bound()
                command = dict(action=action, binding_digest=digest)
                self.assertEqual(b.receive(c.send(command)), command)
                result = c.receive(b.send(dict(**command, outcome='denied', lifecycle='retired', released_bytes=0)))
                self.assertEqual(result['released_bytes'], 0)
                self.assertNotIn('data', result)
                self.terminal(c); self.terminal(b)

    def test_read_release_and_approve_are_unsupported(self):
        for action in ('read', 'acquire', 'release', 'approve', 'allow_once', True):
            c, b, digest = self.bound()
            with self.assertRaises(BrokerProtocolError): c.send(dict(action=action, binding_digest=digest))
            self.terminal(c)

    def test_authority_injection_and_path_fields(self):
        for name in ('approved', 'authority', 'expires_at', 'path', 'handle'):
            c, _ = self.pair(); message = self.message(); message['context'][name] = True
            with self.assertRaises(BrokerProtocolError): c.send(message)
            self.terminal(c)

    def test_malformed_and_oversized_context(self):
        for name, value in [('max_bytes', True), ('max_bytes', 4097), ('application_id', 'x'*257),
                            ('draft_revision', 0), ('size_bytes', -1), ('volume_serial', 2**64),
                            ('file_id', 'x'*32), ('review_id', '2'*64), ('recipient', 'other'),
                            ('operation', 'files.write')]:
            c, _ = self.pair(); message = self.message(); message['context'][name] = value
            with self.assertRaises(BrokerProtocolError): c.send(message)
            self.terminal(c)

    def test_missing_context_field(self):
        c, _ = self.pair(); message = self.message(); del message['context']['grant_id']
        with self.assertRaises(BrokerProtocolError): c.send(message)

    def test_display_digest_validation(self):
        for value in (True, '', 'A'*64, 'a'*65, b'a'*64):
            c, _ = self.pair(); message = self.message(); message['display_digest'] = value
            with self.assertRaises(BrokerProtocolError): c.send(message)

    def test_caller_mutation_does_not_change_binding(self):
        c, b = self.pair(); message = self.message()
        digest = hashlib.sha256(_canonical(message)).hexdigest()
        frame = c.send(message); message['context']['application_id'] = 'other'
        decoded = b.receive(frame); decoded['context']['max_bytes'] = 4096
        c.receive(b.send(dict(outcome='bound', binding_digest=digest)))
        b.receive(c.send(dict(action='retire', binding_digest=digest)))

    def test_wrong_binding_digest(self):
        c, b = self.pair(); b.receive(c.send(self.message()))
        with self.assertRaises(BrokerProtocolError): b.send(dict(outcome='bound', binding_digest='f'*64))
        self.terminal(b)

    def test_forged_signed_changed_binding_is_rejected(self):
        c, b = self.pair(); b.receive(c.send(self.message()))
        frame = b._encode('reply', dict(step=1, previous=b._previous,
            message_json=_canonical(dict(outcome='bound', binding_digest='f'*64)).decode()))
        with self.assertRaises(BrokerProtocolError): c.receive(frame)
        self.terminal(c)

    def test_transcript_substitution(self):
        c, b = self.pair(); b.receive(c.send(self.message()))
        frame = b._encode('reply', dict(step=1, previous='f'*64,
            message_json=_canonical(dict(outcome='bound', binding_digest=b._digest)).decode()))
        with self.assertRaises(BrokerProtocolError): c.receive(frame)

    def test_duplicate_and_replay_are_terminal(self):
        c, b = self.pair(); frame = c.send(self.message()); b.receive(frame)
        with self.assertRaises(BrokerProtocolError): b.receive(frame)
        self.terminal(b)

    def test_wrong_role(self):
        _, b = self.pair()
        with self.assertRaises(BrokerProtocolError): b.send(self.message())
        self.terminal(b)

    def test_wrong_key_and_session(self):
        for options in (dict(key=b'x'*32), dict(session=b'x'*32)):
            c, _ = self.pair(); _, b = self.pair(**options)
            with self.assertRaises(BrokerProtocolError): b.receive(c.send(self.message()))
            self.terminal(b)

    def test_other_protocol_domain_cannot_consume_frame(self):
        c, _ = self.pair()
        peer = LiveMetadataExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(peer.close)
        with self.assertRaises(BrokerProtocolError): peer.receive(c.send(self.message()))

    def test_truncated_oversized_and_corrupt_frames(self):
        for mutate in (lambda f: f[:-1], lambda f: f+b'x', lambda f: b'x'*9000,
                       lambda f: f[:-1]+bytes([f[-1]^1])):
            c, b = self.pair()
            with self.assertRaises(BrokerProtocolError): b.receive(mutate(c.send(self.message())))
            self.terminal(b)

    def test_final_ack_cannot_include_bytes_or_allow(self):
        for changes in (dict(data='secret'), dict(outcome='allow'), dict(released_bytes=1), dict(released_bytes=False)):
            c, b, digest = self.bound(); command = dict(action='retire', binding_digest=digest)
            b.receive(c.send(command))
            final = dict(**command, outcome='denied', lifecycle='retired', released_bytes=0); final.update(changes)
            with self.assertRaises(BrokerProtocolError): b.send(final)
            self.terminal(b)

    def test_lost_initial_frame_does_not_allow_finish(self):
        c, b = self.pair(); c.send(self.message())
        with self.assertRaises(BrokerProtocolError): c.send(dict(action='retire', binding_digest='a'*64))
        self.terminal(c)
        b.close(); self.terminal(b)

    def test_lost_final_ack_cannot_be_recreated(self):
        c, b, digest = self.bound(); command = dict(action='cancel', binding_digest=digest)
        b.receive(c.send(command))
        final = dict(**command, outcome='denied', lifecycle='retired', released_bytes=0)
        b.send(final)  # Lost. No acknowledgement exists at coordinator.
        with self.assertRaises(BrokerProtocolError): b.send(final)
        c.close(); self.terminal(c)

    def test_idle_peer_disappearance_expires_both_endpoints(self):
        c, b = self.pair(timeout=.03); b.receive(c.send(self.message()))
        for endpoint in (c, b): endpoint._timer.join(1)
        self.terminal(c); self.terminal(b)

    def test_expiry_during_encoding_withholds_frame(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            frame = original(*args); c._deadline = 0; return frame
        with patch.object(c, '_encode', side_effect=encode):
            with self.assertRaises(BrokerProtocolError): c.send(self.message())
        self.terminal(c)

    def test_expiry_during_final_decoding_withholds_result(self):
        c, b, digest = self.bound(); command = dict(action='retire', binding_digest=digest)
        b.receive(c.send(command))
        frame = b.send(dict(**command, outcome='denied', lifecycle='retired', released_bytes=0))
        original = c._decode
        def decode(*args):
            value = original(*args); c._deadline = 0; return value
        with patch.object(c, '_decode', side_effect=decode):
            with self.assertRaises(BrokerProtocolError): c.receive(frame)
        self.terminal(c)

    def test_concurrent_first_sends_emit_at_most_one_frame(self):
        c, _ = self.pair()
        def attempt(_):
            try: c.send(self.message()); return 1
            except BrokerProtocolError: return 0
        with ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sum(pool.map(attempt, range(2))), 1)
        self.terminal(c)

    def test_cancellation_during_encoding_withholds_frame(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            frame = original(*args); c.close(); return frame
        with patch.object(c, '_encode', side_effect=encode):
            with self.assertRaises(BrokerProtocolError): c.send(self.message())
        self.terminal(c)

    def test_cancellation_during_final_decode_withholds_result(self):
        c, b, digest = self.bound(); command = dict(action='retire', binding_digest=digest)
        b.receive(c.send(command))
        frame = b.send(dict(**command, outcome='denied', lifecycle='retired', released_bytes=0))
        original = c._decode
        def decode(*args):
            value = original(*args); c.close(); return value
        with patch.object(c, '_decode', side_effect=decode):
            with self.assertRaises(BrokerProtocolError): c.receive(frame)
        self.terminal(c)

    def test_timer_start_failure_is_terminal(self):
        with patch('core.broker_binding_protocol.Timer.start', side_effect=RuntimeError('unavailable')):
            with self.assertRaises(BrokerProtocolError): self.pair()

    def test_cancel_close_at_every_phase(self):
        for phase in range(4):
            c, b = self.pair(); message = self.message()
            digest = hashlib.sha256(_canonical(message)).hexdigest()
            if phase >= 1: b.receive(c.send(message))
            if phase >= 2: c.receive(b.send(dict(outcome='bound', binding_digest=digest)))
            if phase >= 3: b.receive(c.send(dict(action='cancel', binding_digest=digest)))
            c.close(); b.close()
            for endpoint in (c, b):
                self.terminal(endpoint)
                with self.assertRaises(BrokerProtocolError): endpoint.send(message)

    def test_invalid_lifetimes(self):
        for timeout in (True, 0, -1, 6, float('nan'), float('inf'), '1'):
            with self.assertRaises(ValueError): self.pair(timeout=timeout)

    def test_legacy_single_exchange_methods_are_disabled(self):
        for name in ('request', 'accept_request', 'reply', 'accept_reply'):
            c, _ = self.pair()
            with self.assertRaises(BrokerProtocolError): getattr(c, name)({})
            self.terminal(c)
