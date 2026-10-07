"""Adversarial synthetic-only framing; no resource or authorization activity."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, FrozenInstanceError
import hashlib
import unittest
from threading import RLock
from unittest.mock import patch

from core import broker_synthetic_payload_protocol as protocol
from core.broker_protocol import BrokerProtocolError, MAX_BODY_BYTES, MAX_DATA_BYTES, _canonical
from core.broker_dispatch_model_protocol import PublicationDispatchExchange
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.json_input import loads
from core.test_broker_dispatch_model_protocol import binding as dispatch_binding
from core.test_broker_publication_commit_protocol import envelope as commit_binding
from core.test_broker_recipient_protocol import binding as witness_binding


DATA = b'Harmless generated synthetic transport fixture\n'


def envelope(data=DATA, *, session=b's'*32):
    return dict(revision=1, mode='synthetic_transport_discard_only', transport_id='a'*64,
                fixture_id='b'*64, byte_count=len(data), digest=hashlib.sha256(data).hexdigest(),
                channel=dict(pid=123, creation_time=456, witness_session=session.hex()))


class SyntheticPayloadProtocolTests(unittest.TestCase):
    def pair(self, **options):
        values = dict(key=b'k'*32, session=b's'*32); values.update(options)
        pair = [protocol.SyntheticPayloadExchange(role=role, **values) for role in ('coordinator', 'broker')]
        for endpoint in pair: self.addCleanup(endpoint.close)
        return pair

    def prepared(self, data=DATA, *, value=None):
        c, b = self.pair(); self.prepare_frame = c.prepare(envelope(data) if value is None else value)
        self.prepare_evidence = b.accept_prepare(self.prepare_frame)
        self.ready_frame = b.ready(); self.ready_evidence = c.accept_ready(self.ready_frame)
        return c, b

    def buffered(self, data=DATA):
        c, b = self.prepared(data); self.payload_frame = c.payload(data)
        self.payload_evidence = b.accept_payload(self.payload_frame)
        return c, b

    def terminal(self, endpoint):
        self.assertEqual((endpoint._state, endpoint._step, endpoint._key), ('closed', 4, b''))
        for name in ('_binding', '_binding_snapshot', '_binding_digest', '_buffer', '_issued_buffer',
                     '_recovery_buffer', '_buffer_snapshot'):
            self.assertIsNone(getattr(endpoint, name))

    def rejects(self, endpoint, operation):
        with self.assertRaisesRegex(BrokerProtocolError, '^synthetic_payload_rejected$'): operation()
        self.terminal(endpoint)

    def test_complete_exchange_has_no_data_or_permission_evidence(self):
        c, b = self.buffered(); original = b._buffer
        self.assertEqual(original, DATA)
        self.assertIsNone(b.discard()); self.assertEqual(original, b'')
        result = c.accept_receipt(b.receipt())
        for evidence, outcome in ((self.prepare_evidence, 'requested'), (self.ready_evidence, 'prepared'),
                                  (self.payload_evidence, 'buffered_private'), (result, 'peer_discarded')):
            self.assertIs(type(evidence), protocol.SyntheticPayloadEvidence)
            self.assertEqual(evidence.inspect(), envelope())
            self.assertEqual((evidence.byte_count, evidence.digest), (len(DATA), hashlib.sha256(DATA).hexdigest()))
            self.assertEqual(evidence.outcome, outcome)
            self.assertEqual(evidence.meaning, protocol._MEANING)
            self.assertNotIn('data', asdict(evidence)); self.assertNotIn('released_bytes', asdict(evidence))
            self.assertNotIn('canonical_binding', repr(evidence))
            with self.assertRaises(TypeError): bool(evidence)
            with self.assertRaises(FrozenInstanceError): evidence.outcome = 'authorized'
        self.terminal(c); self.terminal(b)

    def test_all_byte_boundaries_and_arbitrary_binary_are_exact(self):
        for count in (0, 1, 4095, MAX_DATA_BYTES):
            data = bytes(index % 256 for index in range(count))
            with self.subTest(count=count):
                c, b = self.buffered(data); original = b._buffer; b.discard()
                result = c.accept_receipt(b.receipt())
                self.assertEqual(result.byte_count, count); self.assertEqual(result.digest, hashlib.sha256(data).hexdigest())
                self.assertEqual(original, b''); self.assertLessEqual(len(self.payload_frame), MAX_BODY_BYTES+36)

    def test_input_binding_and_inspection_are_detached(self):
        c, b = self.pair(); value = envelope(); frame = c.prepare(value)
        value['channel']['pid'] = 999; value['fixture_id'] = 'c'*64
        result = b.accept_prepare(frame); detached = result.inspect(); detached['channel']['pid'] = 1000
        self.assertEqual(result.inspect(), envelope()); self.assertEqual(loads(c._binding_snapshot), envelope())

    def test_invalid_bootstrap_exact_types_and_lengths(self):
        for name, value in (('role', True), ('role', 'requester'), ('key', bytearray(32)), ('key', 'k'*32),
                            ('key', b'k'*31), ('key', b'k'*33), ('session', bytearray(32)),
                            ('session', 's'*32), ('session', b's'*31), ('session', b's'*33)):
            options = dict(role='coordinator', key=b'k'*32, session=b's'*32); options[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(BrokerProtocolError):
                protocol.SyntheticPayloadExchange(**options)

    def test_secret_key_cannot_be_public_session(self):
        for role in ('coordinator', 'broker'):
            with self.subTest(role=role), self.assertRaisesRegex(BrokerProtocolError, '^invalid_bootstrap$'):
                protocol.SyntheticPayloadExchange(role=role, key=b'k'*32, session=b'k'*32)

    def test_envelope_container_and_subclasses_are_rejected(self):
        class Mapping(dict): pass
        for value in (None, True, [], (), envelope().items(), Mapping(envelope())):
            c, _ = self.pair(); self.rejects(c, lambda: c.prepare(value))
        c, _ = self.pair(); value = envelope(); value['channel'] = Mapping(value['channel'])
        self.rejects(c, lambda: c.prepare(value))

    def test_every_missing_and_unsupported_field_is_rejected(self):
        for name in envelope():
            c, _ = self.pair(); value = envelope(); del value[name]
            with self.subTest(missing=name): self.rejects(c, lambda: c.prepare(value))
        for name in ('authority', 'approval', 'grant_id', 'application_id', 'proposal_id', 'path', 'callback',
                     'data', 'expires_at', 'recipient', 'effects', 'allow_once', 'released_bytes'):
            c, _ = self.pair(); value = envelope(); value[name] = True
            with self.subTest(extra=name): self.rejects(c, lambda: c.prepare(value))
        for name in envelope()['channel']:
            c, _ = self.pair(); value = envelope(); del value['channel'][name]
            self.rejects(c, lambda: c.prepare(value))
        c, _ = self.pair(); value = envelope(); value['channel']['trusted'] = True
        self.rejects(c, lambda: c.prepare(value))

    def test_revision_mode_count_and_digest_exact_types(self):
        for name, bad in (('revision', True), ('revision', 1.0), ('revision', 2), ('mode', True),
                ('mode', 'publish'), ('mode', 'dry_run_discard_only'), ('mode', 'dispatch_model_only'),
                ('byte_count', True), ('byte_count', -1), ('byte_count', 4097), ('byte_count', 1.0),
                ('byte_count', '37'), ('digest', b'f'*64), ('digest', 'F'*64), ('digest', 'f'*63)):
            c, _ = self.pair(); value = envelope(); value[name] = bad
            with self.subTest(name=name, bad=bad): self.rejects(c, lambda: c.prepare(value))

    def test_identifier_bounds_and_collision(self):
        for name in ('transport_id', 'fixture_id'):
            for bad in (None, True, b'a'*64, 'A'*64, 'g'*64, 'a'*63, 'a'*65, 'a'*(MAX_BODY_BYTES+1), '\ud800'):
                c, _ = self.pair(); value = envelope(); value[name] = bad
                self.rejects(c, lambda: c.prepare(value))
        for mutate in (lambda v: v.update(transport_id=v['fixture_id']),
                       lambda v: v.update(transport_id=v['channel']['witness_session']),
                       lambda v: v.update(fixture_id=v['channel']['witness_session'])):
            c, _ = self.pair(); value = envelope(); mutate(value); self.rejects(c, lambda: c.prepare(value))

    def test_native_channel_fields_are_only_bounded_metadata(self):
        for name, bad in (('pid', True), ('pid', 0), ('pid', -1), ('pid', 0x100000000), ('pid', 1.0),
                         ('creation_time', True), ('creation_time', 0), ('creation_time', 0x10000000000000000),
                         ('witness_session', 'F'*64), ('witness_session', b'f'*64), ('witness_session', 'f'*64)):
            c, _ = self.pair(); value = envelope(); value['channel'][name] = bad
            self.rejects(c, lambda: c.prepare(value))
        c, b = self.pair(); value = envelope(); value['channel'].update(pid=0xffffffff, creation_time=0xffffffffffffffff)
        b.accept_prepare(c.prepare(value))  # The codec cannot attest native identity.

    def test_empty_count_requires_empty_digest(self):
        c, _ = self.pair(); value = envelope(b''); value['digest'] = hashlib.sha256(DATA).hexdigest()
        self.rejects(c, lambda: c.prepare(value))

    def test_sender_payload_type_length_digest_and_oversize_rejected(self):
        class Bytes(bytes): pass
        for bad in (None, True, bytearray(DATA), memoryview(DATA), DATA.decode(), Bytes(DATA), b'', DATA+b'x',
                    b'x'*len(DATA), b'x'*4097):
            c, _ = self.prepared(); self.rejects(c, lambda: c.payload(bad))

    def test_receiver_payload_has_exact_effect_fields(self):
        for name, bad in (('revision', True), ('revision', 2), ('mode', 'publish'), ('binding_digest', 'f'*64),
                ('byte_count', True), ('byte_count', len(DATA)-1), ('digest', 'f'*64), ('data', True),
                ('data', 'x'*5465), ('data', None), ('authority', True), ('released_bytes', len(DATA))):
            c, b = self.prepared(); frame = c.payload(DATA); message = b._message('request', frame)
            message[name] = bad; self.rejects(b, lambda: b.accept_payload(b._frame('request', message)))
        for name in ('revision', 'mode', 'binding_digest', 'byte_count', 'digest', 'data'):
            c, b = self.prepared(); frame = c.payload(DATA); message = b._message('request', frame); del message[name]
            self.rejects(b, lambda: b.accept_payload(b._frame('request', message)))

    def test_receiver_base64_is_canonical_and_exact(self):
        encoded = base64.b64encode(DATA).decode('ascii')
        for bad in (encoded+'\n', ' '+encoded, encoded+'=', encoded.rstrip('='), '!!!!', '-___',
                    base64.b64encode(b'x'*len(DATA)).decode('ascii'), base64.b64encode(DATA+b'x').decode('ascii')):
            if bad == encoded: continue
            c, b = self.prepared(); frame = c.payload(DATA); message = b._message('request', frame); message['data'] = bad
            self.rejects(b, lambda: b.accept_payload(b._frame('request', message)))
        # Non-zero padding bits decode to the same byte but are not canonical.
        c, b = self.prepared(b'a'); frame = c.payload(b'a'); message = b._message('request', frame); message['data'] = 'YR=='
        self.rejects(b, lambda: b.accept_payload(b._frame('request', message)))

    def test_receipt_before_discard_rejects_and_wipes(self):
        _, b = self.buffered(); original = b._buffer
        self.rejects(b, b.receipt); self.assertEqual(original, b'')

    def test_discard_cannot_be_replayed_or_used_in_wrong_phase(self):
        _, b = self.pair(); self.rejects(b, b.discard)
        c, b = self.prepared(); self.rejects(b, b.discard)
        c, b = self.buffered(); b.discard(); self.rejects(b, b.discard)
        c, b = self.buffered(); self.rejects(c, c.discard)

    def test_all_message_replays_are_terminal(self):
        c, b = self.prepared(); self.rejects(b, lambda: b.accept_prepare(self.prepare_frame))
        c, b = self.prepared(); self.rejects(c, lambda: c.accept_ready(self.ready_frame))
        c, b = self.buffered(); original = b._buffer
        self.rejects(b, lambda: b.accept_payload(self.payload_frame)); self.assertEqual(original, b'')
        c, b = self.buffered(); b.discard(); frame = b.receipt(); c.accept_receipt(frame)
        self.rejects(c, lambda: c.accept_receipt(frame)); self.rejects(b, b.receipt)

    def test_lost_receipt_does_not_allow_retry_or_repeated_payload(self):
        c, b = self.buffered(); b.discard(); b.receipt()  # Intentionally not delivered.
        self.terminal(b); self.rejects(c, lambda: c.payload(DATA)); self.rejects(b, b.receipt)

    def test_close_after_buffering_wipes_original_and_is_idempotent(self):
        c, b = self.buffered(); original = b._buffer; b.close(); b.close(); c.close(); c.close()
        self.assertEqual(original, b''); self.terminal(b); self.terminal(c)

    def test_wrong_roles_and_phases_are_terminal(self):
        operations = (('broker', lambda e: e.prepare(envelope())), ('coordinator', lambda e: e.accept_prepare(b'')),
                      ('coordinator', lambda e: e.ready()), ('broker', lambda e: e.accept_ready(b'')),
                      ('broker', lambda e: e.payload(DATA)), ('coordinator', lambda e: e.accept_payload(b'')),
                      ('coordinator', lambda e: e.receipt()), ('broker', lambda e: e.accept_receipt(b'')))
        for role, operation in operations:
            c, b = self.pair(); endpoint = c if role == 'coordinator' else b
            self.rejects(endpoint, lambda: operation(endpoint))
        c, b = self.pair(); self.rejects(c, lambda: c.payload(DATA))
        c, b = self.prepared(); self.rejects(c, lambda: c.accept_receipt(self.ready_frame))

    def test_receipt_cannot_add_authority_data_or_wrong_count(self):
        for name, bad in (('byte_count', True), ('byte_count', len(DATA)-1), ('digest', 'f'*64),
                ('outcome', 'authorized'), ('outcome', 'delivered'), ('mode', 'publish'), ('revision', True),
                ('binding_digest', 'f'*64), ('data', 'anything'), ('authority', True), ('released_bytes', 0)):
            c, b = self.buffered(); b.discard(); message = b._expected(3); message[name] = bad
            self.rejects(c, lambda: c.accept_receipt(b._frame('reply', message)))

    def test_ready_cannot_add_permission_or_replace_binding(self):
        for name, bad in (('outcome', 'allowed'), ('byte_count', True), ('digest', 'f'*64), ('authority', True),
                         ('data', 'synthetic'), ('released_bytes', 0)):
            c, b = self.pair(); b.accept_prepare(c.prepare(envelope())); message = b._expected(1); message[name] = bad
            self.rejects(c, lambda: c.accept_ready(b._frame('reply', message)))

    def test_binding_substitution_or_session_splice_rejected(self):
        for mutate in (lambda v: v.update(transport_id='c'*64), lambda v: v.update(fixture_id='c'*64),
                       lambda v: v['channel'].update(pid=999), lambda v: v['channel'].update(creation_time=999)):
            c, b = self.pair(); b.accept_prepare(c.prepare(envelope()))
            c2, b2 = self.pair(); value = envelope(); mutate(value); b2.accept_prepare(c2.prepare(value))
            self.rejects(c, lambda: c.accept_ready(b2.ready()))
        for options in (dict(key=b'x'*32), dict(session=b'x'*32)):
            c, b = self.pair(); b.accept_prepare(c.prepare(envelope()))
            c2, b2 = self.pair(**options); b2.accept_prepare(c2.prepare(envelope(session=options.get('session', b's'*32))))
            self.rejects(c, lambda: c.accept_ready(b2.ready()))

    def test_payload_and_receipt_cannot_splice_different_exact_transcripts(self):
        c, b = self.prepared(); c2, b2 = self.prepared(value=dict(envelope(), transport_id='c'*64))
        self.rejects(b, lambda: b.accept_payload(c2.payload(DATA)))
        c, b = self.buffered(); c2, b2 = self.prepared(value=dict(envelope(), fixture_id='c'*64))
        b2.accept_payload(c2.payload(DATA)); b2.discard(); self.rejects(c, lambda: c.accept_receipt(b2.receipt()))

    def test_old_witness_dry_commit_and_model_mac_domains_are_separate(self):
        for kind, value in ((RecipientWitnessExchange, witness_binding()), (PublicationCommitExchange, commit_binding()),
                            (PublicationDispatchExchange, dispatch_binding())):
            other = kind(role='coordinator', key=b'k'*32, session=b's'*32); self.addCleanup(other.close)
            frame = other.request(value) if kind is RecipientWitnessExchange else other.prepare(value)
            _, b = self.pair(); self.rejects(b, lambda: b.accept_prepare(frame))

    def test_synthetic_frames_are_rejected_by_existing_witness_and_commit(self):
        for kind in (RecipientWitnessExchange, PublicationCommitExchange, PublicationDispatchExchange):
            c, _ = self.pair(); frame = c.prepare(envelope()); other = kind(role='broker', key=b'k'*32, session=b's'*32)
            self.addCleanup(other.close)
            with self.assertRaises(BrokerProtocolError):
                (other.accept_request if kind is RecipientWitnessExchange else other.accept_prepare)(frame)

    def test_frame_type_prefix_bounds_tamper_and_trailing_rejected(self):
        for bad in (None, True, b'', bytearray(36), b'0'*(MAX_BODY_BYTES+37), b'\0\0\0\x20'+b'0'*32):
            _, b = self.pair(); self.rejects(b, lambda: b.accept_prepare(bad))
        for mutate in (lambda f: f[:-1], lambda f: f+b'x', lambda f: f[4:],
                       lambda f: (len(f)-3).to_bytes(4, 'big')+f[4:],
                       lambda f: f[:-1]+bytes([f[-1]^1])):
            c, b = self.pair(); frame = c.prepare(envelope()); self.rejects(b, lambda: b.accept_prepare(mutate(frame)))

    def test_authenticated_noncanonical_duplicate_and_deep_json_rejected(self):
        for mutate in (lambda body: b' '+body, lambda body: body.replace(b'"version":1', b'"version":1,"version":1')):
            c, b = self.pair(); frame = c.prepare(envelope()); body = mutate(frame[4:-32]); signed = body+c._mac('request', body)
            self.rejects(b, lambda: b.accept_prepare(len(signed).to_bytes(4, 'big')+signed))
        for message in ('{"revision":1,"revision":1}', '{"x":NaN}', '{"x":'+ '['*7+'0'+']'*7+'}',
                        ' '+_canonical(envelope()).decode('ascii')):
            c, b = self.pair(); body = dict(step=0, previous='0'*64, message_json=message)
            self.rejects(b, lambda: b.accept_prepare(c._encode('request', body)))

    def test_authenticated_wrong_transcript_fields_and_direction_rejected(self):
        for name, bad in (('step', True), ('step', 1), ('previous', 'f'*64), ('message_json', True), ('extra', True)):
            c, b = self.pair(); body = dict(step=0, previous='0'*64, message_json=_canonical(envelope()).decode('ascii')); body[name] = bad
            self.rejects(b, lambda: b.accept_prepare(c._encode('request', body)))
        c, b = self.pair(); body = dict(step=0, previous='0'*64, message_json=_canonical(envelope()).decode('ascii'))
        self.rejects(b, lambda: b.accept_prepare(c._encode('reply', body)))

    def test_key_role_session_phase_and_binding_mutation_rejected(self):
        for name, bad in (('_key', b'x'*32), ('_role', 'broker'), ('_session', 'f'*64), ('_step', True),
                          ('_previous', 'f'*64), ('_phase_snapshot', [0, '0'*64, 'new'])):
            c, _ = self.pair(); setattr(c, name, bad); self.rejects(c, lambda: c.prepare(envelope()))
        for name, bad in (('_binding', b'{}'), ('_binding_snapshot', b'{}'), ('_binding_digest', 'f'*64)):
            c, b = self.prepared(); setattr(c, name, bad); self.rejects(c, lambda: c.payload(DATA))

    def test_substituted_or_deleted_lock_is_not_entered_and_spends_endpoint(self):
        class Foreign:
            def __enter__(self): raise AssertionError('foreign lock entered')
            def __exit__(self, *_): pass
        for name in ('_lock', '_issued_lock'):
            for bad in (Foreign(), RLock(), None):
                c, b = self.prepared(); original = getattr(c, name); setattr(c, name, bad)
                try: self.rejects(c, lambda: c.payload(DATA))
                finally: setattr(c, name, original)
            c, b = self.prepared(); original = getattr(c, name); delattr(c, name)
            try: self.rejects(c, lambda: c.payload(DATA))
            finally: setattr(c, name, original)

    def test_substituted_lock_close_still_wipes_original_private_bytes(self):
        _, b = self.buffered(); original = b._buffer; lock = b._lock; b._lock = None
        try:
            self.rejects(b, b.close); self.assertEqual(original, b'')
        finally: b._lock = lock

    def test_original_buffer_pointer_mutation_wipes_only_original(self):
        for name in ('_buffer', '_issued_buffer', '_recovery_buffer'):
            _, b = self.buffered(); original = b._buffer; foreign = bytearray(b'foreign')
            setattr(b, name, foreign); self.rejects(b, b.discard)
            self.assertEqual(original, b''); self.assertEqual(foreign, b'foreign')

    def test_original_buffer_content_or_snapshot_mutation_rejected_and_wiped(self):
        for mutate in (lambda b: b._buffer.__setitem__(0, 0), lambda b: b._buffer.append(0),
                       lambda b: setattr(b, '_buffer_snapshot', (1, 'f'*64)),
                       lambda b: setattr(b, '_discarded', True), lambda b: setattr(b, '_discard_snapshot', True)):
            _, b = self.buffered(); original = b._buffer; mutate(b); self.rejects(b, b.discard)
            self.assertEqual(original, b'')

    def test_deleted_buffer_alias_still_wipes_original(self):
        for name in ('_buffer', '_issued_buffer', '_recovery_buffer'):
            _, b = self.buffered(); original = b._buffer; delattr(b, name)
            self.rejects(b, b.discard); self.assertEqual(original, b'')

    def test_snapshot_boolean_count_cannot_equal_one_byte_integer(self):
        _, b = self.buffered(b'a'); original = b._buffer
        b._buffer_snapshot = (True, hashlib.sha256(b'a').hexdigest())
        self.rejects(b, b.discard); self.assertEqual(original, b'')

    def test_failed_wipe_retires_key_before_error_and_can_only_retry_cleanup(self):
        _, b = self.buffered(); original = b._buffer
        with patch.object(b, '_wipe', side_effect=MemoryError):
            with self.assertRaisesRegex(BrokerProtocolError, '^synthetic_payload_rejected$'): b.close()
            self.assertEqual((b._state, b._step, b._key), ('closed', 4, b''))
            self.assertIsNone(b._binding); self.assertIsNone(b._binding_snapshot)
            with self.assertRaisesRegex(BrokerProtocolError, '^synthetic_payload_rejected$'): b.receipt()
        b.close(); self.assertEqual(original, b''); self.terminal(b)

    def test_discard_wipe_fault_is_not_a_receipt_or_reusable_endpoint(self):
        _, b = self.buffered(); original = b._buffer
        with patch.object(b, '_wipe', side_effect=MemoryError):
            with self.assertRaisesRegex(BrokerProtocolError, '^synthetic_payload_rejected$'): b.discard()
            self.assertEqual((b._state, b._step, b._key), ('closed', 4, b''))
            with self.assertRaisesRegex(BrokerProtocolError, '^synthetic_payload_rejected$'): b.discard()
        b.close(); self.assertEqual(original, b''); self.terminal(b)

    def test_exported_view_cannot_retain_bytes_or_create_discard_receipt(self):
        _, b = self.buffered(); original = b._buffer; view = memoryview(original)
        try:
            self.rejects(b, b.discard)
            self.assertEqual(view.tobytes(), b'\0'*len(DATA))
            self.rejects(b, b.receipt)
        finally: view.release()

    def test_injected_buffer_after_discard_does_not_produce_receipt(self):
        _, b = self.buffered(); original = b._buffer; b.discard(); original.extend(b'secret')
        self.rejects(b, b.receipt); self.assertEqual(original, b'')

    def test_closed_state_rollback_cannot_restore_original_key(self):
        c, _ = self.pair(); c.close(); c._state, c._step = 'new', 0
        self.rejects(c, lambda: c.prepare(envelope()))

    def test_inherited_witness_model_and_authority_methods_disabled(self):
        for name in ('request', 'accept_request', 'prove', 'accept_proof', 'retire', 'accept_retirement',
                     'acknowledge_retirement', 'accept_ack', 'reply', 'accept_reply', 'dry_commit', 'accept_dry_commit',
                     'model_visibility', 'accept_model_visibility', 'receipt_claim', 'accept_receipt_claim',
                     'data', 'read', 'publish', 'deliver', 'retire_for_check', 'accept_retirement_ack'):
            c, _ = self.pair(); self.rejects(c, lambda: getattr(c, name)())

    def test_reentrant_close_during_prepare_withholds_metadata(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            frame = original(*args); c.close(); return frame
        with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.prepare(envelope()))

    def test_reentrant_close_during_payload_withholds_data_frame(self):
        c, b = self.prepared(); original = c._encode
        def encode(*args):
            frame = original(*args); c.close(); return frame
        with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.payload(DATA))

    def test_reentrant_close_during_receipt_withholds_claim(self):
        _, b = self.buffered(); b.discard(); original = b._encode
        def encode(*args):
            frame = original(*args); b.close(); return frame
        with patch.object(b, '_encode', side_effect=encode): self.rejects(b, b.receipt)

    def test_reentrant_close_during_payload_evidence_wipes_buffer(self):
        c, b = self.prepared(); frame = c.payload(DATA); original = b._evidence; captured = []
        def evidence(outcome):
            value = original(outcome); captured.append(b._buffer); b.close(); return value
        with patch.object(b, '_evidence', side_effect=evidence): self.rejects(b, lambda: b.accept_payload(frame))
        self.assertEqual(captured[0], b'')

    def test_mutated_evidence_cannot_be_sealed(self):
        for name, bad in (('canonical_binding', b'{}'), ('binding_digest', 'f'*64), ('outcome', 'allowed'),
                          ('byte_count', True), ('byte_count', 0), ('digest', 'f'*64), ('meaning', 'permission')):
            c, b = self.pair(); frame = c.prepare(envelope()); original = b._evidence
            def evidence(outcome):
                result = original(outcome); object.__setattr__(result, name, bad); return result
            with patch.object(b, '_evidence', side_effect=evidence): self.rejects(b, lambda: b.accept_prepare(frame))

    def test_mutated_payload_and_receipt_evidence_wipe_and_reject(self):
        c, b = self.prepared(); frame = c.payload(DATA); original = b._evidence; captured = []
        def evidence(outcome):
            result = original(outcome); captured.append(b._buffer); object.__setattr__(result, 'byte_count', True); return result
        with patch.object(b, '_evidence', side_effect=evidence): self.rejects(b, lambda: b.accept_payload(frame))
        self.assertEqual(captured[0], b'')
        c, b = self.buffered(); b.discard(); frame = b.receipt(); original = c._evidence
        def changed(outcome):
            result = original(outcome); object.__setattr__(result, 'digest', b'f'*64); return result
        with patch.object(c, '_evidence', side_effect=changed): self.rejects(c, lambda: c.accept_receipt(frame))

    def test_duplicate_concurrent_prepare_has_at_most_one_frame(self):
        c, _ = self.pair()
        def attempt():
            try: return c.prepare(envelope())
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: result = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(item is not None for item in result), 1); self.terminal(c)

    def test_duplicate_concurrent_payload_has_at_most_one_frame(self):
        c, _ = self.prepared()
        def attempt():
            try: return c.payload(DATA)
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: result = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(item is not None for item in result), 1); self.terminal(c)

    def test_duplicate_concurrent_receipt_has_at_most_one_claim(self):
        _, b = self.buffered(); b.discard()
        def attempt():
            try: return b.receipt()
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: result = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(item is not None for item in result), 1); self.terminal(b)


if __name__ == '__main__': unittest.main()
