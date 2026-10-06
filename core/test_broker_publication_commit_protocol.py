"""Adversarial pure dry-commit transcripts; no native identity or delivery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import unittest
from unittest.mock import patch
from core import broker_publication_commit_protocol as protocol
from core.broker_protocol import BrokerProtocolError, _canonical
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.json_input import loads
from core import test_broker_recipient_protocol as helpers


def envelope():
    return dict(revision=1, mode='dry_run_discard_only', commit_id='9'*64, binding=helpers.binding(),
        staged_bytes=37, staged_digest=hashlib.sha256(b'SecurityBrightness synthetic fixture\n').hexdigest(),
        channel=dict(pid=123, creation_time=456, witness_session='a'*64))


class PublicationCommitProtocolTests(unittest.TestCase):
    def pair(self):
        pair = [protocol.PublicationCommitExchange(role=role, key=b'k'*32, session=b's'*32) for role in ('coordinator', 'broker')]
        for endpoint in pair: self.addCleanup(endpoint.close)
        return pair

    def prepared(self):
        c, b = self.pair(); self.prepare_frame = c.prepare(envelope())
        self.prepare_evidence = b.accept_prepare(self.prepare_frame)
        self.ready_frame = b.ready(); self.ready_evidence = c.accept_ready(self.ready_frame)
        return c, b

    def committed(self):
        c, b = self.prepared(); self.commit_frame = c.dry_commit()
        self.commit_evidence = b.accept_dry_commit(self.commit_frame)
        return c, b

    def terminal(self, endpoint):
        self.assertEqual((endpoint._state, endpoint._step, endpoint._key), ('closed', 4, b''))
        self.assertIsNone(endpoint._binding)

    def rejects(self, endpoint, operation):
        with self.assertRaises(BrokerProtocolError): operation()
        self.terminal(endpoint)

    def test_complete_dry_commit_releases_zero_and_cannot_be_permission(self):
        c, b = self.committed(); receipt = c.accept_receipt(b.receipt())
        for value, phase in ((self.prepare_evidence, 'requested'), (self.ready_evidence, 'prepared'),
                             (self.commit_evidence, 'committing'), (receipt, 'dry_run_retired')):
            self.assertEqual(value.inspect(), envelope())
            self.assertEqual(value.outcome, phase)
            self.assertEqual(value.released_bytes, 0)
            self.assertNotIn('data', asdict(value))
            self.assertNotIn('canonical_binding', repr(value))
            with self.assertRaises(TypeError): bool(value)
        self.terminal(c); self.terminal(b)

    def test_input_and_inspected_copies_cannot_mutate_binding(self):
        c, b = self.pair(); value = envelope(); frame = c.prepare(value)
        value['channel']['pid'] = 999
        evidence = b.accept_prepare(frame); evidence.inspect()['binding']['context']['max_bytes'] = 4096
        self.assertEqual(evidence.inspect(), envelope())

    def test_count_boundaries(self):
        for count in (0, 1, 4095, 4096):
            c, b = self.pair(); value = envelope(); value['binding']['context']['max_bytes'] = 4096
            value['binding']['context']['size_bytes'] = count
            value['staged_bytes'] = count
            if not count: value['staged_digest'] = hashlib.sha256(b'').hexdigest()
            self.assertEqual(b.accept_prepare(c.prepare(value)).inspect()['staged_bytes'], count)

    def test_invalid_bootstrap(self):
        for name, value in (('role', True), ('role', 'recipient'), ('key', bytearray(32)), ('key', b'k'), ('session', 's'*32)):
            options = dict(role='coordinator', key=b'k'*32, session=b's'*32); options[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(BrokerProtocolError): protocol.PublicationCommitExchange(**options)

    def invalid_envelopes(self):
        for name, value in (('revision', True), ('revision', 2), ('mode', 'publish'), ('mode', 'allow_once'),
                ('commit_id', 'x'*64), ('commit_id', '9'*65), ('commit_id', True), ('staged_bytes', True),
                ('staged_bytes', -1), ('staged_bytes', 4097), ('staged_bytes', 1.0), ('staged_digest', 'F'*64)):
            v = envelope(); v[name] = value; yield v
        for name in envelope():
            v = envelope(); del v[name]; yield v
        for name in ('data', 'authority', 'approval', 'grant_id', 'path', 'execute', 'expires_at', 'callback'):
            v = envelope(); v[name] = True; yield v
        v = envelope(); v['staged_bytes'] = 0; yield v
        v = envelope(); v['staged_bytes'] = 36; yield v  # Whole-file contract forbids partial delivery claims.
        v = envelope(); v['binding']['context']['max_bytes'] = 4096; v['staged_bytes'] = 38; yield v
        v = envelope(); v['binding']['recipient']['recipient_revision'] = 2; yield v

    def test_malformed_unsupported_or_authority_injected_envelopes_fail_closed(self):
        for value in self.invalid_envelopes():
            c, _ = self.pair()
            with self.subTest(value=value): self.rejects(c, lambda: c.prepare(value))

    def test_native_claim_types_ranges_and_extra_fields_are_strict(self):
        for name, bad in (('pid', True), ('pid', 0), ('pid', 2**32), ('pid', '123'), ('creation_time', False),
                ('creation_time', -1), ('creation_time', 2**64), ('witness_session', 'A'*64), ('witness_session', b'a'*64)):
            c, _ = self.pair(); value = envelope(); value['channel'][name] = bad
            self.rejects(c, lambda: c.prepare(value))
        for extra in ('handle', 'path', 'trusted', 'authority'):
            c, _ = self.pair(); value = envelope(); value['channel'][extra] = 1
            self.rejects(c, lambda: c.prepare(value))

    def test_identity_collisions_are_rejected(self):
        for identity in ('7'*64, '8'*64, 'a'*64, envelope()['binding']['context']['resource_token']):
            c, _ = self.pair(); value = envelope(); value['commit_id'] = identity
            self.rejects(c, lambda: c.prepare(value))

    def test_binding_application_effect_or_resource_substitution_is_rejected(self):
        for mutate in (lambda v: v['binding']['recipient'].update(application_id='other'),
                       lambda v: v['binding']['context'].update(operation='files.write'),
                       lambda v: v['binding']['context'].update(max_bytes=True),
                       lambda v: v['binding']['context'].update(path='C:\\personal')):
            c, _ = self.pair(); value = envelope(); mutate(value)
            self.rejects(c, lambda: c.prepare(value))

    def test_prepare_replay_spends_recipient(self):
        c, b = self.prepared(); self.rejects(b, lambda: b.accept_prepare(self.prepare_frame))

    def test_ready_replay_spends_coordinator(self):
        c, b = self.prepared(); self.rejects(c, lambda: c.accept_ready(self.ready_frame))

    def test_commit_replay_spends_recipient(self):
        c, b = self.committed(); self.rejects(b, lambda: b.accept_dry_commit(self.commit_frame))

    def test_receipt_replay_cannot_restore_state(self):
        c, b = self.committed(); frame = b.receipt(); c.accept_receipt(frame)
        self.rejects(c, lambda: c.accept_receipt(frame))

    def test_wrong_phase_commit_consumes_endpoint(self):
        c, _ = self.pair(); self.rejects(c, c.dry_commit)

    def test_wrong_role_prepare_consumes_endpoint(self):
        _, b = self.pair(); self.rejects(b, lambda: b.prepare(envelope()))

    def test_cross_session_ready_is_rejected(self):
        c, b = self.prepared(); c2, b2 = self.pair()
        c2._session = c2._session_snapshot = b2._session = b2._session_snapshot = 'b'*64
        b2.accept_prepare(c2.prepare(envelope())); frame = b2.ready()
        self.rejects(c, lambda: c.accept_ready(frame))

    def test_witness_domain_frame_cannot_be_a_commit_prepare(self):
        c = RecipientWitnessExchange(role='coordinator', key=b'k'*32, session=b's'*32)
        self.addCleanup(c.close); _, b = self.pair()
        self.rejects(b, lambda: b.accept_prepare(c.request(helpers.binding())))

    def test_authenticated_extra_or_broadened_ready_fields_are_rejected(self):
        for extra in ('data', 'permission', 'allow', 'max_bytes', 'expires_at'):
            c, b = self.prepared()
            # Separate pair remains at step 1 to produce an authenticated wrong message.
            c2, b2 = self.pair(); b2.accept_prepare(c2.prepare(envelope()))
            message = b2._expected(1); message[extra] = True
            frame = b2._frame('reply', message)
            self.rejects(c, lambda: c.accept_ready(frame))

    def test_authenticated_receipt_cannot_claim_protected_bytes(self):
        c, b = self.committed(); message = b._expected(3); message['released_bytes'] = 37
        self.rejects(c, lambda: c.accept_receipt(b._frame('reply', message)))

    def test_frame_types_lengths_and_tampering_fail_closed(self):
        for bad in (None, True, b'', b'0'*9000, bytearray(36), b'\0\0\0\x20'+b'0'*32):
            _, b = self.pair(); self.rejects(b, lambda: b.accept_prepare(bad))
        c, b = self.pair(); frame = c.prepare(envelope())
        self.rejects(b, lambda: b.accept_prepare(frame[:-1]+bytes([frame[-1]^1])))

    def test_noncanonical_or_duplicate_json_is_rejected_with_valid_mac(self):
        for change in (lambda body: b' '+body, lambda body: body.replace(b'"version":1', b'"version":1,"version":1')):
            c, b = self.pair(); frame = c.prepare(envelope()); body = change(frame[4:-32]); signed = body+c._mac('request', body)
            self.rejects(b, lambda: b.accept_prepare(len(signed).to_bytes(4, 'big')+signed))

    def test_key_role_session_and_phase_mutations_are_terminal(self):
        for field, value in (('_key', b'x'*32), ('_role', 'broker'), ('_session', 'x'*64), ('_step', True), ('_previous', 'f'*64)):
            c, _ = self.pair(); setattr(c, field, value); self.rejects(c, lambda: c.prepare(envelope()))

    def test_binding_mutation_after_prepare_is_terminal(self):
        c, b = self.prepared(); c._binding = c._binding_snapshot+b' '
        self.rejects(c, c.dry_commit)

    def test_state_rollback_cannot_restore_closed_key(self):
        c, _ = self.pair(); c.close(); c._state, c._step = 'new', 0
        self.rejects(c, lambda: c.prepare(envelope()))

    def test_inherited_witness_or_data_operations_are_disabled(self):
        for name in ('request', 'accept_request', 'prove', 'accept_proof', 'retire', 'accept_retirement',
                     'acknowledge_retirement', 'accept_ack', 'reply', 'accept_reply'):
            c, _ = self.pair(); self.rejects(c, lambda: getattr(c, name)())

    def test_reentrant_close_during_frame_construction_withholds_output(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            result = original(*args); c.close(); return result
        with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.prepare(envelope()))

    def test_mutated_evidence_is_not_sealed_as_valid(self):
        c, b = self.pair(); frame = c.prepare(envelope()); original = b._evidence
        def evidence(outcome):
            value = original(outcome); object.__setattr__(value, 'released_bytes', True); return value
        with patch.object(b, '_evidence', side_effect=evidence): self.rejects(b, lambda: b.accept_prepare(frame))

    def test_duplicate_concurrent_commit_has_at_most_one_notice(self):
        c, b = self.prepared()
        def attempt():
            try: return c.dry_commit()
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)
        self.terminal(c)


if __name__ == '__main__': unittest.main()
