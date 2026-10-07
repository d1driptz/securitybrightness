"""Adversarial inactive dispatch transcripts; no transport or byte delivery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import unittest
from unittest.mock import patch

from core import broker_dispatch_model_protocol as protocol
from core.broker_protocol import BrokerProtocolError, MAX_BODY_BYTES, _canonical
from core.broker_publication_commit_protocol import PublicationCommitExchange
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.json_input import loads
from core.test_broker_publication_commit_protocol import envelope
from core.test_broker_recipient_protocol import binding as witness_binding


def binding():
    return dict(revision=1, mode='dispatch_model_only', attempt_id='b'*64, commit=envelope())


class DispatchModelProtocolTests(unittest.TestCase):
    def pair(self, **options):
        values = dict(key=b'k'*32, session=b's'*32); values.update(options)
        pair = [protocol.PublicationDispatchExchange(role=role, **values) for role in ('coordinator', 'broker')]
        for endpoint in pair: self.addCleanup(endpoint.close)
        return pair

    def prepared(self, value=None):
        c, b = self.pair(); self.prepare_frame = c.prepare(binding() if value is None else value)
        self.prepare_evidence = b.accept_prepare(self.prepare_frame)
        self.ready_frame = b.ready(); self.ready_evidence = c.accept_ready(self.ready_frame)
        return c, b

    def visible(self, value=None):
        c, b = self.prepared(value); self.visibility_frame = c.model_visibility()
        self.visibility_evidence = b.accept_model_visibility(self.visibility_frame)
        return c, b

    @staticmethod
    def claim(b):
        return b.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])

    def terminal(self, endpoint):
        self.assertEqual((endpoint._state, endpoint._step, endpoint._key), ('closed', 4, b''))
        self.assertIsNone(endpoint._binding)
        self.assertIsNone(endpoint._binding_snapshot)
        self.assertIsNone(endpoint._binding_digest)

    def rejects(self, endpoint, operation):
        with self.assertRaisesRegex(BrokerProtocolError, '^dispatch_model_rejected$'): operation()
        self.terminal(endpoint)

    def test_complete_model_is_only_exact_unproven_receiver_claim(self):
        c, b = self.visible(); result = c.accept_receipt_claim(self.claim(b))
        for evidence, outcome in ((self.prepare_evidence, 'requested'), (self.ready_evidence, 'prepared'),
                                  (self.visibility_evidence, 'visibility_possible'), (result, 'receiver_claimed')):
            self.assertIs(type(evidence), protocol.DispatchModelEvidence)
            self.assertEqual(evidence.inspect(), binding())
            self.assertEqual(evidence.outcome, outcome)
            self.assertEqual(evidence.observed_delivery, 'unproven')
            self.assertEqual(evidence.meaning, protocol._MEANING)
            self.assertNotIn('data', asdict(evidence))
            self.assertNotIn('released_bytes', asdict(evidence))
            self.assertNotIn('canonical_binding', repr(evidence))
            with self.assertRaises(TypeError): bool(evidence)
            if outcome == 'receiver_claimed':
                self.assertEqual((evidence.claimed_bytes, evidence.claimed_digest), (37, envelope()['staged_digest']))
            else:
                self.assertIsNone(evidence.claimed_bytes); self.assertIsNone(evidence.claimed_digest)
        self.terminal(c); self.terminal(b)

    def test_original_dry_commit_mode_and_no_data_survive_model(self):
        c, b = self.visible()
        result = c.accept_receipt_claim(self.claim(b)).inspect()
        self.assertEqual(result['mode'], 'dispatch_model_only')
        self.assertEqual(result['commit']['mode'], 'dry_run_discard_only')
        self.assertEqual(set(result), {'revision', 'mode', 'attempt_id', 'commit'})

    def test_input_and_inspection_are_detached(self):
        c, b = self.pair(); value = binding(); frame = c.prepare(value)
        value['commit']['channel']['pid'] = 999
        value['commit']['binding']['context']['max_bytes'] = 4096
        evidence = b.accept_prepare(frame); copy = evidence.inspect(); copy['attempt_id'] = 'c'*64
        copy['commit']['staged_bytes'] = 1
        self.assertEqual(evidence.inspect(), binding())

    def test_count_boundaries_are_exact_full_file_claims(self):
        for count in (0, 1, 4095, 4096):
            value = binding(); commit = value['commit']; commit['binding']['context']['max_bytes'] = 4096
            commit['binding']['context']['size_bytes'] = commit['staged_bytes'] = count
            if not count: commit['staged_digest'] = hashlib.sha256(b'').hexdigest()
            c, b = self.visible(value)
            result = c.accept_receipt_claim(b.receipt_claim(claimed_bytes=count, claimed_digest=commit['staged_digest']))
            self.assertEqual(result.claimed_bytes, count)
            self.assertEqual(result.claimed_digest, commit['staged_digest'])

    def test_invalid_bootstrap(self):
        for name, bad in (('role', True), ('role', 'requester'), ('key', bytearray(32)),
                          ('key', b'k'), ('session', 's'*32), ('session', b's'*31)):
            options = dict(role='coordinator', key=b'k'*32, session=b's'*32); options[name] = bad
            with self.subTest(name=name, bad=bad), self.assertRaises(BrokerProtocolError):
                protocol.PublicationDispatchExchange(**options)

    def test_dispatch_revision_mode_and_identifier_are_strict(self):
        for name, bad in (('revision', True), ('revision', 2), ('revision', 1.0),
                ('mode', 'publish'), ('mode', 'allow_once'), ('mode', 'dry_run_discard_only'),
                ('mode', True), ('attempt_id', True), ('attempt_id', b'b'*64),
                ('attempt_id', 'B'*64), ('attempt_id', 'b'*63), ('attempt_id', 'b'*65)):
            c, _ = self.pair(); value = binding(); value[name] = bad
            with self.subTest(name=name, bad=bad): self.rejects(c, lambda: c.prepare(value))

    def test_missing_and_extra_top_level_fields_fail_closed(self):
        for name in binding():
            c, _ = self.pair(); value = binding(); del value[name]
            self.rejects(c, lambda: c.prepare(value))
        for name in ('data', 'bytes', 'authority', 'approval', 'grant_id', 'permission', 'path',
                     'execute', 'expires_at', 'callback', 'trusted', 'released_bytes'):
            c, _ = self.pair(); value = binding(); value[name] = True
            self.rejects(c, lambda: c.prepare(value))

    def test_binding_container_types_fail_closed(self):
        for bad in (None, True, [], (), binding().items()):
            c, _ = self.pair(); self.rejects(c, lambda: c.prepare(bad))
        class Mapping(dict): pass
        c, _ = self.pair(); self.rejects(c, lambda: c.prepare(Mapping(binding())))

    def test_attempt_collision_with_original_commit_and_witness_is_rejected(self):
        for identifier in (envelope()['commit_id'], envelope()['channel']['witness_session']):
            c, _ = self.pair(); value = binding(); value['attempt_id'] = identifier
            self.rejects(c, lambda: c.prepare(value))

    def test_attempt_collision_with_every_nested_string_identifier_is_rejected(self):
        original = binding()
        for group in ('context', 'recipient'):
            for name, identifier in original['commit']['binding'][group].items():
                if type(identifier) is str and len(identifier) == 64:
                    c, _ = self.pair(); value = binding(); value['attempt_id'] = identifier
                    with self.subTest(group=group, name=name): self.rejects(c, lambda: c.prepare(value))
        c, _ = self.pair(); value = binding()
        value['commit']['binding']['context']['application_id'] = value['attempt_id']
        value['commit']['binding']['recipient']['application_id'] = value['attempt_id']
        self.rejects(c, lambda: c.prepare(value))

    def test_nested_commit_cannot_broaden_to_active_dispatch_or_add_authority(self):
        for name, bad in (('mode', 'publish'), ('mode', 'dispatch_model_only'), ('revision', True),
                          ('staged_bytes', True), ('staged_bytes', 36), ('staged_bytes', 4097),
                          ('staged_digest', 'F'*64), ('commit_id', 'x'*64)):
            c, _ = self.pair(); value = binding(); value['commit'][name] = bad
            self.rejects(c, lambda: c.prepare(value))
        for name in ('authority', 'data', 'permission', 'publish', 'grant_id', 'expires_at'):
            c, _ = self.pair(); value = binding(); value['commit'][name] = True
            self.rejects(c, lambda: c.prepare(value))

    def test_nested_application_resource_effect_and_recipient_remain_strict(self):
        for mutate in (lambda v: v['commit']['binding']['recipient'].update(application_id='other'),
                lambda v: v['commit']['binding']['recipient'].update(recipient_revision=2),
                lambda v: v['commit']['binding']['context'].update(operation='files.write'),
                lambda v: v['commit']['binding']['context'].update(max_bytes=True),
                lambda v: v['commit']['binding']['context'].update(path='C:\\personal'),
                lambda v: v['commit']['channel'].update(pid=True),
                lambda v: v['commit']['channel'].update(creation_time=0),
                lambda v: v['commit']['channel'].update(trusted=True)):
            c, _ = self.pair(); value = binding(); mutate(value)
            self.rejects(c, lambda: c.prepare(value))

    def test_oversized_requester_values_are_rejected_without_output(self):
        for group, name in (('context', 'application_id'), ('recipient', 'application_id')):
            c, _ = self.pair(); value = binding(); value['commit']['binding'][group][name] = 'x'*(MAX_BODY_BYTES+1)
            self.rejects(c, lambda: c.prepare(value))
        c, _ = self.pair(); value = binding(); value['attempt_id'] = 'b'*(MAX_BODY_BYTES+1)
        self.rejects(c, lambda: c.prepare(value))

    def test_lone_surrogate_input_is_rejected(self):
        c, _ = self.pair(); value = binding(); value['commit']['binding']['context']['application_id'] = '\ud800'
        value['commit']['binding']['recipient']['application_id'] = '\ud800'
        self.rejects(c, lambda: c.prepare(value))

    def test_prepare_replay_is_terminal(self):
        c, b = self.prepared(); self.rejects(b, lambda: b.accept_prepare(self.prepare_frame))

    def test_ready_replay_is_terminal(self):
        c, b = self.prepared(); self.rejects(c, lambda: c.accept_ready(self.ready_frame))

    def test_visibility_replay_is_terminal(self):
        c, b = self.visible(); self.rejects(b, lambda: b.accept_model_visibility(self.visibility_frame))

    def test_receipt_replay_cannot_restore_or_retry(self):
        c, b = self.visible(); frame = self.claim(b); c.accept_receipt_claim(frame)
        self.rejects(c, lambda: c.accept_receipt_claim(frame))
        self.rejects(b, lambda: self.claim(b))

    def test_receipt_loss_does_not_make_model_visibility_retryable(self):
        c, b = self.visible(); self.claim(b)  # Lost without coordinator consumption.
        self.terminal(b)
        self.rejects(c, c.model_visibility)
        self.rejects(b, lambda: self.claim(b))

    def test_close_after_visibility_cannot_restore_receiver_claim(self):
        c, b = self.visible(); c.close(); b.close()
        self.rejects(c, c.model_visibility)
        self.rejects(b, lambda: self.claim(b))

    def test_wrong_roles_are_terminal(self):
        for role, operation in (('broker', lambda e: e.prepare(binding())),
                                ('coordinator', lambda e: e.ready()),
                                ('broker', lambda e: e.model_visibility()),
                                ('coordinator', lambda e: self.claim(e))):
            c, b = self.pair(); endpoint = c if role == 'coordinator' else b
            self.rejects(endpoint, lambda: operation(endpoint))

    def test_wrong_phase_visibility_and_early_receipt_are_terminal(self):
        c, b = self.pair(); self.rejects(c, c.model_visibility)
        c, b = self.prepared(); self.rejects(b, lambda: self.claim(b))
        c, b = self.prepared(); self.rejects(c, lambda: c.accept_receipt_claim(self.ready_frame))

    def test_claim_types_count_digest_and_partial_claims_fail_closed(self):
        for count in (None, True, '37', 37.0, -1, 0, 1, 36, 38, 4097):
            c, b = self.visible()
            with self.subTest(count=count):
                self.rejects(b, lambda: b.receipt_claim(claimed_bytes=count, claimed_digest=envelope()['staged_digest']))
        for digest in (None, True, b'f'*64, 'F'*64, 'f'*63, 'f'*65, hashlib.sha256(b'').hexdigest()):
            c, b = self.visible()
            with self.subTest(digest=digest):
                self.rejects(b, lambda: b.receipt_claim(claimed_bytes=37, claimed_digest=digest))

    def test_authenticated_forged_receiver_claim_fields_are_rejected(self):
        for name, bad in (('claimed_bytes', True), ('claimed_bytes', 36), ('claimed_digest', 'f'*64),
                          ('observed_delivery', 'delivered'), ('released_bytes', 37), ('permission', True),
                          ('outcome', 'delivered'), ('data', 'synthetic')):
            c, b = self.visible(); message = b._expected(3); message[name] = bad
            self.rejects(c, lambda: c.accept_receipt_claim(b._frame('reply', message)))

    def test_authenticated_ready_or_visibility_cannot_add_authority(self):
        for phase in (1, 2):
            for name in ('permission', 'data', 'expires_at', 'authority', 'released_bytes'):
                c, b = self.pair(); b.accept_prepare(c.prepare(binding()))
                if phase == 1:
                    message = b._expected(1); message[name] = True
                    self.rejects(c, lambda: c.accept_ready(b._frame('reply', message)))
                else:
                    c.accept_ready(b.ready()); message = c._expected(2); message[name] = True
                    self.rejects(b, lambda: b.accept_model_visibility(c._frame('request', message)))

    def test_authenticated_wrong_application_resource_or_attempt_ready_is_rejected(self):
        for mutate in (lambda v: v.update(attempt_id='c'*64),
                lambda v: v['commit']['binding']['context'].update(resource_token='c'*64),
                lambda v: v['commit']['binding']['context'].update(application_id='other'),
                lambda v: v['commit']['channel'].update(pid=999)):
            c, b = self.pair(); b.accept_prepare(c.prepare(binding()))
            c2, b2 = self.pair(); value = binding(); mutate(value)
            if value['commit']['binding']['context']['application_id'] == 'other':
                value['commit']['binding']['recipient']['application_id'] = 'other'
            b2.accept_prepare(c2.prepare(value))
            self.rejects(c, lambda: c.accept_ready(b2.ready()))

    def test_cross_session_and_key_frames_are_rejected(self):
        for options in (dict(session=b'x'*32), dict(key=b'x'*32)):
            c, b = self.pair(); b.accept_prepare(c.prepare(binding()))
            c2, b2 = self.pair(**options); b2.accept_prepare(c2.prepare(binding()))
            self.rejects(c, lambda: c.accept_ready(b2.ready()))

    def test_existing_witness_and_commit_mac_domains_cannot_be_spliced(self):
        for kind, value in ((RecipientWitnessExchange, witness_binding()), (PublicationCommitExchange, envelope())):
            other = kind(role='coordinator', key=b'k'*32, session=b's'*32); self.addCleanup(other.close)
            frame = other.request(value) if kind is RecipientWitnessExchange else other.prepare(value)
            _, b = self.pair(); self.rejects(b, lambda: b.accept_prepare(frame))

    def test_dispatch_frame_cannot_be_spliced_into_existing_commit(self):
        c, _ = self.pair(); other = PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(other.close)
        with self.assertRaises(BrokerProtocolError): other.accept_prepare(c.prepare(binding()))
        self.terminal(other)

    def test_frame_type_bounds_and_tampering_are_terminal(self):
        for bad in (None, True, b'', bytearray(36), b'0'*(MAX_BODY_BYTES+37), b'\0\0\0\x20'+b'0'*32):
            _, b = self.pair(); self.rejects(b, lambda: b.accept_prepare(bad))
        c, b = self.pair(); frame = c.prepare(binding())
        self.rejects(b, lambda: b.accept_prepare(frame[:-1]+bytes([frame[-1]^1])))

    def test_prefix_truncation_trailing_and_wrong_direction_are_terminal(self):
        for change in (lambda f: f[4:], lambda f: f[:-1], lambda f: f+b'0',
                       lambda f: (len(f)-3).to_bytes(4, 'big')+f[4:]):
            c, b = self.pair(); frame = c.prepare(binding())
            self.rejects(b, lambda: b.accept_prepare(change(frame)))
        c, b = self.pair(); c.prepare(binding()); payload = dict(step=0, previous='0'*64, message_json=_canonical(binding()).decode('ascii'))
        self.rejects(b, lambda: b.accept_prepare(c._encode('reply', payload)))

    def test_authenticated_noncanonical_duplicate_or_deep_json_is_rejected(self):
        for mutate in (lambda body: b' '+body,
                       lambda body: body.replace(b'"version":1', b'"version":1,"version":1')):
            c, b = self.pair(); frame = c.prepare(binding()); body = mutate(frame[4:-32]); signed = body+c._mac('request', body)
            self.rejects(b, lambda: b.accept_prepare(len(signed).to_bytes(4, 'big')+signed))
        for message in ('{"revision":1,"revision":1}', '{"extra":'+ '['*7+'0'+']'*7+'}',
                        '{"x":NaN}', ' '+_canonical(binding()).decode('ascii')):
            c, b = self.pair(); payload = dict(step=0, previous='0'*64, message_json=message)
            self.rejects(b, lambda: b.accept_prepare(c._encode('request', payload)))

    def test_authenticated_wrong_transcript_fields_are_terminal(self):
        for name, bad in (('step', True), ('step', 1), ('previous', 'f'*64), ('message_json', True), ('extra', 1)):
            c, b = self.pair(); payload = dict(step=0, previous='0'*64, message_json=_canonical(binding()).decode('ascii')); payload[name] = bad
            self.rejects(b, lambda: b.accept_prepare(c._encode('request', payload)))

    def test_key_role_session_phase_and_snapshot_mutation_are_terminal(self):
        for name, bad in (('_key', b'x'*32), ('_role', 'broker'), ('_session', 'x'*64),
                ('_step', True), ('_previous', 'f'*64), ('_phase_snapshot', [0, '0'*64, 'new'])):
            c, _ = self.pair(); setattr(c, name, bad); self.rejects(c, lambda: c.prepare(binding()))

    def test_binding_or_digest_mutation_after_ready_is_terminal(self):
        for name, bad in (('_binding', b'{}'), ('_binding_snapshot', b'{}'), ('_binding_digest', 'f'*64)):
            c, b = self.prepared(); setattr(c, name, bad); self.rejects(c, c.model_visibility)

    def test_closed_state_rollback_does_not_restore_original_key(self):
        c, _ = self.pair(); c.close(); c._state, c._step = 'new', 0
        self.rejects(c, lambda: c.prepare(binding()))

    def test_inherited_witness_data_and_dry_commit_paths_are_disabled(self):
        for name in ('request', 'accept_request', 'prove', 'accept_proof', 'retire', 'accept_retirement',
                     'acknowledge_retirement', 'accept_ack', 'reply', 'accept_reply', 'dry_commit',
                     'accept_dry_commit', 'receipt', 'accept_receipt', 'data', 'read', 'publish', 'deliver',
                     'retire_for_check', 'accept_retirement_ack'):
            c, _ = self.pair(); self.rejects(c, lambda: getattr(c, name)())

    def test_reentrant_close_during_prepare_withholds_metadata(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            frame = original(*args); c.close(); return frame
        with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.prepare(binding()))

    def test_reentrant_close_during_receipt_withholds_metadata(self):
        c, b = self.visible(); original = b._encode
        def encode(*args):
            frame = original(*args); b.close(); return frame
        with patch.object(b, '_encode', side_effect=encode): self.rejects(b, lambda: self.claim(b))

    def test_mutated_model_evidence_is_not_sealed(self):
        for name, bad in (('claimed_bytes', 37), ('claimed_digest', 'f'*64), ('observed_delivery', 'delivered'),
                          ('meaning', 'permission'), ('outcome', 'allowed'), ('binding_digest', 'f'*64)):
            c, b = self.pair(); frame = c.prepare(binding()); original = b._evidence
            def evidence(outcome):
                value = original(outcome); object.__setattr__(value, name, bad); return value
            with patch.object(b, '_evidence', side_effect=evidence): self.rejects(b, lambda: b.accept_prepare(frame))

    def test_mutated_receipt_evidence_types_are_rejected(self):
        for name, bad in (('claimed_bytes', True), ('claimed_digest', b'f'*64), ('observed_delivery', True)):
            c, b = self.visible(); frame = self.claim(b); original = c._evidence
            def evidence(outcome):
                value = original(outcome); object.__setattr__(value, name, bad); return value
            with patch.object(c, '_evidence', side_effect=evidence): self.rejects(c, lambda: c.accept_receipt_claim(frame))

    def test_duplicate_concurrent_prepare_has_at_most_one_notice(self):
        c, _ = self.pair()
        def attempt():
            try: return c.prepare(binding())
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1); self.terminal(c)

    def test_duplicate_concurrent_visibility_has_at_most_one_notice(self):
        c, b = self.prepared()
        def attempt():
            try: return c.model_visibility()
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1); self.terminal(c)

    def test_duplicate_concurrent_receipt_has_at_most_one_claim(self):
        c, b = self.visible()
        def attempt():
            try: return self.claim(b)
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1); self.terminal(b)


if __name__ == '__main__': unittest.main()
