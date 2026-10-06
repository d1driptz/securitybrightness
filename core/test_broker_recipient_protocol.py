"""Adversarial metadata-only recipient witnesses; no native/process/byte I/O."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import unittest
from unittest.mock import patch

from core import broker_recipient_protocol as protocol
from core.broker_protocol import BrokerProtocolError, FixtureBrokerExchange, _canonical
from core.broker_publication_protocol import PublicationCheckExchange
from core.broker_quarantine import QuarantinedReadExchange
from core.json_input import loads
from core.test_broker_quarantine import context


def binding():
    return dict(context=context(), recipient=dict(application_id='app', recipient_session='7'*64,
                                                  recipient_id='8'*64, recipient_revision=1))


class RecipientWitnessProtocolTests(unittest.TestCase):
    def pair(self, **options):
        values = dict(key=b'k'*32, session=b's'*32); values.update(options)
        pair = [protocol.RecipientWitnessExchange(role=role, **values) for role in ('coordinator', 'broker')]
        for endpoint in pair: self.addCleanup(endpoint.close)
        return pair

    def requested(self):
        c, b = self.pair(); self.request_frame = c.request(binding())
        self.request_evidence = b.accept_request(self.request_frame)
        return c, b

    def proved(self):
        c, b = self.requested(); self.proof_frame = b.prove()
        self.proof_evidence = c.accept_proof(self.proof_frame)
        return c, b

    def retiring(self):
        c, b = self.proved(); self.retirement_frame = c.retire()
        self.retirement_evidence = b.accept_retirement(self.retirement_frame)
        return c, b

    def retired(self):
        c, b = self.retiring(); self.ack_frame = b.acknowledge_retirement()
        self.ack_evidence = c.accept_ack(self.ack_frame)
        return c, b

    def terminal(self, endpoint):
        self.assertEqual(endpoint._state, 'closed')
        self.assertEqual(endpoint._step, 4)
        self.assertEqual(endpoint._key, b'')
        self.assertIsNone(endpoint._binding)
        self.assertIsNone(endpoint._binding_snapshot)
        self.assertIsNone(endpoint._binding_digest)

    def rejects(self, endpoint, operation):
        with self.assertRaises(BrokerProtocolError): operation()
        self.terminal(endpoint)

    def signed(self, sender, sign_direction, **changes):
        frame = sender._frame(sign_direction, changes.pop('message', sender._expected(sender._step)))
        outer = loads(frame[4:-32]); outer.update(changes)
        body = _canonical(outer); signed = body+sender._mac(sign_direction, body)
        return len(signed).to_bytes(4, 'big')+signed

    def test_complete_witness_has_no_data_and_permanently_closes_both_endpoints(self):
        c, b = self.retired()
        for value, outcome in ((self.request_evidence, 'requested'), (self.proof_evidence, 'witnessed'),
                               (self.retirement_evidence, 'retiring'), (self.ack_evidence, 'retired')):
            self.assertEqual(value.inspect(), binding())
            self.assertEqual(value.binding_digest, hashlib.sha256(_canonical(binding())).hexdigest())
            self.assertEqual(value.outcome, outcome)
            self.assertEqual(value.released_bytes, 0)
            self.assertNotIn('data', asdict(value))
            self.assertNotIn('canonical_binding', repr(value))
            self.assertIn('not OS peer identity', value.meaning)
            with self.assertRaises(TypeError): bool(value)
        self.terminal(c); self.terminal(b)

    def test_source_and_inspection_mutations_cannot_change_binding(self):
        c, b = self.pair(); value = binding(); frame = c.request(value)
        value['context']['max_bytes'] = 4096; value['recipient']['recipient_id'] = '9'*64
        evidence = b.accept_request(frame); evidence.inspect()['recipient']['recipient_id'] = 'a'*64
        self.assertEqual(evidence.inspect(), binding())
        self.assertEqual(c.accept_proof(b.prove()).inspect(), binding())

    def test_metadata_boundaries_are_strict_and_have_no_data_semantics(self):
        for size in (0, 1, 4095, 4096):
            c, b = self.pair(); value = binding(); value['context'] = context(size)
            with self.subTest(size=size):
                evidence = b.accept_request(c.request(value))
                self.assertEqual(evidence.inspect()['context']['size_bytes'], size)
                self.assertEqual(c.accept_proof(b.prove()).released_bytes, 0)

    def test_wrong_bootstrap_types_and_lengths_are_rejected(self):
        for change in (dict(role='requester'), dict(role=True), dict(key=b'k'*31),
                       dict(key='k'*32), dict(session=b's'*31), dict(session=bytearray(b's'*32))):
            values = dict(role='coordinator', key=b'k'*32, session=b's'*32); values.update(change)
            with self.subTest(change=change), self.assertRaises(BrokerProtocolError):
                protocol.RecipientWitnessExchange(**values)

    def test_plain_requester_mapping_is_not_authenticated_frame(self):
        _, b = self.pair(); self.rejects(b, lambda: b.accept_request(binding()))

    def test_unsupported_wrapper_fields_rejected_on_first_attempt(self):
        for field in ('data', 'approved', 'authority', 'path', 'pid', 'callback'):
            c, _ = self.pair(); value = binding(); value[field] = True
            with self.subTest(field=field): self.rejects(c, lambda: c.request(value))

    def test_context_fields_cannot_inject_authority_or_paths(self):
        for field in ('data', 'approved', 'permission', 'path', 'handle', 'expires_at', 'attributes'):
            c, _ = self.pair(); value = binding(); value['context'][field] = True
            with self.subTest(field=field): self.rejects(c, lambda: c.request(value))

    def test_recipient_fields_cannot_inject_channel_identity_or_authority(self):
        for field in ('data', 'pid', 'path', 'address', 'permission', 'authority', 'expires_at'):
            c, _ = self.pair(); value = binding(); value['recipient'][field] = True
            with self.subTest(field=field): self.rejects(c, lambda: c.request(value))

    def test_missing_wrapper_context_or_recipient_fields_rejected(self):
        for group, field in ((None, 'context'), (None, 'recipient'), ('context', 'grant_id'),
                             ('context', 'max_bytes'), ('recipient', 'recipient_id')):
            c, _ = self.pair(); value = binding(); target = value if group is None else value[group]
            del target[field]
            with self.subTest(group=group, field=field): self.rejects(c, lambda: c.request(value))

    def test_recipient_fixed_revision_and_exact_application_are_required(self):
        for field, changed in (('recipient_revision', 0), ('recipient_revision', 2), ('recipient_revision', True),
                               ('recipient_revision', 2**31), ('application_id', 'other')):
            c, _ = self.pair(); value = binding(); value['recipient'][field] = changed
            with self.subTest(field=field, changed=changed): self.rejects(c, lambda: c.request(value))

    def test_context_type_confusion_bounds_and_unsupported_effects_rejected(self):
        for field, changed in (('max_bytes', True), ('max_bytes', 4097), ('size_bytes', -1), ('size_bytes', 38),
                               ('volume_serial', True), ('draft_revision', True), ('file_id', 'x'*32),
                               ('proposal_id', 'sbp2_sha256_'+'x'*64), ('recipient', 'other'),
                               ('operation', 'files.write'), ('application_id', ' app')):
            c, _ = self.pair(); value = binding(); value['context'][field] = changed
            with self.subTest(field=field, changed=changed): self.rejects(c, lambda: c.request(value))

    def test_recipient_identifier_malformed_colliding_or_oversized_rejected(self):
        for field, changed in (('recipient_id', 'x'*64), ('recipient_id', 'x'*10000),
                               ('recipient_id', '7'*64), ('recipient_session', '8'*64)):
            c, _ = self.pair(); value = binding(); value['recipient'][field] = changed
            with self.subTest(field=field, changed=changed): self.rejects(c, lambda: c.request(value))
        for field in ('review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token'):
            for recipient_field in ('recipient_id', 'recipient_session'):
                c, _ = self.pair(); value = binding()
                value['recipient'][recipient_field] = value['context'][field]
                with self.subTest(field=field, recipient_field=recipient_field):
                    self.rejects(c, lambda: c.request(value))

    def test_mapping_subclasses_and_scalar_subclasses_are_rejected(self):
        class Mapping(dict): pass
        class String(str): pass
        class Number(int): pass
        for group, changed in ((None, Mapping(binding())), ('context', Mapping(context())),
                                ('recipient', Mapping(binding()['recipient']))):
            c, _ = self.pair(); value = binding() if group else changed
            if group: value[group] = changed
            self.rejects(c, lambda: c.request(value))
        for group, field, changed in (('context', 'file_id', String('0'*32)),
                                      ('recipient', 'recipient_revision', Number(1))):
            c, _ = self.pair(); value = binding(); value[group][field] = changed
            self.rejects(c, lambda: c.request(value))

    def test_first_wrong_role_or_phase_attempt_is_terminal(self):
        for role, method in (('coordinator', 'prove'), ('coordinator', 'retire'), ('broker', 'request'),
                              ('broker', 'acknowledge_retirement')):
            c, b = self.pair(); endpoint = c if role == 'coordinator' else b
            args = (binding(),) if method == 'request' else ()
            with self.subTest(role=role, method=method):
                self.rejects(endpoint, lambda: getattr(endpoint, method)(*args))

    def test_wrong_key_and_session_fail_closed(self):
        for change in (dict(key=b'x'*32), dict(session=b'x'*32)):
            c, _ = self.pair(); _, b = self.pair(**change)
            self.rejects(b, lambda: b.accept_request(c.request(binding())))

    def test_other_mac_domains_cannot_splice_request_or_proof(self):
        for exchange in (FixtureBrokerExchange, QuarantinedReadExchange, PublicationCheckExchange):
            c, b = self.pair(); old = exchange(role='coordinator', key=b'k'*32, session=b's'*32)
            self.addCleanup(old.close)
            frame = old._encode('request', dict(step=0, previous='0'*64, message_json=_canonical(binding()).decode()))
            with self.subTest(profile=exchange.__name__): self.rejects(b, lambda: b.accept_request(frame))
        c, b = self.requested(); old = QuarantinedReadExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        frame = old._encode('reply', dict(step=1, previous=c._previous,
                                         message_json=_canonical(b._expected(1)).decode()))
        self.rejects(c, lambda: c.accept_proof(frame))

    def test_new_witness_domain_cannot_enter_existing_publication_profile(self):
        c, _ = self.pair(); old = PublicationCheckExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError): old.accept_request(c.request(binding()))
        self.assertEqual(old._state, 'closed')

    def test_signed_version_direction_and_outer_field_mismatch_rejected(self):
        for change in (dict(version=2), dict(version=True), dict(direction='request'), dict(extra='authority')):
            c, b = self.requested()
            frame = self.signed(b, 'reply', **change)
            with self.subTest(change=change): self.rejects(c, lambda: c.accept_proof(frame))

    def test_signed_transcript_step_previous_or_shape_mismatch_rejected(self):
        for change in (dict(step=True), dict(step=2), dict(previous='f'*64), dict(previous=True),
                       dict(message_json='{}'), dict(extra='authority')):
            c, b = self.requested(); frame = b._frame('reply', b._expected(1))
            body = loads(frame[4:-32]); body['payload'].update(change); body = _canonical(body)
            signed = body+b._mac('reply', body); frame = len(signed).to_bytes(4, 'big')+signed
            with self.subTest(change=change): self.rejects(c, lambda: c.accept_proof(frame))

    def test_signed_noncanonical_or_duplicate_json_is_rejected(self):
        for message in (' {"binding_digest":"'+'f'*64+'","outcome":"witnessed"}',
                         '{"outcome":"witnessed","outcome":"allowed"}'):
            c, b = self.requested()
            frame = b._encode('reply', dict(step=1, previous=b._previous, message_json=message))
            self.rejects(c, lambda: c.accept_proof(frame))

    def test_signed_proof_cannot_widen_effect_or_grant_delivery(self):
        for change in (dict(binding_digest='f'*64), dict(outcome='allowed'), dict(outcome=True),
                       dict(data='secret'), dict(permission='allow_once'), dict(released_bytes=37)):
            c, b = self.requested(); value = b._expected(1); value.update(change)
            frame = b._frame('reply', value)
            with self.subTest(change=change): self.rejects(c, lambda: c.accept_proof(frame))

    def test_authenticated_changed_binding_is_rejected_against_original_parent(self):
        for group, field, changed in (('context', 'file_id', '9'*32), ('context', 'draft_revision', 2),
                                      ('context', 'proposal_id', 'sbp2_sha256_'+'9'*64),
                                      ('recipient', 'recipient_id', '9'*64), ('recipient', 'recipient_session', '9'*64)):
            c, b = self.requested(); value = binding(); value[group][field] = changed
            other, peer = self.pair(); peer.accept_request(other.request(value))
            with self.subTest(group=group, field=field): self.rejects(c, lambda: c.accept_proof(peer.prove()))

    def test_signed_retirement_only_accepts_fixed_action_and_exact_digest(self):
        for change in (dict(action='read'), dict(action='publish'), dict(action='allow_once'),
                       dict(binding_digest='f'*64), dict(data='secret'), dict(permission=True)):
            c, b = self.proved(); value = c._expected(2); value.update(change)
            with self.subTest(change=change):
                self.rejects(b, lambda: b.accept_retirement(c._frame('request', value)))

    def test_signed_ack_cannot_report_data_permission_or_nonzero_release(self):
        for change in (dict(released_bytes=True), dict(released_bytes=1), dict(data='secret'),
                       dict(outcome='allowed'), dict(lifecycle='active'), dict(binding_digest='f'*64),
                       dict(permission=True), dict(action='publish')):
            c, b = self.retiring(); value = b._expected(3); value.update(change)
            with self.subTest(change=change): self.rejects(c, lambda: c.accept_ack(b._frame('reply', value)))

    def test_malformed_truncated_corrupt_oversized_and_deep_input_rejected(self):
        for mutate in (lambda f: f[:-1], lambda f: f+b'x', lambda f: b'x'*9000,
                       lambda f: f[:-1]+bytes([f[-1]^1]), lambda f: bytearray(f)):
            c, b = self.pair(); frame = c.request(binding())
            self.rejects(b, lambda: b.accept_request(mutate(frame)))
        c, b = self.pair()
        deep = '[['*10+'null'+']]'*10
        frame = c._encode('request', dict(step=0, previous='0'*64, message_json=deep))
        self.rejects(b, lambda: b.accept_request(frame))

    def test_request_proof_retirement_and_ack_replays_are_terminal(self):
        c, b = self.requested(); self.rejects(b, lambda: b.accept_request(self.request_frame))
        c, b = self.proved(); self.rejects(c, lambda: c.accept_proof(self.proof_frame))
        c, b = self.retiring(); self.rejects(b, lambda: b.accept_retirement(self.retirement_frame))
        c, b = self.retired(); self.rejects(c, lambda: c.accept_ack(self.ack_frame))

    def test_close_is_irreversible_and_retired_evidence_cannot_restore_endpoint(self):
        c, b = self.requested(); evidence = self.request_evidence; b.close()
        self.rejects(b, b.prove); self.rejects(c, lambda: c.accept_proof(evidence))
        self.assertEqual(evidence.released_bytes, 0)

    def test_two_concurrent_attempts_can_emit_at_most_one_request(self):
        c, _ = self.pair()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(c.request, binding()) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.terminal(c)

    def test_internal_phase_key_session_role_and_binding_mutation_rejected(self):
        for field, changed in (('_step', True), ('_step', 0), ('_previous', 'f'*64), ('_state', 'active'),
                               ('_key', b'x'*32), ('_session', 'x'*64), ('_role', 'broker'),
                               ('_binding', bytearray(_canonical(binding()))), ('_binding_digest', 'f'*64)):
            c, b = self.requested(); setattr(c, field, changed)
            with self.subTest(field=field): self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_reentrant_close_during_frame_generation_emits_no_frame(self):
        c, _ = self.pair(); original = c._frame
        def frame(*args):
            value = original(*args); c.close(); return value
        with patch.object(c, '_frame', side_effect=frame): self.rejects(c, lambda: c.request(binding()))

    def test_equal_valued_snapshot_type_substitution_is_rejected(self):
        class String(str): pass
        for field in ('_role_snapshot', '_session_snapshot', '_key_snapshot'):
            c, b = self.requested(); setattr(c, field, String(getattr(c, field)))
            with self.subTest(field=field): self.rejects(c, lambda: c.accept_proof(b.prove()))
        c, b = self.requested(); c._binding_snapshot = bytearray(c._binding_snapshot)
        self.rejects(c, lambda: c.accept_proof(b.prove()))
        c, b = self.requested(); c._phase_snapshot = list(c._phase_snapshot)
        self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_evidence_mutation_during_construction_is_rejected(self):
        c, b = self.requested(); original = c._evidence
        def evidence(outcome):
            result = original(outcome); object.__setattr__(result, 'released_bytes', True); return result
        with patch.object(c, '_evidence', side_effect=evidence): self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_corrupted_generated_frame_is_withheld(self):
        c, b = self.requested(); original = b._frame
        def frame(*args):
            value = original(*args); return value[:-1]+bytes([value[-1]^1])
        with patch.object(b, '_frame', side_effect=frame): self.rejects(b, b.prove)

    def test_inherited_data_reply_paths_are_explicitly_terminal(self):
        c, b = self.requested(); self.rejects(b, lambda: b.reply(outcome='buffered', data=b'secret'))
        c, b = self.requested(); self.rejects(c, lambda: c.accept_reply(b'fake'))

    def test_pure_witness_has_no_acquisition_publication_or_timer_interface(self):
        c, b = self.pair()
        for endpoint in (c, b):
            for name in ('read', 'open_path', 'execute', 'acquire', 'release', 'publish', 'data', '_buffer', '_timer', '_deadline'):
                self.assertFalse(hasattr(endpoint, name))


if __name__ == '__main__': unittest.main()
