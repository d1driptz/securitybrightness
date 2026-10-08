"""Adversarial zero-byte source/native association claims, never permission."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
from threading import RLock
import unittest
from unittest.mock import patch

from core import broker_source_association_protocol as protocol
from core.broker_protocol import BrokerProtocolError, FixtureBrokerExchange, _canonical
from core.broker_publication_commit_protocol import PublicationCommitExchange, _commit_binding
from core.broker_recipient_protocol import RecipientWitnessExchange
from core.json_input import loads
from core.test_broker_publication_commit_protocol import envelope as source_envelope


def envelope(session=b's'*32):
    source = source_envelope()
    return dict(revision=1, mode='source_native_association_discard_only', association_id='b'*64,
        source_commit_json=_commit_binding(source).decode('ascii'),
        grant_id=source['binding']['context']['grant_id'], grant_fingerprint='c'*64,
        recipient_channel=dict(pid=124, creation_time=457, witness_session=session.hex()))


class SourceAssociationProtocolTests(unittest.TestCase):
    def pair(self, **options):
        values = dict(key=b'k'*32, session=b's'*32); values.update(options)
        endpoints = [protocol.SourceRecipientAssociationExchange(role=role, **values)
                     for role in ('coordinator', 'broker')]
        for endpoint in endpoints: self.addCleanup(endpoint.close)
        return endpoints

    def requested(self):
        c, b = self.pair(); self.request_frame = c.request(envelope())
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

    def terminal(self, endpoint):
        self.assertEqual((endpoint._state, endpoint._step, endpoint._key), ('closed', 4, b''))
        self.assertIsNone(endpoint._binding)
        self.assertIsNone(endpoint._binding_snapshot)
        self.assertIsNone(endpoint._binding_digest)

    def rejects(self, endpoint, operation):
        with self.assertRaises(BrokerProtocolError): operation()
        self.terminal(endpoint)

    def invalid(self, changes):
        for name, value in changes:
            c, _ = self.pair(); claimed = envelope(); claimed[name] = value
            with self.subTest(name=name, value=value): self.rejects(c, lambda: c.request(claimed))

    def invalid_source(self, changes):
        for change in changes:
            c, _ = self.pair(); claimed = envelope(); source = loads(claimed['source_commit_json'])
            change(source); claimed['source_commit_json'] = _canonical(source).decode('ascii')
            self.rejects(c, lambda: c.request(claimed))

    def test_complete_contract_is_zero_byte_claim_and_irreversibly_retired(self):
        c, b = self.retiring(); receipt = c.accept_ack(b.acknowledge_retirement())
        for value, outcome in ((self.request_evidence, 'requested'),
                               (self.proof_evidence, 'associated_ready'),
                               (self.retirement_evidence, 'source_discarded'),
                               (receipt, 'associated_retired')):
            self.assertEqual(value.inspect(), envelope())
            self.assertEqual(value.outcome, outcome)
            self.assertEqual(value.released_bytes, 0)
            self.assertEqual(value.binding_digest, hashlib.sha256(_canonical(envelope())).hexdigest())
            self.assertEqual(value.meaning, protocol._MEANING)
            self.assertNotIn('data', asdict(value))
            self.assertNotIn('canonical_binding', repr(value))
            with self.assertRaises(TypeError): bool(value)
        self.terminal(c); self.terminal(b)

    def test_original_source_envelope_is_preserved_without_recipient_rewrite(self):
        c, b = self.requested(); claimed = self.request_evidence.inspect()
        self.assertEqual(claimed['source_commit_json'], _commit_binding(source_envelope()).decode('ascii'))
        self.assertNotEqual(loads(claimed['source_commit_json'])['channel'], claimed['recipient_channel'])
        self.assertEqual(c.accept_proof(b.prove()).inspect(), claimed)

    def test_input_mapping_mutation_cannot_change_snapshot(self):
        c, b = self.pair(); value = envelope(); frame = c.request(value)
        value['recipient_channel']['pid'] = 987; value['source_commit_json'] = '{}'
        self.assertEqual(b.accept_request(frame).inspect(), envelope())

    def test_inspection_is_detached_from_evidence_and_endpoint(self):
        c, b = self.requested(); self.request_evidence.inspect()['recipient_channel']['pid'] = 987
        self.assertEqual(self.request_evidence.inspect(), envelope())
        self.assertEqual(c.accept_proof(b.prove()).inspect(), envelope())

    def test_bootstrap_scalar_type_and_length_confusion_rejected(self):
        for change in (dict(role=True), dict(role='application'), dict(key=bytearray(32)),
                       dict(key=b'k'*31), dict(session='s'*32), dict(session=b's'*33)):
            values = dict(role='coordinator', key=b'k'*32, session=b's'*32); values.update(change)
            with self.subTest(change=change), self.assertRaises(BrokerProtocolError):
                protocol.SourceRecipientAssociationExchange(**values)

    def test_key_cannot_double_as_session(self):
        with self.assertRaises(BrokerProtocolError):
            protocol.SourceRecipientAssociationExchange(role='coordinator', key=b'k'*32, session=b'k'*32)

    def test_plain_mapping_or_evidence_cannot_be_authenticated_request(self):
        for value in (envelope(), protocol.SourceRecipientAssociationEvidence(b'{}', 'b'*64, 'associated_ready')):
            _, b = self.pair(); self.rejects(b, lambda: b.accept_request(value))

    def test_missing_top_level_fields_rejected(self):
        for name in envelope():
            c, _ = self.pair(); value = envelope(); del value[name]
            self.rejects(c, lambda: c.request(value))

    def test_extra_authority_data_path_and_endpoint_fields_rejected(self):
        for name in ('authority', 'allow_once', 'data', 'path', 'handle', 'callback', 'expires_at', 'recipient'):
            c, _ = self.pair(); value = envelope(); value[name] = True
            self.rejects(c, lambda: c.request(value))

    def test_revision_mode_and_identity_are_exact(self):
        self.invalid((('revision', True), ('revision', 2), ('revision', 1.0),
                      ('mode', 'publish'), ('mode', 'allow_once'), ('mode', True),
                      ('association_id', 'B'*64), ('association_id', 'b'*63), ('association_id', True)))

    def test_grant_fingerprint_has_bounded_exact_digest_type(self):
        self.invalid((('grant_fingerprint', b'c'*64), ('grant_fingerprint', True),
                      ('grant_fingerprint', 'C'*64), ('grant_fingerprint', 'c'*65)))

    def test_outer_grant_identity_is_canonical_and_matches_source(self):
        current = envelope()['grant_id']
        self.invalid((('grant_id', '{'+current+'}'), ('grant_id', current.replace('-', '')),
                      ('grant_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff'),
                      ('grant_id', True), ('grant_id', b'x'*36)))

    def test_case_variant_grant_identity_is_not_a_canonical_alias(self):
        c, _ = self.pair(); value = envelope(); source = source_envelope()
        source['binding']['context']['grant_id'] = 'abcdefab-cdef-4abc-8abc-abcdefabcdef'
        value['source_commit_json'] = _commit_binding(source).decode('ascii')
        value['grant_id'] = source['binding']['context']['grant_id'].upper()
        self.rejects(c, lambda: c.request(value))

    def test_new_recipient_channel_fields_are_exact(self):
        for field in ('pid', 'creation_time', 'witness_session'):
            c, _ = self.pair(); value = envelope(); del value['recipient_channel'][field]
            self.rejects(c, lambda: c.request(value))
        for field in ('handle', 'path', 'trusted', 'application_id', 'permission'):
            c, _ = self.pair(); value = envelope(); value['recipient_channel'][field] = True
            self.rejects(c, lambda: c.request(value))

    def test_new_recipient_native_integer_ranges_and_types_are_strict(self):
        for name, bad in (('pid', True), ('pid', 0), ('pid', 2**32), ('pid', '124'),
                          ('creation_time', False), ('creation_time', -1),
                          ('creation_time', 2**64), ('creation_time', 457.0)):
            c, _ = self.pair(); value = envelope(); value['recipient_channel'][name] = bad
            self.rejects(c, lambda: c.request(value))

    def test_new_channel_boundaries_are_valid_metadata_only(self):
        for pid, creation in ((1, 1), (0xffffffff, 0xffffffffffffffff)):
            c, b = self.pair(); value = envelope(); value['recipient_channel'].update(pid=pid, creation_time=creation)
            self.assertEqual(b.accept_request(c.request(value)).released_bytes, 0)

    def test_new_recipient_session_is_exact_codec_session(self):
        for session in ('d'*64, 'A'*64, True, b's'*32):
            c, _ = self.pair(); value = envelope(); value['recipient_channel']['witness_session'] = session
            self.rejects(c, lambda: c.request(value))

    def test_original_native_channel_cannot_be_reused_as_new_recipient(self):
        c, _ = self.pair(); value = envelope()
        value['recipient_channel'].update(pid=123, creation_time=456)
        self.rejects(c, lambda: c.request(value))

    def test_reused_numeric_pid_with_distinct_creation_is_only_a_metadata_claim(self):
        c, b = self.pair(); value = envelope(); value['recipient_channel']['pid'] = 123
        self.assertEqual(b.accept_request(c.request(value)).released_bytes, 0)

    def test_new_association_id_cannot_collide_with_source_identifiers(self):
        source = source_envelope()
        identities = list(source['binding']['context'].values())+list(source['binding']['recipient'].values())
        identities += [source['commit_id'], source['channel']['witness_session'], envelope()['recipient_channel']['witness_session']]
        for value in identities:
            if type(value) is str and len(value) == 64:
                self.invalid((('association_id', value),))

    def test_new_session_cannot_collide_with_original_source_identifiers(self):
        source = source_envelope()
        identities = list(source['binding']['context'].values())+list(source['binding']['recipient'].values())
        identities += [source['commit_id'], source['channel']['witness_session'], envelope()['association_id']]
        for value in identities:
            if type(value) is str and len(value) == 64:
                c, _ = self.pair(session=bytes.fromhex(value)); claimed = envelope(bytes.fromhex(value))
                self.rejects(c, lambda: c.request(claimed))

    def test_source_json_type_empty_ascii_depth_and_size_are_bounded(self):
        self.invalid((('source_commit_json', b'{}'), ('source_commit_json', True),
                      ('source_commit_json', ''), ('source_commit_json', '\u00e9'),
                      ('source_commit_json', ' '*8193), ('source_commit_json', '[['*100+'0'+']]'*100)))

    def test_noncanonical_nested_source_json_is_rejected(self):
        source = envelope()['source_commit_json']
        self.invalid((('source_commit_json', ' '+source), ('source_commit_json', source+'\n'),
                      ('source_commit_json', source.replace(':', ': '))))

    def test_duplicate_nested_source_json_is_rejected(self):
        source = envelope()['source_commit_json'].replace('"revision":1', '"revision":1,"revision":1')
        self.invalid((('source_commit_json', source),))

    def test_source_contract_version_mode_and_extra_authority_rejected(self):
        self.invalid_source((lambda s: s.update(revision=True), lambda s: s.update(mode='publish'),
                             lambda s: s.update(permission='allow_once'), lambda s: s.update(data='secret')))

    def test_source_application_effect_and_resource_contract_is_unchanged(self):
        self.invalid_source((lambda s: s['binding']['recipient'].update(application_id='other'),
                             lambda s: s['binding']['context'].update(operation='files.write'),
                             lambda s: s['binding']['context'].update(path='C:\\personal'),
                             lambda s: s['binding']['context'].update(resource_token=True)))

    def test_source_count_digest_native_fields_and_recipient_version_unchanged(self):
        self.invalid_source((lambda s: s.update(staged_bytes=36), lambda s: s.update(staged_digest=True),
                             lambda s: s['channel'].update(pid=True),
                             lambda s: s['binding']['recipient'].update(recipient_revision=2)))

    def test_zero_and_maximum_source_counts_preserve_no_payload_semantics(self):
        for count in (0, 1, 4095, 4096):
            c, b = self.pair(); value = envelope(); source = source_envelope()
            source['staged_bytes'] = count; source['binding']['context'].update(max_bytes=4096, size_bytes=count)
            if not count: source['staged_digest'] = hashlib.sha256(b'').hexdigest()
            value['source_commit_json'] = _commit_binding(source).decode('ascii')
            self.assertEqual(b.accept_request(c.request(value)).released_bytes, 0)

    def test_mapping_and_scalar_subclasses_cannot_supply_binding(self):
        class Mapping(dict): pass
        class String(str): pass
        class Number(int): pass
        for change in (lambda v: Mapping(v),
                       lambda v: dict(v, recipient_channel=Mapping(v['recipient_channel'])),
                       lambda v: dict(v, source_commit_json=String(v['source_commit_json'])),
                       lambda v: dict(v, revision=Number(1))):
            c, _ = self.pair(); self.rejects(c, lambda: c.request(change(envelope())))

    def test_request_replay_is_terminal(self):
        c, b = self.requested(); self.rejects(b, lambda: b.accept_request(self.request_frame))

    def test_proof_replay_is_terminal(self):
        c, b = self.proved(); self.rejects(c, lambda: c.accept_proof(self.proof_frame))

    def test_retirement_replay_is_terminal(self):
        c, b = self.retiring(); self.rejects(b, lambda: b.accept_retirement(self.retirement_frame))

    def test_ack_replay_cannot_restore_endpoint(self):
        c, b = self.retiring(); frame = b.acknowledge_retirement(); c.accept_ack(frame)
        self.rejects(c, lambda: c.accept_ack(frame))

    def test_first_wrong_role_or_phase_is_terminal(self):
        for role, name in (('broker', 'request'), ('coordinator', 'prove'),
                           ('coordinator', 'retire'), ('broker', 'acknowledge_retirement')):
            c, b = self.pair(); endpoint = c if role == 'coordinator' else b
            args = (envelope(),) if name == 'request' else ()
            self.rejects(endpoint, lambda: getattr(endpoint, name)(*args))

    def test_cross_session_and_wrong_key_frames_fail_closed(self):
        for options in (dict(key=b'x'*32), dict(session=b'x'*32)):
            c, _ = self.pair(); _, b = self.pair(**options)
            self.rejects(b, lambda: b.accept_request(c.request(envelope())))

    def test_other_mac_domains_cannot_enter_association(self):
        for kind in (FixtureBrokerExchange, RecipientWitnessExchange, PublicationCommitExchange):
            old = kind(role='coordinator', key=b'k'*32, session=b's'*32); self.addCleanup(old.close)
            _, b = self.pair()
            frame = old._encode('request', dict(step=0, previous='0'*64, message_json=_canonical(envelope()).decode('ascii')))
            self.rejects(b, lambda: b.accept_request(frame))

    def test_association_mac_domain_cannot_enter_old_commit(self):
        c, _ = self.pair(); old = PublicationCommitExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close); self.rejects(old, lambda: old.accept_prepare(c.request(envelope())))

    def test_signed_broadened_proof_is_rejected(self):
        for changes in (dict(outcome='allowed'), dict(mode='publish'), dict(data='secret'),
                        dict(permission='allow_once'), dict(released_bytes=1), dict(released_bytes=True)):
            c, b = self.requested(); message = b._expected(1); message.update(changes)
            self.rejects(c, lambda: c.accept_proof(b._frame('reply', message)))

    def test_signed_broadened_retirement_is_rejected(self):
        for changes in (dict(outcome='publish'), dict(binding_digest='f'*64), dict(approved=True),
                        dict(released_bytes=37), dict(revision=True)):
            c, b = self.proved(); message = c._expected(2); message.update(changes)
            self.rejects(b, lambda: b.accept_retirement(c._frame('request', message)))

    def test_signed_broadened_ack_is_rejected(self):
        for changes in (dict(outcome='active'), dict(binding_digest='f'*64), dict(data='secret'),
                        dict(released_bytes=True), dict(released_bytes=37), dict(authority=True)):
            c, b = self.retiring(); message = b._expected(3); message.update(changes)
            self.rejects(c, lambda: c.accept_ack(b._frame('reply', message)))

    def test_valid_mac_with_wrong_transcript_step_or_previous_is_rejected(self):
        for changes in (dict(step=True), dict(step=2), dict(previous='f'*64),
                        dict(previous=True), dict(extra='permission')):
            c, b = self.requested(); frame = b._frame('reply', b._expected(1))
            body = loads(frame[4:-32]); body['payload'].update(changes); body = _canonical(body)
            signed = body+b._mac('reply', body)
            self.rejects(c, lambda: c.accept_proof(len(signed).to_bytes(4, 'big')+signed))

    def test_noncanonical_outer_json_is_rejected_even_with_valid_mac(self):
        c, b = self.pair(); frame = c.request(envelope()); body = b' '+frame[4:-32]
        signed = body+c._mac('request', body)
        self.rejects(b, lambda: b.accept_request(len(signed).to_bytes(4, 'big')+signed))

    def test_frame_type_truncation_tampering_extension_and_oversize_fail_closed(self):
        for change in (lambda f: None, lambda f: bytearray(f), lambda f: f[:-1], lambda f: f+b'x',
                       lambda f: f[:-1]+bytes([f[-1]^1]), lambda f: b'x'*9000):
            c, b = self.pair(); frame = c.request(envelope())
            self.rejects(b, lambda: b.accept_request(change(frame)))

    def test_authenticated_changed_source_commit_or_recipient_is_not_original_proof(self):
        for change in (lambda v: v.update(grant_fingerprint='d'*64),
                       lambda v: v.update(association_id='d'*64),
                       lambda v: v['recipient_channel'].update(pid=125),
                       lambda v: v.update(source_commit_json=v['source_commit_json'].replace('"draft_revision":1', '"draft_revision":2'))):
            c, b = self.requested(); other, peer = self.pair(); value = envelope(); change(value)
            peer.accept_request(other.request(value))
            self.rejects(c, lambda: c.accept_proof(peer.prove()))

    def test_key_role_session_phase_and_transcript_mutation_are_terminal(self):
        for field, value in (('_key', b'x'*32), ('_role', 'broker'), ('_session', 'f'*64),
                             ('_step', True), ('_step', 0), ('_previous', 'f'*64), ('_state', 'active')):
            c, b = self.requested(); setattr(c, field, value)
            self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_binding_mutation_and_equal_valued_snapshot_type_changes_are_terminal(self):
        class String(str): pass
        for field, change in (('_binding', lambda v: bytearray(v)),
                              ('_binding_snapshot', lambda v: v+b' '),
                              ('_binding_digest', lambda v: 'f'*64),
                              ('_role_snapshot', String), ('_session_snapshot', String),
                              ('_key_snapshot', String), ('_phase_snapshot', list)):
            c, b = self.requested(); setattr(c, field, change(getattr(c, field)))
            self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_closed_state_rollback_cannot_restore_original_key(self):
        c, _ = self.pair(); c.close(); c._state, c._step = 'new', 0
        self.rejects(c, lambda: c.request(envelope()))

    def test_reentrant_close_during_frame_construction_withholds_output(self):
        c, _ = self.pair(); original = c._encode
        def encode(*args):
            result = original(*args); c.close(); return result
        with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.request(envelope()))

    def test_substituted_or_deleted_locks_are_never_entered_and_spend_endpoint(self):
        class Foreign:
            def __enter__(self): raise AssertionError('foreign lock entered')
            def __exit__(self, *_): pass
        for name in ('_lock', '_issued_lock'):
            for bad in (Foreign(), RLock(), None):
                c, b = self.requested(); original = getattr(c, name); setattr(c, name, bad)
                try: self.rejects(c, lambda: c.accept_proof(b.prove()))
                finally: setattr(c, name, original)
            c, b = self.requested(); original = getattr(c, name); delattr(c, name)
            try: self.rejects(c, lambda: c.accept_proof(b.prove()))
            finally: setattr(c, name, original)

    def test_close_with_replaced_lock_retires_key_without_dispatching_foreign_lock(self):
        class Foreign:
            def __enter__(self): raise AssertionError('foreign lock entered')
            def __exit__(self, *_): pass
        for name in ('_lock', '_issued_lock'):
            c, _ = self.requested(); original = getattr(c, name); setattr(c, name, Foreign())
            try: self.rejects(c, c.close)
            finally: setattr(c, name, original)

    def test_reentrant_lock_mutation_during_frame_construction_withholds_output(self):
        c, _ = self.pair(); original_encode, original_lock = c._encode, c._lock
        def encode(*args):
            result = original_encode(*args); c._lock = None; return result
        try:
            with patch.object(c, '_encode', side_effect=encode): self.rejects(c, lambda: c.request(envelope()))
        finally: c._lock = original_lock

    def test_canonical_binding_bound_is_checked_independently_of_frame_encoding(self):
        original = protocol._canonical
        with patch.object(protocol, '_canonical', side_effect=lambda value: original(value)+b' '*8192):
            with self.assertRaises(ValueError): protocol._association_binding(envelope())

    def test_generated_corrupted_frame_is_withheld(self):
        c, b = self.requested(); original = b._frame
        def frame(*args):
            result = original(*args); return result[:-1]+bytes([result[-1]^1])
        with patch.object(b, '_frame', side_effect=frame): self.rejects(b, b.prove)

    def test_evidence_mutation_during_construction_is_rejected(self):
        for field, bad in (('released_bytes', True), ('meaning', 'permission'),
                           ('outcome', 'allowed'), ('canonical_binding', b'{}'), ('binding_digest', 'f'*64)):
            c, b = self.requested(); original = c._evidence
            def evidence(outcome):
                result = original(outcome); object.__setattr__(result, field, bad); return result
            with patch.object(c, '_evidence', side_effect=evidence): self.rejects(c, lambda: c.accept_proof(b.prove()))

    def test_two_concurrent_requests_emit_at_most_one_frame(self):
        c, _ = self.pair()
        def attempt():
            try: return c.request(envelope())
            except BrokerProtocolError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.terminal(c)

    def test_data_dry_commit_and_model_interfaces_are_explicitly_terminal(self):
        for name in ('reply', 'accept_reply', 'prepare', 'accept_prepare', 'ready', 'accept_ready',
                     'dry_commit', 'accept_dry_commit', 'receipt', 'accept_receipt',
                     'model_visibility', 'accept_model_visibility', 'receipt_claim', 'accept_receipt_claim',
                     'payload', 'accept_payload', 'data', 'publish', 'release', 'acquire'):
            c, _ = self.pair(); self.rejects(c, lambda: getattr(c, name)())

    def test_no_file_callback_buffer_clock_or_authorization_interface_exists(self):
        c, b = self.pair()
        for endpoint in (c, b):
            for name in ('read', 'open_path', 'execute', 'grant', 'authorize', '_buffer', '_timer', '_deadline'):
                self.assertFalse(hasattr(endpoint, name))


if __name__ == '__main__': unittest.main()
