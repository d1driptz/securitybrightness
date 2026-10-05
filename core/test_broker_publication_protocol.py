"""Adversarial synthetic transcripts; no process, resource or delivery I/O."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import time
import unittest
from unittest.mock import patch

from core import broker_publication_protocol as protocol
from core.broker_protocol import BrokerProtocolError, FixtureBrokerExchange, _canonical
from core.broker_quarantine import QuarantinedReadExchange
from core.test_broker_quarantine import context


def recipient(application_id='app'):
    return dict(application_id=application_id, recipient_session='7'*64, recipient_id='8'*64, recipient_revision=1)


class PublicationProtocolTests(unittest.TestCase):
    def pair(self, timeout=5, key=b'k'*32, session=b's'*32):
        pair = [protocol.PublicationCheckExchange(role=role, key=key, session=session, timeout=timeout)
                for role in ('coordinator', 'broker')]
        for endpoint in pair:
            self.addCleanup(endpoint.close)
        return pair

    def opened(self, value=None, destination=None, **kwargs):
        coordinator, broker = self.pair(**kwargs)
        evidence = broker.accept_request(coordinator.request(context() if value is None else value,
                                                              recipient() if destination is None else destination))
        return coordinator, broker, evidence

    def staged(self, size=37, outcome='staged', **kwargs):
        coordinator, broker, _ = self.opened(context(size), **kwargs)
        frame = broker.reply(outcome=outcome, data=b'x'*size if outcome == 'staged' else b'')
        summary = coordinator.accept_reply(frame)
        return coordinator, broker, frame, summary

    def retired(self, size=37, outcome='staged', **kwargs):
        coordinator, broker, frame, summary = self.staged(size, outcome, **kwargs)
        retirement = coordinator.retire_for_check()
        broker.accept_retirement(retirement)
        ack = broker.acknowledge_retirement()
        receipt = coordinator.accept_retirement_ack(ack)
        return coordinator, broker, ack, summary, receipt

    def terminal(self, endpoint):
        self.assertEqual(endpoint._state, 'closed')
        self.assertEqual(endpoint._buffer, bytearray())
        self.assertEqual(endpoint._issued_buffer, bytearray())
        self.assertEqual(endpoint._key, b'')

    def test_exact_recipient_envelope_is_metadata_and_detached(self):
        coordinator, broker = self.pair()
        value, destination = context(), recipient()
        frame = coordinator.request(value, destination)
        value['max_bytes'] = 4096
        destination['recipient_revision'] = 2
        evidence = broker.accept_request(frame)
        self.assertEqual(evidence.inspect(), dict(context=context(), recipient=recipient()))
        evidence.inspect()['recipient']['recipient_id'] = '9'*64
        self.assertEqual(evidence.inspect()['recipient']['recipient_id'], '8'*64)
        with self.assertRaises(TypeError):
            bool(evidence)

    def test_recipient_validation_detaches_before_external_callback_mutation(self):
        coordinator, broker = self.pair()
        destination = recipient()
        original = protocol._recipient
        def captured(*args):
            result = original(*args); destination['recipient_id'] = '9'*64; return result
        with patch.object(protocol, '_recipient', side_effect=captured):
            frame = coordinator.request(context(), destination)
        self.assertEqual(broker.accept_request(frame).inspect()['recipient'], recipient())

    def test_retirement_retains_private_buffer_only_and_deadline_survives_ack(self):
        coordinator, broker, _, summary, receipt = self.retired()
        self.assertEqual(coordinator._state, 'retired_for_check')
        self.assertEqual(coordinator._key, b'')
        self.assertEqual(coordinator._buffer, bytearray(b'x'*37))
        self.assertIsNone(coordinator.validate_retained())
        self.assertTrue(coordinator._timer.is_alive())
        self.assertEqual(summary.staged_bytes, 37)
        self.assertEqual(receipt.staged_bytes, 37)
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(receipt.outcome, 'retired_for_check')
        self.assertNotIn('data', asdict(summary))
        self.assertNotIn('data', asdict(receipt))
        with self.assertRaises(TypeError):
            bool(receipt)
        self.terminal(broker)

    def test_denied_staging_can_only_retire_zero_bytes(self):
        coordinator, _, _, _, receipt = self.retired(outcome='denied')
        self.assertEqual(receipt.staged_bytes, 0)
        self.assertEqual(receipt.staged_digest, hashlib.sha256(b'').hexdigest())
        self.assertEqual(coordinator._buffer, bytearray())

    def test_zero_and_maximum_exact_staged_boundaries(self):
        for size in (0, 1, 4095, 4096):
            with self.subTest(size=size):
                coordinator, _, _, _, receipt = self.retired(size)
                self.assertEqual(receipt.staged_bytes, size)
                coordinator.validate_retained()

    def test_old_profiles_cannot_splice_authenticated_frames(self):
        for exchange in (FixtureBrokerExchange, QuarantinedReadExchange):
            coordinator, _, _ = self.opened()
            old = exchange(role='broker', key=b'k'*32, session=b's'*32)
            self.addCleanup(old.close)
            frame = old._encode('reply', dict(step=1, previous=coordinator._previous,
                                               message_json=_canonical(dict(binding_digest=coordinator._binding_digest,
                                                                          outcome='denied', data='')).decode()))
            with self.subTest(profile=exchange.__name__), self.assertRaises(BrokerProtocolError):
                coordinator.accept_reply(frame)
            self.terminal(coordinator)

    def test_new_profile_cannot_splice_into_old_discard_profile(self):
        new, _ = self.pair()
        old = QuarantinedReadExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(old.close)
        with self.assertRaises(BrokerProtocolError):
            old.accept_request(new.request(context(), recipient()))
        self.assertEqual(old._state, 'closed')
        self.assertEqual(old._buffer, bytearray())

    def test_old_discard_methods_fail_closed_without_returning_data(self):
        for name in ('discard', 'accept_discard', 'acknowledge_discard', 'accept_discard_ack'):
            coordinator, _, _, _, _ = self.retired()
            with self.subTest(method=name), self.assertRaises(BrokerProtocolError):
                getattr(coordinator, name)()
            self.terminal(coordinator)

    def test_signed_unsupported_retirement_actions_fail_closed(self):
        for action in ('release', 'publish', 'discard', 'read', 'execute', 'allow'):
            coordinator, broker, _, _ = self.staged()
            value = coordinator._retirement()
            value['action'] = action
            with self.subTest(action=action), self.assertRaises(BrokerProtocolError):
                broker.accept_retirement(coordinator._frame('request', value))
            self.terminal(broker)
            coordinator.close()
            self.terminal(coordinator)

    def test_signed_ack_type_confusion_or_extra_fields_fail_closed(self):
        for change in (dict(released_bytes=False), dict(released_bytes=37), dict(staged_bytes=True),
                       dict(staged_bytes=38), dict(outcome='released'), dict(data='secret'), dict(permission=True)):
            coordinator, broker, _, _ = self.staged()
            broker.accept_retirement(coordinator.retire_for_check())
            value = broker._retirement_ack()
            value.update(change)
            with self.subTest(change=change), self.assertRaises(BrokerProtocolError):
                coordinator.accept_retirement_ack(broker._frame('reply', value))
            self.terminal(coordinator)

    def test_signed_retirement_type_confusion_or_extra_fields_rejected(self):
        for change in (dict(staged_bytes=True), dict(staged_bytes=38), dict(data='secret'), dict(authority=True)):
            coordinator, broker, _, _ = self.staged()
            value = coordinator._retirement(); value.update(change)
            with self.subTest(change=change), self.assertRaises(BrokerProtocolError):
                broker.accept_retirement(coordinator._frame('request', value))
            self.terminal(broker)

    def test_context_authority_effect_or_path_fields_rejected(self):
        for field in ('approved', 'permission', 'path', 'reference', 'effects', 'attributes'):
            coordinator, _ = self.pair()
            value = context(); value[field] = True
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                coordinator.request(value, recipient())
            self.terminal(coordinator)

    def test_context_missing_fields_and_type_confusion_rejected(self):
        for field, value in [('draft_revision', True), ('max_bytes', True), ('size_bytes', True),
                             ('volume_serial', True), ('file_id', 'G'*32), ('review_id', 'X'*64),
                             ('max_bytes', 4097), ('size_bytes', 38), ('recipient', 'other'),
                             ('operation', 'files.write'), ('application_id', ' app')]:
            coordinator, _ = self.pair(); candidate = context(); candidate[field] = value
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                coordinator.request(candidate, recipient())
            self.terminal(coordinator)
        coordinator, _ = self.pair(); candidate = context(); del candidate['grant_id']
        with self.assertRaises(BrokerProtocolError):
            coordinator.request(candidate, recipient())

    def test_recipient_application_identity_revision_and_fields_strict(self):
        for field, value in [('application_id', 'other'), ('recipient_session', 'X'*64),
                             ('recipient_id', '7'*64), ('recipient_id', '2'*64),
                             ('recipient_revision', True), ('recipient_revision', 0),
                             ('recipient_revision', 2**31), ('recipient_id', 'x'*10000)]:
            coordinator, _ = self.pair(); candidate = recipient(); candidate[field] = value
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                coordinator.request(context(), candidate)
            self.terminal(coordinator)
        for field in ('path', 'pid', 'permission', 'address', 'authority'):
            coordinator, _ = self.pair(); candidate = recipient(); candidate[field] = True
            with self.assertRaises(BrokerProtocolError):
                coordinator.request(context(), candidate)
        coordinator, _ = self.pair(); candidate = recipient(); del candidate['recipient_id']
        with self.assertRaises(BrokerProtocolError):
            coordinator.request(context(), candidate)

    def test_each_recipient_id_is_disjoint_from_context_identities(self):
        for target in ('recipient_session', 'recipient_id'):
            for field in ('review_id', 'decision_id', 'registry_session', 'owner_session', 'resource_token'):
                coordinator, _ = self.pair(); candidate = recipient(); candidate[target] = context()[field]
                with self.subTest(target=target, context_field=field), self.assertRaises(BrokerProtocolError):
                    coordinator.request(context(), candidate)
                self.terminal(coordinator)

    def test_every_recipient_or_context_substitution_breaks_transcript(self):
        for group, field, value in [('recipient', 'recipient_session', '9'*64),
                                    ('recipient', 'recipient_id', '9'*64),
                                    ('recipient', 'recipient_revision', 2),
                                    ('context', 'file_id', '9'*32), ('context', 'draft_revision', 2),
                                    ('context', 'review_id', '9'*64), ('context', 'max_bytes', 128),
                                    ('context', 'proposal_id', 'sbp2_sha256_'+'9'*64)]:
            coordinator, _, _ = self.opened()
            ctx, destination = context(), recipient()
            (ctx if group == 'context' else destination)[field] = value
            _, broker, _ = self.opened(ctx, destination)
            with self.subTest(group=group, field=field), self.assertRaises(BrokerProtocolError):
                coordinator.accept_reply(broker.reply(outcome='staged', data=b'x'*37))
            self.terminal(coordinator)

    def test_replayed_stage_retirement_or_ack_never_restores_bytes(self):
        coordinator, broker, frame, _ = self.staged()
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
        self.terminal(coordinator)
        coordinator, broker, _, _ = self.staged()
        frame = coordinator.retire_for_check(); broker.accept_retirement(frame)
        with self.assertRaises(BrokerProtocolError): broker.accept_retirement(frame)
        self.terminal(broker)
        coordinator, _, ack, _, _ = self.retired()
        with self.assertRaises(BrokerProtocolError): coordinator.accept_retirement_ack(ack)
        self.terminal(coordinator)

    def test_wrong_roles_and_sequences_wipe(self):
        for action in (lambda endpoint: endpoint.retire_for_check(),
                       lambda endpoint: endpoint.acknowledge_retirement(),
                       lambda endpoint: endpoint.reply(outcome='denied'),
                       lambda endpoint: endpoint.validate_retained()):
            coordinator, _, _ = self.opened()
            with self.assertRaises(BrokerProtocolError): action(coordinator)
            self.terminal(coordinator)

    def test_signed_transcript_type_confusion_and_version_mismatch(self):
        for step in (True, 0, 2):
            coordinator, broker, _ = self.opened()
            value = dict(binding_digest=broker._binding_digest, outcome='denied', data='')
            frame = broker._encode('reply', dict(step=step, previous=broker._previous,
                                                 message_json=_canonical(value).decode()))
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
            self.terminal(coordinator)
        coordinator, broker, _ = self.opened()
        body = _canonical(dict(version=2, session=broker._session, direction='reply', payload={}))
        signed = body+broker._mac('reply', body)
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(len(signed).to_bytes(4, 'big')+signed)
        self.terminal(coordinator)

    def test_malformed_oversized_and_noncanonical_input_wipes(self):
        for frame in (None, bytearray(b'x'*40), b'x'*9000, b'\0'*36, b'\0'*39):
            coordinator, _, _ = self.opened()
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
            self.terminal(coordinator)
        for encoded in ('@@', 'eA==\n', 'eB==', 'x'*5465):
            coordinator, broker, _ = self.opened(context(1))
            value = dict(binding_digest=broker._binding_digest, outcome='staged', data=encoded)
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker._frame('reply', value))
            self.terminal(coordinator)

    def test_signed_denial_with_bytes_and_partial_staging_rejected(self):
        coordinator, broker, _ = self.opened()
        value = dict(binding_digest=broker._binding_digest, outcome='denied', data=base64.b64encode(b'x').decode())
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker._frame('reply', value))
        self.terminal(coordinator)
        for size in (0, 36, 38, 4097):
            _, broker, _ = self.opened()
            with self.assertRaises(BrokerProtocolError): broker.reply(outcome='staged', data=b'x'*size)
            self.terminal(broker)

    def test_retained_buffer_metadata_and_context_mutation_are_terminal(self):
        mutations = [lambda c: c._buffer.__setitem__(0, ord('z')),
                     lambda c: c._buffer.append(0), lambda c: setattr(c, '_buffer', bytearray(b'x'*37)),
                     lambda c: setattr(c, '_buffer', bytes(b'x'*37)),
                     lambda c: setattr(c, '_digest', '9'*64), lambda c: setattr(c, '_size', True),
                     lambda c: setattr(c, '_binding_digest', '9'*64),
                     lambda c: setattr(c, '_binding', c._binding+b' '),
                     lambda c: setattr(c, '_previous', '9'*64), lambda c: setattr(c, '_step', True),
                     lambda c: setattr(c, '_role', 'broker'), lambda c: setattr(c, '_session', '9'*64),
                     lambda c: setattr(c, '_deadline', c._deadline+10), lambda c: setattr(c, '_key', b'k'*32)]
        for mutate in mutations:
            coordinator, _, _, _, _ = self.retired(); original = coordinator._issued_buffer
            mutate(coordinator)
            with self.subTest(mutation=mutate), self.assertRaises(BrokerProtocolError): coordinator.validate_retained()
            self.assertEqual(original, bytearray())
            if type(coordinator._buffer) is bytearray: self.assertEqual(coordinator._buffer, bytearray())
            self.assertEqual(coordinator._state, 'closed')

    def test_semantic_summary_mutation_or_equal_type_aliases_rejected(self):
        class Text(str):
            pass
        for field in ('_role', '_session', '_previous', '_state'):
            coordinator, _, _, _, _ = self.retired()
            setattr(coordinator, field, Text(getattr(coordinator, field)))
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError): coordinator.validate_retained()
            self.terminal(coordinator)
        for index, value in ((2, True), (2, 0), (3, 'denied'), (3, Text('staged'))):
            coordinator, _, _, _, _ = self.retired()
            changed = list(coordinator._summary_snapshot); changed[index] = value
            coordinator._summary_snapshot = tuple(changed)
            with self.assertRaises(BrokerProtocolError): coordinator.validate_retained()
            self.terminal(coordinator)

    def test_close_zeros_original_buffer_despite_substituted_buffer_or_timer(self):
        coordinator, _, _, _, _ = self.retired()
        retained = coordinator._buffer
        coordinator._buffer = bytearray(b'evil')
        coordinator._timer = object()
        coordinator.close()
        self.terminal(coordinator)
        self.assertEqual(retained, bytearray())

    def test_timer_cancellation_failure_still_wipes_bytes_and_keys(self):
        coordinator, _, _, _, _ = self.retired()
        with patch.object(coordinator._timer_snapshot, 'cancel', side_effect=RuntimeError('fault')):
            with self.assertRaises(RuntimeError): coordinator.close()
        self.terminal(coordinator)

    def test_frame_generation_mutation_is_rechecked_before_retirement(self):
        coordinator, _, _, _ = self.staged()
        original = coordinator._frame
        def changed(*args):
            frame = original(*args); coordinator._buffer[0] = ord('z'); return frame
        with patch.object(coordinator, '_frame', side_effect=changed), self.assertRaises(BrokerProtocolError):
            coordinator.retire_for_check()
        self.terminal(coordinator)

    def test_reply_or_ack_frame_generation_mutation_withholds_frame(self):
        _, broker, _ = self.opened()
        original = broker._frame
        def changed(*args):
            frame = original(*args); broker._size = True; return frame
        with patch.object(broker, '_frame', side_effect=changed), self.assertRaises(BrokerProtocolError):
            broker.reply(outcome='staged', data=b'x'*37)
        self.terminal(broker)
        coordinator, broker, _, _ = self.staged()
        broker.accept_retirement(coordinator.retire_for_check()); original = broker._frame
        def changed(*args):
            frame = original(*args); broker._digest = '9'*64; return frame
        with patch.object(broker, '_frame', side_effect=changed), self.assertRaises(BrokerProtocolError):
            broker.acknowledge_retirement()
        self.terminal(broker)

    def test_expiry_during_staging_or_ack_returns_no_metadata(self):
        coordinator, broker, _ = self.opened()
        frame = broker.reply(outcome='staged', data=b'x'*37)
        original = coordinator._stage; current = [coordinator._deadline-1]
        def stage(*args):
            result = original(*args); current[0] = coordinator._deadline; return result
        with patch.object(coordinator, '_stage', side_effect=stage), patch.object(protocol, 'monotonic', side_effect=lambda: current[0]):
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
        self.terminal(coordinator)
        coordinator, broker, _, _ = self.staged()
        broker.accept_retirement(coordinator.retire_for_check()); ack = broker.acknowledge_retirement()
        with patch.object(protocol, 'monotonic', return_value=coordinator._deadline):
            with self.assertRaises(BrokerProtocolError): coordinator.accept_retirement_ack(ack)
        self.terminal(coordinator)

    def test_idle_timer_wipes_after_ack_and_key_closure(self):
        coordinator, _, _, _, _ = self.retired(timeout=.15)
        self.assertEqual(coordinator._buffer, bytearray(b'x'*37))
        deadline = time.monotonic()+2
        while coordinator._state != 'closed' and time.monotonic() < deadline: time.sleep(.005)
        self.terminal(coordinator)

    def test_close_after_ack_is_irreversible_and_wipes(self):
        coordinator, _, _, _, _ = self.retired()
        coordinator.close(); self.terminal(coordinator)
        with self.assertRaises(BrokerProtocolError): coordinator.validate_retained()
        with self.assertRaises(BrokerProtocolError): coordinator.request(context(), recipient())

    def test_concurrent_retirement_allows_only_one_attempt_then_wipes(self):
        coordinator, _, _, _ = self.staged()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(coordinator.retire_for_check) for _ in range(2)]
        self.assertEqual(sum(f.exception() is None for f in futures), 1)
        self.terminal(coordinator)

    def test_invalid_lifetime_and_no_release_or_executor_api(self):
        for timeout in (True, 0, -1, 6, float('inf'), float('nan')):
            with self.assertRaises(ValueError): self.pair(timeout)
        coordinator, _, _, _, _ = self.retired()
        for name in ('release', 'publish', 'read', 'execute', 'take_buffer', 'data', 'permission'):
            self.assertFalse(hasattr(coordinator, name))

    def test_authenticated_peer_can_only_claim_retirement_not_current_authority(self):
        coordinator, broker, _, _, receipt = self.retired()
        self.assertIn('claim only', receipt.meaning)
        self.assertNotIn('authority', asdict(receipt))
        coordinator.validate_retained()
        self.assertEqual(coordinator._buffer, bytearray(b'x'*37))
        self.terminal(broker)
