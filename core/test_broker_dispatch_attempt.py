"""Adversarial inactive dispatch accounting; no native transport or delivery.

Synthetic peer receipts are claims. Cancellation here models lost authority or
transport; these tests do not pretend to exercise a registry or a real read.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict
import hashlib
from threading import Barrier, Event, RLock
import unittest
from unittest.mock import patch

from core import broker_dispatch_attempt as model
from core.broker_dispatch_model_protocol import PublicationDispatchExchange
from core.test_broker_publication_commit_protocol import envelope


class DispatchAttemptTests(unittest.TestCase):
    def ledger(self, **options):
        value = model.PublicationDispatchLedger(**options)
        self.addCleanup(value.close)
        return value

    def opened(self, value=None, *, ledger=None, **options):
        ledger = self.ledger() if ledger is None else ledger
        attempt = ledger.open(envelope() if value is None else value,
                              key=b'k'*32, session=b's'*32, **options)
        return ledger, attempt

    def prepared(self, **options):
        ledger, attempt = self.opened(**options)
        peer = PublicationDispatchExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(peer.close)
        self.prepare_frame = attempt.prepare()
        self.prepare_evidence = peer.accept_prepare(self.prepare_frame)
        return ledger, attempt, peer

    def ready(self, **options):
        ledger, attempt, peer = self.prepared(**options)
        self.ready_frame = peer.ready()
        attempt.accept_ready(self.ready_frame)
        return ledger, attempt, peer

    def visible(self, **options):
        ledger, attempt, peer = self.ready(**options)
        self.visibility_frame = attempt.begin_model_visibility()
        peer.accept_model_visibility(self.visibility_frame)
        return ledger, attempt, peer

    def awaiting(self, **options):
        ledger, attempt, peer = self.visible(**options)
        attempt.record_model_write(envelope()['staged_bytes'])
        return ledger, attempt, peer

    def claimed(self):
        ledger, attempt, peer = self.awaiting()
        self.receipt_frame = peer.receipt_claim(claimed_bytes=envelope()['staged_bytes'],
                                               claimed_digest=envelope()['staged_digest'])
        attempt.accept_receipt_claim(self.receipt_frame)
        return ledger, attempt, peer

    def state(self, attempt, expected, *, possible=False, written=0, claimed=None):
        value = attempt.inspect()
        self.assertIs(type(value), model.DispatchAttemptSnapshot)
        self.assertEqual(value.state, expected)
        self.assertIs(value.visibility_possible, possible)
        self.assertIs(type(value.model_written_bytes), int)
        self.assertEqual(value.model_written_bytes, written)
        self.assertEqual(value.receiver_claimed_bytes, claimed)
        self.assertEqual(value.observed_delivery, 'unproven')
        self.assertIs(type(value.meaning), str)
        with self.assertRaises(TypeError):
            bool(value)
        return value

    def rejected(self, operation):
        with self.assertRaises(model.DispatchAttemptError):
            operation()

    def unique(self, index):
        value = envelope()
        value['binding']['context']['decision_id'] = f'{100+index:064x}'
        value['binding']['context']['resource_token'] = f'{1000+index:064x}'
        return value

    def test_full_simulated_exchange_is_only_a_claim_not_delivery_or_permission(self):
        _, attempt, _ = self.claimed()
        snapshot = self.state(attempt, 'receiver_claimed', possible=True, written=37, claimed=37)
        self.assertRegex(snapshot.attempt_id, '^[0-9a-f]{64}$')
        self.assertRegex(snapshot.binding_digest, '^[0-9a-f]{64}$')
        self.assertNotIn('data', asdict(snapshot))
        self.assertNotIn('permission', asdict(snapshot))
        self.assertNotIn('authority', asdict(snapshot))
        self.assertIn('model', snapshot.meaning.lower())

    def test_public_phase_progression_records_no_write_before_visibility(self):
        _, attempt = self.opened()
        self.state(attempt, 'new')
        peer = PublicationDispatchExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(peer.close)
        peer.accept_prepare(attempt.prepare())
        self.state(attempt, 'prepared')
        attempt.accept_ready(peer.ready())
        self.state(attempt, 'ready')
        attempt.begin_model_visibility()
        self.state(attempt, 'visibility_possible', possible=True)
        attempt.record_model_write(37)
        self.state(attempt, 'awaiting_claim', possible=True, written=37)

    def test_closed_before_visibility_is_permanently_not_started(self):
        ledger, attempt, _ = self.ready()
        attempt.close(); attempt.close()
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)
        self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))

    def test_cancel_after_visibility_is_unknown_even_with_zero_modeled_bytes(self):
        _, attempt, _ = self.visible()
        attempt.close(); attempt.close()
        self.state(attempt, 'outcome_unknown', possible=True)
        self.rejected(lambda: attempt.record_model_write(37))

    def test_lost_claim_after_full_simulated_write_never_implies_zero_delivery(self):
        _, attempt, _ = self.awaiting()
        attempt.close()
        self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_terminal_receiver_claim_survives_idempotent_close_as_unproven(self):
        _, attempt, _ = self.claimed()
        attempt.close(); attempt.close()
        self.state(attempt, 'receiver_claimed', possible=True, written=37, claimed=37)

    def test_partial_or_zero_model_write_is_terminal_unknown_without_retry(self):
        for count in (0, 1, 36):
            with self.subTest(count=count):
                _, attempt, _ = self.visible()
                attempt.record_model_write(count)
                self.state(attempt, 'outcome_unknown', possible=True, written=count)
                self.rejected(lambda: attempt.record_model_write(37))
                self.rejected(attempt.begin_model_visibility)

    def test_zero_size_full_simulated_write_still_is_not_observed_delivery(self):
        value = envelope()
        value['staged_bytes'] = value['binding']['context']['size_bytes'] = 0
        value['staged_digest'] = hashlib.sha256(b'').hexdigest()
        _, attempt, peer = self.ready(value=value)
        peer.accept_model_visibility(attempt.begin_model_visibility())
        attempt.record_model_write(0)
        attempt.accept_receipt_claim(peer.receipt_claim(claimed_bytes=0, claimed_digest=value['staged_digest']))
        self.state(attempt, 'receiver_claimed', possible=True, written=0, claimed=0)

    def test_write_count_rejects_type_confusion_and_out_of_bounds(self):
        for count in (True, False, 37.0, '37', b'37', None, -1, 38, 2**64):
            with self.subTest(count=count):
                _, attempt, _ = self.visible()
                self.rejected(lambda: attempt.record_model_write(count))
                self.state(attempt, 'outcome_unknown', possible=True)

    def test_model_write_cannot_precede_visibility(self):
        _, attempt, _ = self.ready()
        self.rejected(lambda: attempt.record_model_write(37))
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)

    def test_duplicate_full_model_write_is_not_a_second_operation(self):
        _, attempt, _ = self.awaiting()
        self.rejected(lambda: attempt.record_model_write(37))
        self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_visibility_before_ready_latches_not_started(self):
        _, attempt = self.opened()
        self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'not_started')
        self.rejected(attempt.prepare)

    def test_visibility_barrier_is_irrevocably_spent_before_serialization(self):
        _, attempt, _ = self.ready()
        seen = []
        def fail():
            seen.append((attempt._attempted, attempt._visibility_possible))
            raise ValueError('synthetic serializer failure')
        with patch.object(attempt._issued_wire, 'model_visibility', side_effect=fail):
            self.rejected(attempt.begin_model_visibility)
        self.assertEqual(seen, [(True, True)])
        self.state(attempt, 'outcome_unknown', possible=True)
        self.rejected(attempt.begin_model_visibility)

    def test_reentrant_cancel_at_visibility_serialization_withholds_notice(self):
        _, attempt, _ = self.ready()
        original = attempt._issued_wire.model_visibility
        def close_during_encode():
            result = original(); attempt.close(); return result
        with patch.object(attempt._issued_wire, 'model_visibility', side_effect=close_during_encode):
            self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_malformed_ready_latches_not_started(self):
        for frame in (None, True, b'', bytearray(36), b'x'*9000):
            _, attempt, _ = self.prepared()
            self.rejected(lambda: attempt.accept_ready(frame))
            self.state(attempt, 'not_started')

    def test_replayed_prepare_spends_attempt(self):
        _, attempt, _ = self.prepared()
        self.rejected(attempt.prepare)
        self.state(attempt, 'not_started')

    def test_replayed_ready_spends_attempt(self):
        _, attempt, _ = self.ready()
        self.rejected(lambda: attempt.accept_ready(self.ready_frame))
        self.state(attempt, 'not_started')

    def test_replayed_visibility_can_never_generate_a_second_notice(self):
        _, attempt, _ = self.visible()
        self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_early_receipt_claim_without_a_modeled_full_write_is_rejected(self):
        _, attempt, peer = self.visible()
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        self.rejected(lambda: attempt.accept_receipt_claim(frame))
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_malformed_receipt_cannot_turn_unknown_into_zero_delivery(self):
        for frame in (None, True, b'', bytearray(36), b'x'*9000):
            _, attempt, _ = self.awaiting()
            self.rejected(lambda: attempt.accept_receipt_claim(frame))
            self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_duplicate_receipt_never_restores_reusability(self):
        ledger, attempt, _ = self.claimed()
        self.rejected(lambda: attempt.accept_receipt_claim(self.receipt_frame))
        self.rejected(attempt.begin_model_visibility)
        self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))
        self.assertEqual(attempt.inspect().observed_delivery, 'unproven')

    def test_source_mutation_after_open_cannot_change_prepared_binding(self):
        value = envelope(); _, attempt = self.opened(value)
        value['staged_bytes'] = 1
        value['binding']['context']['application_id'] = 'other'
        peer = PublicationDispatchExchange(role='broker', key=b'k'*32, session=b's'*32)
        self.addCleanup(peer.close)
        claim = peer.accept_prepare(attempt.prepare()).inspect()['commit']
        self.assertEqual(claim, envelope())

    def test_inspection_snapshot_is_frozen_and_not_a_mutable_capability(self):
        _, attempt, _ = self.ready()
        snapshot = attempt.inspect()
        with self.assertRaises(FrozenInstanceError): snapshot.visibility_possible = True
        self.assertNotIn('key', asdict(snapshot))
        self.assertNotIn('frame', asdict(snapshot))

    def test_decision_reuse_rejected_even_after_recipient_or_request_changes(self):
        ledger, attempt = self.opened(); attempt.close()
        for mutation in (lambda v: v['binding']['recipient'].update(recipient_id='b'*64),
                         lambda v: v['binding']['context'].update(resource_token='c'*64),
                         lambda v: v.update(commit_id='d'*64)):
            value = envelope(); mutation(value)
            self.rejected(lambda: ledger.open(value, key=b'k'*32, session=b's'*32))

    def test_resource_token_reuse_rejected_even_with_a_new_decision(self):
        ledger, attempt = self.opened(); attempt.close()
        value = envelope(); value['binding']['context']['decision_id'] = 'c'*64
        self.rejected(lambda: ledger.open(value, key=b'k'*32, session=b's'*32))

    def test_capacity_does_not_evict_cancelled_or_completed_claims(self):
        ledger = self.ledger(max_attempts=1)
        _, attempt = self.opened(ledger=ledger); attempt.close()
        self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
        self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))

    def test_independent_untrusted_ids_can_only_create_independent_model_records(self):
        ledger = self.ledger(max_attempts=2)
        _, first = self.opened(ledger=ledger)
        _, second = self.opened(self.unique(1), ledger=ledger)
        self.assertNotEqual(first.inspect().attempt_id, second.inspect().attempt_id)
        self.state(first, 'new'); self.state(second, 'new')

    def test_ledger_close_cancels_all_original_attempts_and_is_permanent(self):
        ledger = self.ledger(max_attempts=2)
        _, first, _ = self.ready(ledger=ledger)
        _, second, _ = self.visible(value=self.unique(1), ledger=ledger)
        ledger.close(); ledger.close()
        self.state(first, 'not_started')
        self.state(second, 'outcome_unknown', possible=True)
        self.rejected(lambda: ledger.open(self.unique(2), key=b'k'*32, session=b's'*32))

    def test_bad_constructor_capacity_types_do_not_create_an_unsafe_ledger(self):
        for value in (True, False, 0, -1, 129, 1.5, None, '1'):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                model.PublicationDispatchLedger(max_attempts=value)

    def test_bad_lifetimes_and_bootstrap_types_are_rejected(self):
        for timeout in (True, False, 0, -1, 5.001, float('inf'), float('nan'), None, '5'):
            ledger = self.ledger()
            with self.subTest(timeout=timeout), self.assertRaises((TypeError, ValueError, model.DispatchAttemptError)):
                ledger.open(envelope(), key=b'k'*32, session=b's'*32, timeout=timeout)
        for name, value in (('key', bytearray(32)), ('key', b'x'), ('session', True), ('session', b'x')):
            ledger = self.ledger(); options = dict(key=b'k'*32, session=b's'*32); options[name] = value
            with self.subTest(name=name, value=value), self.assertRaises((TypeError, ValueError, model.DispatchAttemptError)):
                ledger.open(envelope(), **options)

    def test_injected_authority_payload_or_ports_are_rejected_at_open(self):
        for name in ('data', 'callback', 'authority', 'permission', 'expires_at', 'path', 'publish'):
            ledger = self.ledger(); value = envelope(); value[name] = True
            self.rejected(lambda: ledger.open(value, key=b'k'*32, session=b's'*32))

    def test_malformed_open_does_not_claim_unrelated_valid_source(self):
        ledger = self.ledger()
        bad = envelope(); bad['binding']['context']['max_bytes'] = True
        self.rejected(lambda: ledger.open(bad, key=b'k'*32, session=b's'*32))
        _, attempt = self.opened(ledger=ledger)
        self.state(attempt, 'new')

    def test_nested_input_types_sizes_and_unsupported_fields_are_rejected(self):
        mutations = (
            lambda v: v.update(revision=True),
            lambda v: v.update(staged_bytes=True),
            lambda v: v.update(staged_bytes=-1),
            lambda v: v.update(staged_bytes=4097),
            lambda v: v.update(staged_digest='x'*10000),
            lambda v: v.update(mode='publish'),
            lambda v: v['binding']['context'].update(operation='files.write'),
            lambda v: v['binding']['context'].update(application_id='x'*10000),
            lambda v: v['binding']['context'].update(path='C:\\private'),
            lambda v: v['binding']['context'].update(authority=True),
            lambda v: v['binding']['recipient'].update(application_id='other'),
            lambda v: v['binding']['recipient'].update(recipient_revision=True),
            lambda v: v['channel'].update(pid=True),
            lambda v: v['channel'].update(creation_time=2**64),
            lambda v: v['channel'].update(witness_session='A'*64),
        )
        for mutate in mutations:
            value = envelope(); mutate(value); ledger = self.ledger()
            self.rejected(lambda: ledger.open(value, key=b'k'*32, session=b's'*32))
        for value in (None, True, [], b'{}', '{}'):
            ledger = self.ledger()
            self.rejected(lambda: ledger.open(value, key=b'k'*32, session=b's'*32))

    def test_expired_before_visibility_is_not_started_without_reservation_reuse(self):
        ledger, attempt, _ = self.ready()
        with patch.object(model, 'monotonic', return_value=attempt._deadline_snapshot+1):
            self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'not_started')
        self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))

    def test_expiry_after_visibility_is_unknown_and_rejects_late_claim(self):
        _, attempt, peer = self.awaiting()
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        with patch.object(model, 'monotonic', return_value=attempt._deadline_snapshot+1):
            self.rejected(lambda: attempt.accept_receipt_claim(frame))
        self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_deadline_extension_is_rejected_without_prolonging_model_use(self):
        _, attempt, _ = self.ready()
        attempt._deadline += 1000
        self.rejected(attempt.begin_model_visibility)
        self.rejected(attempt.inspect)
        attempt._deadline = attempt._deadline_snapshot
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)

    def test_cancel_event_replacement_cannot_restore_use(self):
        _, attempt, _ = self.ready()
        original = attempt._issued_cancel
        attempt._cancel = Event()
        self.rejected(attempt.begin_model_visibility)
        self.assertTrue(original.is_set())

    def test_clearing_cancel_event_cannot_restore_use(self):
        _, attempt, _ = self.ready()
        attempt.close(); attempt._issued_cancel.clear()
        self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'not_started')

    def test_replaced_wire_does_not_close_foreign_owner(self):
        _, attempt, _ = self.ready()
        original = attempt._issued_wire
        foreign = PublicationDispatchExchange(role='coordinator', key=b'f'*32, session=b'g'*32)
        self.addCleanup(foreign.close)
        attempt._wire = foreign
        self.rejected(attempt.begin_model_visibility)
        self.assertEqual(original._key, b'')
        self.assertEqual(foreign._key, b'f'*32)

    def test_replaced_ledger_cannot_transfer_source_ownership(self):
        original, attempt, _ = self.ready()
        foreign = self.ledger()
        _, other = self.opened(self.unique(1), ledger=foreign)
        attempt._ledger = foreign
        self.rejected(attempt.begin_model_visibility)
        self.state(other, 'new')
        attempt._ledger = original
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)

    def test_phase_type_confusion_cannot_be_used_as_progress(self):
        for field, value in (('_state', True), ('_attempted', 0), ('_visibility_possible', 0)):
            _, attempt, _ = self.ready()
            setattr(attempt, field, value)
            self.rejected(attempt.begin_model_visibility)

    def test_timer_replacement_does_not_cancel_foreign_owner(self):
        _, attempt, _ = self.ready()
        class ForeignTimer:
            cancelled = False
            def cancel(self): self.cancelled = True
        foreign = ForeignTimer(); attempt._timer = foreign
        self.rejected(attempt.begin_model_visibility)
        self.assertFalse(foreign.cancelled)

    def test_snapshot_mutation_is_not_reported_as_successful_delivery(self):
        _, attempt, _ = self.ready()
        object.__setattr__(attempt._issued_snapshot, 'observed_delivery', 'verified')
        self.rejected(attempt.inspect)
        self.state(attempt, 'not_started')

    def test_equal_but_foreign_snapshot_cannot_replace_original_record(self):
        _, attempt, _ = self.ready()
        from dataclasses import replace
        original = attempt._issued_snapshot
        attempt._snapshot = replace(original)
        self.rejected(attempt.begin_model_visibility)
        self.state(attempt, 'not_started')

    def test_mutated_claim_cannot_become_proof_of_delivery_or_authority(self):
        _, attempt, _ = self.claimed()
        object.__setattr__(attempt._claim, 'observed_delivery', 'verified')
        self.rejected(attempt.inspect)
        self.rejected(attempt.begin_model_visibility)

    def test_terminal_state_rollback_cannot_restore_visibility(self):
        _, attempt, _ = self.visible(); attempt.close()
        attempt._state = 'ready'; attempt._attempted = False
        attempt._visibility_possible = False
        self.rejected(attempt.begin_model_visibility)
        attempt._state = 'outcome_unknown'; attempt._attempted = True
        attempt._visibility_possible = True
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_preparation_serialization_failure_latches_no_start(self):
        _, attempt = self.opened()
        with patch.object(attempt._issued_wire, 'prepare', side_effect=ValueError('synthetic serializer failure')):
            self.rejected(attempt.prepare)
        self.state(attempt, 'not_started')

    def test_model_attempt_id_collisions_exhaust_bounded_retries_without_claim(self):
        ledger, attempt = self.opened()
        with patch.object(model.secrets, 'token_hex', return_value=attempt.inspect().attempt_id) as random_id:
            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
        self.assertEqual(random_id.call_count, 8)
        _, second = self.opened(self.unique(1), ledger=ledger)
        self.state(second, 'new')

    def test_model_attempt_id_must_not_alias_any_source_binding_id(self):
        for identifier in (envelope()['commit_id'], envelope()['channel']['witness_session'],
                           envelope()['binding']['context']['decision_id']):
            ledger = self.ledger()
            with patch.object(model.secrets, 'token_hex', return_value=identifier) as random_id:
                self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))
            self.assertEqual(random_id.call_count, 8)

    def test_reentrant_cancel_after_receipt_decode_withholds_claim(self):
        _, attempt, peer = self.awaiting()
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        original = attempt._issued_wire.accept_receipt_claim
        def cancelled(frame):
            value = original(frame); attempt.close(); return value
        with patch.object(attempt._issued_wire, 'accept_receipt_claim', side_effect=cancelled):
            self.rejected(lambda: attempt.accept_receipt_claim(frame))
        self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_idle_deadline_timer_retires_unused_claim_without_owner_polling(self):
        ledger, attempt = self.opened(timeout=0.1)
        self.assertTrue(attempt._issued_cancel.wait(1))
        self.state(attempt, 'not_started')
        self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))

    def test_idle_timer_after_visibility_records_unknown_and_never_retry(self):
        _, attempt, _ = self.visible(timeout=0.5)
        self.assertTrue(attempt._issued_cancel.wait(1))
        self.state(attempt, 'outcome_unknown', possible=True)
        self.rejected(attempt.begin_model_visibility)

    def test_decoded_receipt_type_confusion_and_mutation_are_rejected(self):
        class EqualString(str): pass
        mutations = (
            lambda value: object.__setattr__(value, 'claimed_bytes', True),
            lambda value: object.__setattr__(value, 'claimed_bytes', 36),
            lambda value: object.__setattr__(value, 'claimed_digest', 'b'*64),
            lambda value: object.__setattr__(value, 'canonical_binding', bytearray(value.canonical_binding)),
            lambda value: object.__setattr__(value, 'binding_digest', EqualString(value.binding_digest)),
            lambda value: object.__setattr__(value, 'meaning', EqualString(value.meaning)),
            lambda value: object.__setattr__(value, 'observed_delivery', 'verified'),
        )
        for mutate in mutations:
            _, attempt, peer = self.awaiting()
            frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
            original = attempt._issued_wire.accept_receipt_claim
            def changed(frame):
                result = original(frame); mutate(result); return result
            with patch.object(attempt._issued_wire, 'accept_receipt_claim', side_effect=changed):
                self.rejected(lambda: attempt.accept_receipt_claim(frame))
            self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_foreign_evidence_type_cannot_be_reported_as_a_receiver_claim(self):
        for value in (True, None, {'claimed_bytes': 37, 'permission': True}):
            _, attempt, _ = self.awaiting()
            with patch.object(attempt._issued_wire, 'accept_receipt_claim', return_value=value):
                self.rejected(lambda: attempt.accept_receipt_claim(b'foreign'))
            self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_prepare_callback_state_mutation_is_not_overwritten_as_valid(self):
        _, attempt = self.opened(); reached = []
        original = attempt._issued_wire.prepare
        def changed(value):
            frame = original(value); reached.append(True)
            attempt._state = 'prepared'
            return frame
        with patch.object(attempt._issued_wire, 'prepare', side_effect=changed):
            self.rejected(attempt.prepare)
        self.assertEqual(reached, [True])
        self.state(attempt, 'not_started')
        self.assertEqual(attempt._issued_wire._key, b'')

    def test_ready_callback_attempt_mutation_is_not_overwritten_as_valid(self):
        _, attempt, peer = self.prepared(); reached = []
        frame = peer.ready(); original = attempt._issued_wire.accept_ready
        def changed(frame):
            evidence = original(frame); reached.append(True)
            attempt._attempted = True
            return evidence
        with patch.object(attempt._issued_wire, 'accept_ready', side_effect=changed):
            self.rejected(lambda: attempt.accept_ready(frame))
        self.assertEqual(reached, [True])
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)

    def test_receipt_callback_snapshot_replacement_withholds_claim(self):
        from dataclasses import replace
        _, attempt, peer = self.awaiting(); reached = []
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        original = attempt._issued_wire.accept_receipt_claim
        def changed(frame):
            evidence = original(frame); reached.append(True)
            attempt._snapshot = replace(attempt._snapshot)
            return evidence
        with patch.object(attempt._issued_wire, 'accept_receipt_claim', side_effect=changed):
            self.rejected(lambda: attempt.accept_receipt_claim(frame))
        self.assertEqual(reached, [True])
        self.state(attempt, 'outcome_unknown', possible=True, written=37)

    def test_visibility_callback_equal_foreign_envelope_withholds_notice(self):
        _, attempt, _ = self.ready(); reached = []
        captured = attempt._envelope_snapshot
        original = attempt._issued_wire.model_visibility
        def changed():
            frame = original(); reached.append(True)
            attempt._envelope = bytes(bytearray(captured))
            self.assertIsNot(attempt._envelope, captured)
            return frame
        with patch.object(attempt._issued_wire, 'model_visibility', side_effect=changed):
            self.rejected(attempt.begin_model_visibility)
        self.assertEqual(reached, [True])
        attempt._envelope = captured
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_reentrant_close_after_claim_seal_preserves_only_unproven_claim(self):
        _, attempt, peer = self.awaiting(); reached = []
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        original = attempt._issued_timer.cancel
        def cancel():
            original()
            if not reached:
                reached.append(attempt._state)
                attempt.close()
        with patch.object(attempt._issued_timer, 'cancel', side_effect=cancel):
            snapshot = attempt.accept_receipt_claim(frame)
        self.assertEqual(reached, ['receiver_claimed'])
        self.assertEqual(snapshot.observed_delivery, 'unproven')
        self.state(attempt, 'receiver_claimed', possible=True, written=37, claimed=37)
        self.rejected(attempt.begin_model_visibility)

    def test_cleanup_timer_fault_closes_original_key_and_poison_blocks_fresh_claim(self):
        ledger = model.PublicationDispatchLedger()
        _, attempt, peer = self.awaiting(ledger=ledger)
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        reached = []
        def fail():
            reached.append(True); raise OSError('synthetic cleanup fault')
        try:
            with patch.object(attempt._issued_timer, 'cancel', side_effect=fail):
                self.rejected(lambda: attempt.accept_receipt_claim(frame))
            self.assertTrue(reached)
            self.assertEqual(attempt._issued_wire._key, b'')
            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
        finally:
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_replaced_issued_ownership_retires_original_and_preserves_foreign(self):
        original, attempt, _ = self.ready()
        foreign_ledger, foreign = self.opened(self.unique(1))
        captured = attempt._issued_ownership
        attempt._issued_ownership = (foreign_ledger, foreign_ledger._issued_lock)
        self.rejected(attempt.begin_model_visibility)
        self.assertEqual(attempt._issued_wire._key, b'')
        self.assertTrue(attempt._issued_timer.finished.is_set())
        self.assertFalse(foreign._issued_cancel.is_set())
        self.assertFalse(foreign._issued_timer.finished.is_set())
        self.state(foreign, 'new')
        attempt._issued_ownership = captured
        self.state(attempt, 'not_started')
        self.rejected(attempt.begin_model_visibility)
        self.rejected(lambda: original.open(envelope(), key=b'k'*32, session=b's'*32))

    def test_malformed_issued_ownership_has_fixed_error_and_cannot_restore_use(self):
        for value in (None, (), ('malformed',)):
            with self.subTest(value=value):
                _, attempt, _ = self.ready()
                original = attempt._issued_ownership
                attempt._issued_ownership = value
                self.rejected(attempt.begin_model_visibility)
                self.assertEqual(attempt._issued_wire._key, b'')
                attempt._issued_ownership = original
                self.state(attempt, 'not_started')
                self.rejected(attempt.begin_model_visibility)

    def test_replaced_ledger_lock_never_waits_on_foreign_lock_and_poison_is_final(self):
        ledger = model.PublicationDispatchLedger()
        attempt = ledger.open(envelope(), key=b'k'*32, session=b's'*32)
        original_lock = ledger._lock
        foreign_lock = RLock()
        foreign_lock.acquire()
        ledger._lock = foreign_lock
        try:
            def reserve():
                try: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32)
                except model.DispatchAttemptError: return 'rejected'
                return 'accepted'
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(reserve)
                try: self.assertEqual(future.result(timeout=1), 'rejected')
                finally: foreign_lock.release()
            self.assertEqual(attempt._issued_wire._key, b'')
            self.assertTrue(attempt._issued_timer.finished.is_set())
            ledger._lock = original_lock
            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
        finally:
            ledger._lock = original_lock
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_foreign_cleanup_origins_cannot_redirect_disposal(self):
        ledger = model.PublicationDispatchLedger()
        attempt = ledger.open(envelope(), key=b'k'*32, session=b's'*32)
        foreign_ledger, foreign = self.opened(self.unique(1))
        original_origins = ledger._cleanup_origins
        ledger._cleanup_origins = foreign_ledger._cleanup_origins
        try:
            self.rejected(lambda: ledger.open(self.unique(2), key=b'k'*32, session=b's'*32))
            self.assertEqual(attempt._issued_wire._key, b'')
            self.assertTrue(attempt._issued_timer.finished.is_set())
            self.assertFalse(foreign._issued_cancel.is_set())
            self.assertFalse(foreign._issued_timer.finished.is_set())
            self.state(foreign, 'new')
            ledger._cleanup_origins = original_origins
            self.rejected(lambda: ledger.open(self.unique(2), key=b'k'*32, session=b's'*32))
        finally:
            ledger._cleanup_origins = original_origins
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_noop_wire_cleanup_cannot_produce_inspect_success_or_fresh_claim(self):
        ledger = model.PublicationDispatchLedger()
        _, attempt, _ = self.ready(ledger=ledger)
        wire = attempt._issued_wire
        try:
            with patch.object(wire, 'close', return_value=None) as cleanup:
                self.rejected(attempt.close)
                self.assertTrue(cleanup.called)
                self.assertNotEqual(wire._key, b'')
                self.rejected(attempt.inspect)
                self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
            wire.close()
            self.assertEqual(wire._key, b'')
        finally:
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_noop_timer_cleanup_withholds_terminal_receipt_return(self):
        ledger = model.PublicationDispatchLedger()
        _, attempt, peer = self.awaiting(ledger=ledger)
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        timer = attempt._issued_timer
        try:
            with patch.object(timer, 'cancel', return_value=None) as cleanup:
                self.rejected(lambda: attempt.accept_receipt_claim(frame))
                self.assertTrue(cleanup.called)
                self.assertFalse(timer.finished.is_set())
                self.assertEqual(attempt._issued_wire._key, b'')
                self.rejected(attempt.inspect)
                self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
            timer.cancel()
        finally:
            timer.cancel()
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_deleted_ownership_alias_is_fixed_rejection_and_cannot_restore_use(self):
        _, foreign = self.opened(self.unique(100))
        for alias in ('_ownership', '_issued_ownership', '_recovery_ownership'):
            for visible in (False, True):
                with self.subTest(alias=alias, visible=visible):
                    factory = self.visible if visible else self.ready
                    _, attempt, _ = factory()
                    captured = getattr(attempt, alias)
                    wire, timer, cancel = attempt._issued_wire, attempt._issued_timer, attempt._issued_cancel
                    delattr(attempt, alias)
                    try:
                        self.rejected(attempt.begin_model_visibility)
                        self.assertEqual(wire._key, b'')
                        self.assertTrue(timer.finished.is_set())
                        self.assertTrue(cancel.is_set())
                    finally:
                        setattr(attempt, alias, captured)
                    self.state(attempt, 'outcome_unknown' if visible else 'not_started', possible=visible)
                    self.rejected(attempt.begin_model_visibility)
        self.state(foreign, 'new')
        self.assertFalse(foreign._issued_cancel.is_set())

    def test_deleted_ledger_lock_alias_poison_is_final_and_original_is_disposed(self):
        _, foreign = self.opened(self.unique(100))
        for alias in ('_lock', '_issued_lock', '_cleanup_lock'):
            for visible in (False, True):
                with self.subTest(alias=alias, visible=visible):
                    ledger = model.PublicationDispatchLedger()
                    factory = self.visible if visible else self.ready
                    _, attempt, _ = factory(ledger=ledger)
                    captured = getattr(ledger, alias)
                    wire, timer, cancel = attempt._issued_wire, attempt._issued_timer, attempt._issued_cancel
                    delattr(ledger, alias)
                    try:
                        try:
                            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
                            self.assertEqual(wire._key, b'')
                            self.assertTrue(timer.finished.is_set())
                            self.assertTrue(cancel.is_set())
                        finally:
                            setattr(ledger, alias, captured)
                        self.rejected(attempt.begin_model_visibility)
                        self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
                    finally:
                        setattr(ledger, alias, captured)
                        try: ledger.close()
                        except model.DispatchAttemptError: pass
        self.state(foreign, 'new')
        self.assertFalse(foreign._issued_cancel.is_set())

    def test_deleted_origin_alias_poison_is_final_and_original_is_disposed(self):
        _, foreign = self.opened(self.unique(100))
        for alias in ('_origins', '_issued_origins', '_cleanup_origins'):
            for visible in (False, True):
                with self.subTest(alias=alias, visible=visible):
                    ledger = model.PublicationDispatchLedger()
                    factory = self.visible if visible else self.ready
                    _, attempt, _ = factory(ledger=ledger)
                    captured = getattr(ledger, alias)
                    wire, timer, cancel = attempt._issued_wire, attempt._issued_timer, attempt._issued_cancel
                    delattr(ledger, alias)
                    try:
                        try:
                            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
                            self.assertEqual(wire._key, b'')
                            self.assertTrue(timer.finished.is_set())
                            self.assertTrue(cancel.is_set())
                        finally:
                            setattr(ledger, alias, captured)
                        self.rejected(attempt.begin_model_visibility)
                        self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
                    finally:
                        setattr(ledger, alias, captured)
                        try: ledger.close()
                        except model.DispatchAttemptError: pass
        self.state(foreign, 'new')
        self.assertFalse(foreign._issued_cancel.is_set())

    def test_corrupt_ledger_records_poison_admission_and_close_original_only(self):
        ledger = model.PublicationDispatchLedger()
        foreign_ledger, foreign = self.opened()
        attempt = ledger.open(envelope(), key=b'k'*32, session=b's'*32)
        original_wire = attempt._issued_wire
        ledger._records = {foreign.inspect().attempt_id: foreign}
        try:
            self.rejected(attempt.prepare)
            self.assertEqual(original_wire._key, b'')
            self.state(foreign, 'new')
            self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))
        finally:
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_corrupt_ledger_journal_cannot_restore_cancelled_source_claim(self):
        ledger = model.PublicationDispatchLedger()
        attempt = ledger.open(envelope(), key=b'k'*32, session=b's'*32)
        attempt.close(); ledger._journal = ()
        try:
            self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))
            self.assertEqual(attempt._issued_wire._key, b'')
        finally:
            try: ledger.close()
            except model.DispatchAttemptError: pass

    def test_attempt_has_no_active_data_executor_or_authorization_api(self):
        _, attempt = self.opened()
        for name in ('read', 'write', 'publish', 'deliver', 'execute', 'authorize', 'grant', 'allow', 'data'):
            self.assertFalse(hasattr(attempt, name), name)

    def test_foreign_ready_transcript_cannot_transfer_a_model_claim(self):
        _, attempt, _ = self.prepared()
        _, other, peer = self.prepared(value=self.unique(1))
        frame = peer.ready()
        self.rejected(lambda: attempt.accept_ready(frame))
        self.state(attempt, 'not_started')
        self.state(other, 'prepared')

    def test_foreign_receipt_transcript_cannot_transfer_a_receiver_claim(self):
        _, attempt, _ = self.awaiting()
        _, other, peer = self.awaiting(value=self.unique(1))
        frame = peer.receipt_claim(claimed_bytes=37, claimed_digest=envelope()['staged_digest'])
        self.rejected(lambda: attempt.accept_receipt_claim(frame))
        self.state(attempt, 'outcome_unknown', possible=True, written=37)
        self.state(other, 'awaiting_claim', possible=True, written=37)

    def test_concurrent_visibility_attempt_has_at_most_one_notice_and_no_retry(self):
        _, attempt, _ = self.ready(); barrier = Barrier(2)
        def advance():
            barrier.wait()
            try: return attempt.begin_model_visibility()
            except model.DispatchAttemptError: return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(lambda _: advance(), range(2)))
        self.assertLessEqual(sum(item is not None for item in result), 1)
        self.state(attempt, 'outcome_unknown', possible=True)

    def test_concurrent_close_and_visibility_cannot_create_a_reusable_attempt(self):
        _, attempt, _ = self.ready(); barrier = Barrier(2)
        def advance():
            barrier.wait()
            try: return attempt.begin_model_visibility()
            except model.DispatchAttemptError: return None
        def cancel(): barrier.wait(); attempt.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            advance_future = pool.submit(advance); cancel_future = pool.submit(cancel)
            advance_future.result(); cancel_future.result()
        result = attempt.inspect()
        self.assertIn(result.state, ('not_started', 'outcome_unknown'))
        self.assertEqual(result.observed_delivery, 'unproven')
        self.rejected(attempt.begin_model_visibility)

    def test_initial_snapshot_failure_disposes_original_and_poison_blocks_new_claim(self):
        ledger = model.PublicationDispatchLedger()
        wires = []
        original = PublicationDispatchExchange.__init__
        def capture(wire, **options):
            original(wire, **options); wires.append(wire)
        with patch.object(PublicationDispatchExchange, '__init__', capture), \
                patch.object(model.DispatchAttemptSnapshot, '__init__', side_effect=MemoryError('synthetic')):
            self.rejected(lambda: ledger.open(envelope(), key=b'k'*32, session=b's'*32))
        self.assertEqual(len(wires), 1)
        self.assertEqual(wires[0]._key, b'')
        self.assertEqual(wires[0]._state, 'closed')
        self.rejected(lambda: ledger.open(self.unique(1), key=b'k'*32, session=b's'*32))

    def test_concurrent_duplicate_source_open_reserves_at_most_one_record(self):
        ledger = self.ledger(); barrier = Barrier(2)
        def reserve():
            barrier.wait()
            try: return ledger.open(envelope(), key=b'k'*32, session=b's'*32)
            except model.DispatchAttemptError: return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(lambda _: reserve(), range(2)))
        self.assertEqual(sum(item is not None for item in result), 1)


if __name__ == '__main__': unittest.main()
