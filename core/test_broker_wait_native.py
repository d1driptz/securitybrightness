"""Adversarial inactive waiting adapter; only disposable generated fixtures.

The synthetic authenticated coordinator below deliberately does not model human
permission. This tests the native transport boundary, never a live grant bridge.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import inspect
import os
import secrets
from threading import Thread
import unittest
from unittest.mock import patch

from core import broker_native_acquisition as native
from core import broker_wait_native as wait_native
from core import broker_wait_phase as wait_phase
from core import broker_wait_protocol as wait_protocol
from core.broker_protocol import BrokerProtocolError, _canonical
from core.broker_publication_protocol import PublicationCheckExchange
from core.file_read_schema import inspect_file_read_proposal, make_file_read_proposal
from core.json_input import loads
from core.test_broker_publication_protocol import recipient
from core.test_broker_quarantine import context


class WaitNativeFixtureTests(unittest.TestCase):
    DATA = b'SecurityBrightness synthetic fixture\n'

    def setUp(self):
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(32)
        self.proposal = make_file_read_proposal('unverified generated fixture label', max_bytes=128)
        self.adapter = wait_native.WaitNativeFixtureAdapter(key=self.key, session=self.session)
        self.addCleanup(self.dispose_adapter, self.adapter)
        self.opening = wait_protocol._WaitOpeningExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.opening.close)
        self.peer = None

    def dispose_adapter(self, adapter):
        try:
            adapter.close()
        except native.NativeAcquisitionError:
            # Deliberate corruption must remain uncertified. Permit only the
            # already asserted terminal state after physical original disposal;
            # never hide a surviving generated resource during test teardown.
            original = getattr(adapter, '_issued_owner', None)
            if adapter._state != 'closed' or (original is not None and original._fd is not None):
                raise

    def open(self):
        request = dict(application_id='app', decision_id='2'*64,
            proposal_json=self.proposal.canonical_bytes().decode())
        self.first = self.opening.send(request)
        self.observed = self.opening.receive(self.adapter.open(self.first))
        return self.observed

    def binding(self):
        if not hasattr(self, 'observed'):
            self.open()
        value = context()
        value.update(self.observed['observation'])
        value.pop('display_path')
        value.update(registry_session=self.observed['registry_session'],
            proposal_id=inspect_file_read_proposal(self.proposal).proposal_id, max_bytes=128)
        return dict(context=value, recipient=recipient())

    def request(self, binding=None, *, raw=False, old=False):
        if not hasattr(self, 'observed'):
            self.open()
        exchange = PublicationCheckExchange if old else wait_protocol._WaitAcquisitionExchange
        self.peer = exchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.peer.close)
        value = self.binding() if binding is None else binding
        return self.peer._frame('request', value) if raw else self.peer.request(value['context'], value['recipient'])

    def staged(self):
        result = self.adapter.stage(self.request())
        self.summary = self.peer.accept_reply(result)
        return self.summary

    def retired(self):
        self.staged()
        self.retirement = self.peer.retire_for_check()
        ack = self.adapter.retire(self.retirement)
        return self.peer.accept_retirement_ack(ack)

    def terminal(self):
        self.assertEqual(self.adapter._state, 'closed')
        original = getattr(self.adapter, '_issued_owner', None)
        if original is not None:
            self.assertIsNone(original._fd)

    def rejected_stage(self, frame, *, before_read=True):
        if before_read:
            with patch.object(native.os, 'read', side_effect=AssertionError('no protected read')) as read:
                with self.assertRaises(native.NativeAcquisitionError):
                    self.adapter.stage(frame)
                read.assert_not_called()
        else:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.stage(frame)
        self.terminal()

    def test_constructor_accepts_only_fixed_bootstrap_not_paths_or_lifetimes(self):
        parameters = inspect.signature(wait_native.WaitNativeFixtureAdapter).parameters
        self.assertEqual(set(parameters), {'key', 'session'})
        for field, value in (('timeout', 120), ('clock', lambda: 0), ('path', 'C:\\personal.txt'),
                             ('contents', b'custom'), ('handle', 123), ('callback', lambda: None)):
            with self.subTest(field=field), self.assertRaises(TypeError):
                wait_native.WaitNativeFixtureAdapter(key=self.key, session=self.session, **{field: value})

    def test_invalid_bootstrap_does_not_create_fixture(self):
        for key, session in ((None, self.session), (bytearray(self.key), self.session),
                             (self.key[:-1], self.session), (self.key, self.session[:-1])):
            with self.subTest(key=type(key).__name__, size=len(session)), \
                 patch.object(native._NativeReadFixture, '__init__', side_effect=AssertionError('no native fixture')) as create:
                with self.assertRaises((ValueError, BrokerProtocolError)):
                    wait_native.WaitNativeFixtureAdapter(key=key, session=session)
                create.assert_not_called()

    def test_open_observation_is_actual_native_identity_without_read(self):
        with patch.object(native.os, 'read', side_effect=AssertionError('no opening read')) as read:
            value = self.open()
            read.assert_not_called()
        owner = self.adapter._issued_owner
        self.assertEqual(value['observation']['file_id'], owner.description.file_id)
        self.assertEqual(value['observation']['volume_serial'], owner.description.volume_serial)
        self.assertEqual(value['observation']['size_bytes'], 37)
        self.assertFalse(os.get_inheritable(owner._fd))
        self.assertIsNone(self.adapter._wire)
        self.assertNotIn('permission', value)
        self.assertNotIn('data', value)

    def test_generated_fixture_path_is_not_reopened_to_acquire(self):
        self.open(); frame = self.request(); fd = self.adapter._issued_owner._fd
        original_read = os.read; calls = []
        def read(actual, size):
            calls.append((actual, size)); return original_read(actual, size)
        with patch.object(native.os, 'read', side_effect=read), \
             patch('builtins.open', side_effect=AssertionError('no path reopen')):
            summary = self.peer.accept_reply(self.adapter.stage(frame))
        self.assertEqual(calls, [(fd, 37)])
        self.assertEqual(summary.staged_digest, hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual(summary.staged_bytes, 37)
        self.assertEqual(bytes(self.peer._buffer), self.DATA)

    def test_successful_retirement_requires_native_cleanup_and_only_zero_release_metadata(self):
        self.open(); path = self.adapter._issued_owner.description.display_path
        receipt = self.retired()
        self.assertFalse(os.path.exists(path))
        self.assertIsNone(self.adapter._issued_owner._fd)
        self.assertEqual(receipt.released_bytes, 0)
        self.assertEqual(receipt.staged_bytes, 37)
        self.assertNotIn('data', asdict(receipt))
        self.assertIsNone(self.adapter._retired_snapshot_current())
        with self.assertRaises(TypeError):
            bool(receipt)

    def test_native_profile_has_no_authority_delivery_or_user_file_api(self):
        for name in ('read', 'execute', 'release', 'publish', 'get_buffer', 'data', 'open_path', 'allow', 'authorize'):
            self.assertFalse(hasattr(self.adapter, name))

    def test_path_shaped_requester_label_does_not_select_native_resource(self):
        label = 'C:\\SB-unverified-requester-description-only.txt'
        self.proposal = make_file_read_proposal(label, max_bytes=128)
        observation = self.open()['observation']
        self.assertNotEqual(observation['display_path'], label)
        self.assertEqual(observation['file_id'], self.adapter._issued_owner.description.file_id)
        self.assertTrue(os.path.exists(self.adapter._issued_owner.description.display_path))

    def test_exact_fixture_size_is_valid_bound(self):
        self.proposal = make_file_read_proposal('bounded generated fixture', max_bytes=37)
        self.open(); binding = self.binding(); binding['context']['max_bytes'] = 37
        frame = self.request(binding)
        result = self.peer.accept_reply(self.adapter.stage(frame))
        self.assertEqual(result.staged_bytes, 37)

    def test_bound_below_fixture_size_closes_without_read(self):
        self.proposal = make_file_read_proposal('too small bound', max_bytes=36)
        request = dict(application_id='app', decision_id='2'*64,
            proposal_json=self.proposal.canonical_bytes().decode())
        # Send an authenticated hostile frame directly: the honest opening codec
        # already rejects this unsupported bound before producing a frame.
        frame = self.opening._encode('request', dict(step=0, previous='0'*64,
            message_json=_canonical(request).decode()))
        with patch.object(native.os, 'read', side_effect=AssertionError('no too-small read')) as read:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.open(frame)
            read.assert_not_called()
        self.terminal()

    def test_signed_opening_authority_field_cannot_create_fixture(self):
        request = dict(application_id='app', decision_id='2'*64,
            proposal_json=self.proposal.canonical_bytes().decode(), approved=True)
        frame = self.opening._encode('request', dict(step=0, previous='0'*64,
            message_json=_canonical(request).decode()))
        with patch.object(native.os, 'read', side_effect=AssertionError('no injected read')) as read:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.open(frame)
            read.assert_not_called()
        self.terminal()

    def test_signed_proposal_unsupported_effect_attribute_is_not_native_authority(self):
        proposal = loads(self.proposal.canonical_bytes())
        proposal['effects']['permission'] = 'allow_once'
        request = dict(application_id='app', decision_id='2'*64,
            proposal_json=_canonical(proposal).decode())
        frame = self.opening._encode('request', dict(step=0, previous='0'*64,
            message_json=_canonical(request).decode()))
        with patch.object(native.os, 'read', side_effect=AssertionError('no unsupported read')) as read:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.open(frame)
            read.assert_not_called()
        self.terminal()

    def test_decision_collision_with_bootstrap_key_is_rejected_before_native_allocation(self):
        request = dict(application_id='app', decision_id=self.key.hex(),
            proposal_json=self.proposal.canonical_bytes().decode())
        frame = self.opening.send(request)
        with patch.object(wait_native._WaitNativeReadFixture, '__init__',
                          side_effect=AssertionError('no colliding native allocation')) as create:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.open(frame)
            create.assert_not_called()
        self.terminal()

    def test_generated_registry_collision_with_bootstrap_key_never_leaks_observation(self):
        owner, resource = secrets.token_hex(32), secrets.token_hex(32)
        with patch.object(native.secrets, 'token_hex', side_effect=[self.key.hex(), owner, resource]):
            with self.assertRaises(native.NativeAcquisitionError):
                self.open()
        self.assertEqual(self.adapter._issued_owner.description.registry_session, self.key.hex())
        self.terminal()

    def test_generated_owner_collision_with_bootstrap_session_never_leaks_observation(self):
        registry, resource = secrets.token_hex(32), secrets.token_hex(32)
        with patch.object(native.secrets, 'token_hex', side_effect=[registry, self.session.hex(), resource]):
            with self.assertRaises(native.NativeAcquisitionError):
                self.open()
        self.assertEqual(self.adapter._issued_owner.description.owner_session, self.session.hex())
        self.terminal()

    def test_requester_observation_or_review_mapping_is_not_a_stage_request(self):
        self.open()
        self.rejected_stage(dict(approved=True, observation=self.observed, file_id=self.observed['observation']['file_id']))

    def test_malformed_or_oversized_first_stage_burns_attempt_without_read(self):
        for bad in (None, {}, bytearray(b'x'*40), b'x'*9000, b'\0'*36):
            with self.subTest(value=type(bad).__name__):
                adapter = wait_native.WaitNativeFixtureAdapter(key=self.key, session=self.session)
                self.addCleanup(self.dispose_adapter, adapter)
                opening = wait_protocol._WaitOpeningExchange(role='coordinator', key=self.key, session=self.session)
                self.addCleanup(opening.close)
                opening.receive(adapter.open(opening.send(dict(application_id='app', decision_id='2'*64,
                    proposal_json=self.proposal.canonical_bytes().decode()))))
                with patch.object(native.os, 'read', side_effect=AssertionError('no invalid read')) as read:
                    with self.assertRaises(native.NativeAcquisitionError):
                        adapter.stage(bad)
                    read.assert_not_called()
                self.assertEqual(adapter._state, 'closed')
                self.assertIsNone(adapter._issued_owner._fd)

    def test_invalid_mac_cannot_read(self):
        frame = bytearray(self.request()); frame[-1] ^= 1
        self.rejected_stage(bytes(frame))

    def test_signed_stage_frame_version_mismatch_cannot_read(self):
        frame = self.request(); body = loads(frame[4:-32])
        body['version'] = 2
        encoded = _canonical(body)
        signed = encoded+self.peer._mac('request', encoded)
        self.rejected_stage(len(signed).to_bytes(4, 'big')+signed)

    def test_old_publication_mac_domain_cannot_read(self):
        self.rejected_stage(self.request(old=True))

    def test_stage_before_open_is_terminal_without_native_creation(self):
        self.rejected_stage(b'')
        self.assertIsNone(self.adapter._issued_owner)

    def test_duplicate_open_cannot_create_second_native_fixture(self):
        self.open(); original = self.adapter._issued_owner
        with patch.object(native.os, 'read', side_effect=AssertionError('no duplicate read')):
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.open(self.first)
        self.assertIs(self.adapter._issued_owner, original)
        self.terminal()

    def test_missing_recipient_signed_binding_cannot_read(self):
        binding = self.binding(); del binding['recipient']
        self.rejected_stage(self.request(binding, raw=True))

    def test_authenticated_authority_injection_cannot_read(self):
        binding = self.binding(); binding['approved'] = True
        self.rejected_stage(self.request(binding, raw=True))

    def test_authenticated_context_authority_injection_cannot_read(self):
        binding = self.binding(); binding['context']['expires_at'] = 'never'
        self.rejected_stage(self.request(binding, raw=True))

    def test_authenticated_recipient_authority_injection_cannot_read(self):
        binding = self.binding(); binding['recipient']['permission'] = 'allow_once'
        self.rejected_stage(self.request(binding, raw=True))

    def test_native_file_identity_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['file_id'] = 'f'*32
        self.rejected_stage(self.request(binding))

    def test_volume_identity_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['volume_serial'] ^= 1
        self.rejected_stage(self.request(binding))

    def test_resource_token_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['resource_token'] = 'e'*64
        self.rejected_stage(self.request(binding))

    def test_application_and_recipient_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['application_id'] = binding['recipient']['application_id'] = 'other'
        self.rejected_stage(self.request(binding))

    def test_proposal_identity_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['proposal_id'] = 'sbp2_sha256_'+'f'*64
        self.rejected_stage(self.request(binding))

    def test_changed_max_bytes_cannot_inherit_opening(self):
        binding = self.binding(); binding['context']['max_bytes'] = 4096
        self.rejected_stage(self.request(binding))

    def test_changed_decision_cannot_inherit_opening(self):
        binding = self.binding(); binding['context']['decision_id'] = 'e'*64
        self.rejected_stage(self.request(binding))

    def test_unsupported_operation_cannot_read_even_when_authenticated(self):
        binding = self.binding(); binding['context']['operation'] = 'files.write'
        self.rejected_stage(self.request(binding, raw=True))

    def test_effect_recipient_substitution_cannot_read(self):
        binding = self.binding(); binding['context']['recipient'] = 'third_party'
        self.rejected_stage(self.request(binding, raw=True))

    def test_boolean_bounds_and_duplicate_identity_cannot_read(self):
        binding = self.binding(); binding['context']['max_bytes'] = True
        self.rejected_stage(self.request(binding, raw=True))

    def test_recipient_revision_change_cannot_read(self):
        binding = self.binding(); binding['recipient']['recipient_revision'] = 2
        self.rejected_stage(self.request(binding))

    def test_recipient_id_collision_with_bootstrap_key_cannot_read(self):
        binding = self.binding(); binding['recipient']['recipient_id'] = self.key.hex()
        self.rejected_stage(self.request(binding))

    def test_recipient_session_collision_with_bootstrap_session_cannot_read(self):
        binding = self.binding(); binding['recipient']['recipient_session'] = self.session.hex()
        self.rejected_stage(self.request(binding))

    def test_review_id_collision_with_bootstrap_key_cannot_read(self):
        binding = self.binding(); binding['context']['review_id'] = self.key.hex()
        self.rejected_stage(self.request(binding))

    def test_malformed_first_attempt_cannot_retry_with_valid_frame(self):
        frame = self.request(); self.rejected_stage(b'bad')
        self.rejected_stage(frame)

    def test_staged_request_replay_cannot_repeat_native_read(self):
        frame = self.request(); self.adapter.stage(frame)
        self.rejected_stage(frame)

    def test_concurrent_stage_attempts_allow_at_most_one_original_read(self):
        frame = self.request(); original_read = os.read; calls = []
        def read(fd, size):
            calls.append((fd, size)); return original_read(fd, size)
        with patch.object(native.os, 'read', side_effect=read):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.adapter.stage, frame) for _ in range(2)]
            # Neither caller is the original native owner. Their rejection only
            # signals cancellation; the owning worker must perform disposal.
            self.assertEqual(sum(f.exception() is None for f in futures), 0)
            self.assertIsNotNone(self.adapter._issued_owner._fd)
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter._input_current()
        self.assertEqual(len(calls), 0)
        self.terminal()

    def test_copied_adapter_cannot_acquire_using_original_owner(self):
        frame = self.request(); copied = copy.copy(self.adapter)
        with patch.object(native.os, 'read', side_effect=AssertionError('no copied read')) as read:
            with self.assertRaises(native.NativeAcquisitionError):
                copied.stage(frame)
            read.assert_not_called()
        self.adapter.close(); self.terminal()

    def test_extended_adapter_deadline_cannot_read(self):
        frame = self.request(); self.adapter._deadline += 100
        self.rejected_stage(frame)

    def test_extended_native_deadline_cannot_read(self):
        frame = self.request(); self.adapter._issued_owner._deadline += 100
        self.rejected_stage(frame)

    def test_waiting_beyond_old_five_seconds_does_not_acquire_early_or_renew_total_budget(self):
        self.open(); phase_origin = self.adapter._phases._original()
        deadline = self.adapter._deadline
        now = phase_origin.created+6.0
        with patch.object(wait_phase, 'monotonic', return_value=now), \
             patch.object(wait_native, 'monotonic', return_value=now), \
             patch.object(native, 'monotonic', return_value=now):
            with patch.object(native.os, 'read', side_effect=AssertionError('no waiting read')) as read:
                self.adapter._phases.check_wait()
                read.assert_not_called()
            frame = self.request()
            summary = self.peer.accept_reply(self.adapter.stage(frame))
            self.assertEqual(summary.staged_bytes, 37)
            self.assertEqual(self.adapter._deadline, deadline)
            self.assertEqual(self.adapter._phases._original().deadline_total, phase_origin.created+35.0)

    def test_exact_wait_expiry_rejects_first_acquisition_without_read(self):
        frame = self.request(); now = self.adapter._phases._original().deadline_wait
        with patch.object(wait_phase, 'monotonic', return_value=now), \
             patch.object(wait_native, 'monotonic', return_value=now), \
             patch.object(native, 'monotonic', return_value=now):
            self.rejected_stage(frame)

    def test_total_expiry_rejects_first_acquisition_without_read(self):
        frame = self.request(); now = self.adapter._phases._original().deadline_total
        with patch.object(wait_phase, 'monotonic', return_value=now), \
             patch.object(wait_native, 'monotonic', return_value=now), \
             patch.object(native, 'monotonic', return_value=now):
            self.rejected_stage(frame)

    def test_old_wait_callback_cannot_cancel_entered_acquisition_between_phase_latches(self):
        frame = self.request(); original = self.adapter._phases.enter_acquisition
        def entered():
            deadline = original()
            self.adapter._wait_expired()
            return deadline
        with patch.object(self.adapter._phases, 'enter_acquisition', side_effect=entered):
            summary = self.peer.accept_reply(self.adapter.stage(frame))
        self.assertEqual(summary.staged_bytes, 37)

    def test_one_changed_adapter_archive_is_terminal_without_read(self):
        frame = self.request(); self.adapter._origin = object()
        self.rejected_stage(frame)

    def test_erased_adapter_archives_cannot_recreate_authority_or_acquire(self):
        frame = self.request()
        self.adapter._origin = self.adapter._issued_origin = self.adapter._recovery_origin = None
        self.rejected_stage(frame)

    def test_changed_native_resource_archive_is_terminal_without_read(self):
        frame = self.request(); self.adapter._issued_owner._resource = object()
        self.rejected_stage(frame)

    def test_native_metadata_mutation_cannot_read(self):
        frame = self.request(); owner = self.adapter._issued_owner
        object.__setattr__(owner.description, 'file_id', 'f'*32)
        self.rejected_stage(frame)

    def test_replaced_native_owner_is_never_read_or_disposed(self):
        frame = self.request(); original = self.adapter._issued_owner
        foreign = native._NativeReadFixture(); self.addCleanup(foreign.close)
        self.adapter._owner = foreign
        self.rejected_stage(frame)
        self.assertIsNone(original._fd)
        self.assertIsNotNone(foreign._fd)

    def test_changed_native_descriptor_cannot_read(self):
        frame = self.request(); self.adapter._issued_owner._fd += 10000
        self.rejected_stage(frame)

    def test_proposal_mutation_before_acquisition_cannot_read(self):
        frame = self.request(); self.adapter._proposal = make_file_read_proposal('changed label', max_bytes=128)
        self.rejected_stage(frame)

    def test_short_read_is_not_staging(self):
        frame = self.request()
        with patch.object(native.os, 'read', return_value=self.DATA[:-1]):
            self.rejected_stage(frame, before_read=False)

    def test_native_read_failure_is_terminal(self):
        frame = self.request()
        with patch.object(native.os, 'read', side_effect=OSError('failed')):
            self.rejected_stage(frame, before_read=False)

    def test_close_during_native_read_withholds_staging_frame(self):
        frame = self.request(); original_read = os.read
        def read(fd, size):
            value = original_read(fd, size); self.adapter.close(); return value
        with patch.object(native.os, 'read', side_effect=read):
            self.rejected_stage(frame, before_read=False)

    def test_mutation_during_native_read_withholds_staging_frame(self):
        frame = self.request(); original_read = os.read
        def read(fd, size):
            value = original_read(fd, size); self.adapter._deadline += 1; return value
        with patch.object(native.os, 'read', side_effect=read):
            self.rejected_stage(frame, before_read=False)

    def test_cancellation_while_waiting_closes_original_fixture_without_acquisition(self):
        self.open(); path = self.adapter._issued_owner.description.display_path
        with patch.object(native.os, 'read', side_effect=AssertionError('no waiting read')) as read:
            self.adapter.close()
            self.rejected_stage(self.request())
            read.assert_not_called()
        self.assertFalse(os.path.exists(path))

    def test_changed_opening_lock_or_close_callback_is_not_dispatched_for_cleanup(self):
        self.open(); opening = self.adapter._opening; calls = []
        class Foreign:
            def acquire(self, *args, **kwargs):
                calls.append('acquire'); raise AssertionError('foreign lock')
            def release(self):
                calls.append('release'); raise AssertionError('foreign lock')
            def __enter__(self):
                calls.append('enter'); raise AssertionError('foreign lock')
            def __exit__(self, *_):
                calls.append('exit'); raise AssertionError('foreign lock')
        opening._lock = Foreign()
        with patch.object(opening, 'close', side_effect=AssertionError('foreign close')) as close:
            self.adapter.close()
            close.assert_not_called()
        self.assertEqual(calls, [])
        self.assertEqual(opening._key, b'')
        self.assertEqual(self.adapter._key, b'')
        self.terminal()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter._retired_snapshot_current()

    def test_changed_captured_adapter_lock_is_rejected_before_foreign_dispatch(self):
        frame = self.request(); origin = self.adapter._origin
        original_lock = origin.lock; calls = []
        class Foreign:
            def acquire(self, *args, **kwargs):
                calls.append('acquire'); raise AssertionError('foreign captured lock')
            def release(self):
                calls.append('release'); raise AssertionError('foreign captured lock')
            def __enter__(self):
                calls.append('enter'); raise AssertionError('foreign captured lock')
            def __exit__(self, *_):
                calls.append('exit'); raise AssertionError('foreign captured lock')
        object.__setattr__(origin, 'lock', Foreign())
        try:
            with patch.object(native.os, 'read', side_effect=AssertionError('no corrupted-owner read')) as read:
                with self.assertRaises(native.NativeAcquisitionError):
                    self.adapter.stage(frame)
                read.assert_not_called()
            self.assertEqual(calls, [])
            self.assertFalse(origin.retired.is_set())
        finally:
            # Restore only a known original disposal target. Failed provenance
            # remains terminal; this does not resume acquisition or grant power.
            object.__setattr__(origin, 'lock', original_lock)
            self.dispose_adapter(self.adapter)
        self.assertTrue(origin.failed.is_set())
        self.assertEqual(self.adapter._key, b'')
        self.terminal()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter._retired_snapshot_current()

    def test_changed_wire_cleanup_fields_never_dispatch_foreign_callbacks_and_wipe_original(self):
        self.staged(); wire = self.adapter._issued_wire
        original = self.adapter._wire_origin
        original.buffer.extend(self.DATA)
        foreign_buffer = bytearray(b'foreign buffer')
        calls = []
        class Foreign:
            def cancel(self):
                calls.append('cancel'); raise AssertionError('foreign timer')
            def acquire(self, *args, **kwargs):
                calls.append('acquire'); raise AssertionError('foreign lock')
            def release(self):
                calls.append('release'); raise AssertionError('foreign lock')
            def __enter__(self):
                calls.append('enter'); raise AssertionError('foreign lock')
            def __exit__(self, *_):
                calls.append('exit'); raise AssertionError('foreign lock')
        wire._timer = wire._timer_snapshot = wire._lock = Foreign()
        wire._buffer = wire._issued_buffer = foreign_buffer
        with patch.object(wire, 'close', side_effect=AssertionError('foreign close')) as close, \
             patch.object(original.timer, 'cancel', side_effect=AssertionError('changed timer callback')) as timer_cancel:
            self.adapter.close()
            close.assert_not_called(); timer_cancel.assert_not_called()
        self.assertEqual(calls, [])
        self.assertEqual(original.buffer, bytearray())
        self.assertEqual(foreign_buffer, bytearray(b'foreign buffer'))
        self.assertEqual(wire._key, b'')
        self.assertEqual(self.adapter._key, b'')
        self.assertTrue(original.timer.finished.is_set())
        self.terminal()

    def test_changed_wait_timer_finished_event_never_dispatches_foreign_callbacks(self):
        self.open(); timer = self.adapter._timer; original_finished = timer.finished
        calls = []
        class Foreign:
            def set(self):
                calls.append('set'); raise AssertionError('foreign event')
            def is_set(self):
                calls.append('is_set'); raise AssertionError('foreign event')
            def wait(self, *args, **kwargs):
                calls.append('wait'); raise AssertionError('foreign event')
        timer.finished = Foreign()
        self.adapter.close()
        timer.join(timeout=2)
        self.assertFalse(timer.is_alive())
        self.assertEqual(calls, [])
        self.assertTrue(original_finished.is_set())
        self.assertIs(timer.finished, original_finished)
        self.assertEqual(self.adapter._key, b'')
        self.assertEqual(self.adapter._opening._key, b'')
        self.terminal()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter._retired_snapshot_current()

    def test_changed_wire_timer_finished_event_withholds_ack_and_retires_original_private_state(self):
        self.staged(); wire = self.adapter._issued_wire
        timer = self.adapter._wire_origin.timer; original_finished = timer.finished
        original_buffer = self.adapter._wire_origin.buffer; calls = []
        class Foreign:
            def set(self):
                calls.append('set'); raise AssertionError('foreign event')
            def is_set(self):
                calls.append('is_set'); raise AssertionError('foreign event')
            def wait(self, *args, **kwargs):
                calls.append('wait'); raise AssertionError('foreign event')
        timer.finished = Foreign()
        frame = self.peer.retire_for_check()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter.retire(frame)
        timer.join(timeout=2)
        self.assertFalse(timer.is_alive())
        self.assertEqual(calls, [])
        self.assertTrue(original_finished.is_set())
        self.assertIs(timer.finished, original_finished)
        self.assertEqual(wire._key, b'')
        self.assertEqual(self.adapter._key, b'')
        self.assertEqual(original_buffer, bytearray())
        self.terminal()

    def test_changed_acquisition_timer_finished_event_withholds_ack_without_foreign_dispatch(self):
        self.staged(); wire = self.adapter._issued_wire
        timer = self.adapter._wire_origin.acquisition_timer; original_finished = timer.finished
        calls = []
        class Foreign:
            def set(self):
                calls.append('set'); raise AssertionError('foreign event')
            def is_set(self):
                calls.append('is_set'); raise AssertionError('foreign event')
            def wait(self, *args, **kwargs):
                calls.append('wait'); raise AssertionError('foreign event')
        timer.finished = Foreign()
        frame = self.peer.retire_for_check()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter.retire(frame)
        timer.join(timeout=2)
        self.assertFalse(timer.is_alive())
        self.assertEqual(calls, [])
        self.assertTrue(original_finished.is_set())
        self.assertIs(timer.finished, original_finished)
        self.assertEqual(wire._key, b'')
        self.assertEqual(self.adapter._key, b'')
        self.assertEqual(self.adapter._wire_origin.buffer, bytearray())
        self.terminal()

    def test_foreign_thread_close_signals_without_disposing_original_resource(self):
        self.open(); owner = self.adapter._issued_owner
        path = owner.description.display_path; errors = []
        def cancel():
            try: self.adapter.close()
            except BaseException as exc: errors.append(exc)
        with patch.object(owner, 'close', side_effect=AssertionError('no foreign thread native cleanup')) as close:
            thread = Thread(target=cancel)
            thread.start(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            close.assert_not_called()
            self.assertIsNotNone(owner._fd)
            self.assertTrue(os.path.exists(path))
        with patch.object(native.os, 'read', side_effect=AssertionError('no cancelled read')) as read:
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter._input_current()
            read.assert_not_called()
        self.assertFalse(os.path.exists(path))
        self.terminal()

    def test_timer_callback_only_signals_then_original_worker_disposes_staged_resource(self):
        self.staged(); owner = self.adapter._issued_owner
        path = owner.description.display_path; errors = []
        def expire():
            try: self.adapter._acquisition_expired()
            except BaseException as exc: errors.append(exc)
        with patch.object(owner, 'close', side_effect=AssertionError('no timer native cleanup')) as close:
            thread = Thread(target=expire)
            thread.start(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            close.assert_not_called()
            self.assertIsNotNone(owner._fd)
            self.assertTrue(os.path.exists(path))
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter._input_current()
        self.assertFalse(os.path.exists(path))
        self.terminal()

    def test_retirement_before_staging_is_terminal(self):
        self.open()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter.retire(b'')
        self.terminal()

    def test_failed_native_cleanup_never_returns_retirement_ack(self):
        self.staged(); frame = self.peer.retire_for_check(); original = self.adapter._issued_owner.close
        def failed():
            original(); raise native.NativeAcquisitionError('cleanup uncertain')
        with patch.object(self.adapter._issued_owner, 'close', side_effect=failed):
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.retire(frame)
        self.terminal()

    def test_cancellation_during_native_cleanup_never_returns_ack(self):
        self.staged(); frame = self.peer.retire_for_check(); original = self.adapter._issued_owner.close
        called = [False]
        def cancelled():
            original()
            if not called[0]:
                called[0] = True; self.adapter.close()
        with patch.object(self.adapter._issued_owner, 'close', side_effect=cancelled):
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.retire(frame)
        self.terminal()

    def test_coherent_transcript_mutation_after_ack_generation_cannot_certify_retirement(self):
        self.staged(); frame = self.peer.retire_for_check()
        wire = self.adapter._issued_wire; original = wire.acknowledge_retirement
        def changed():
            result = original()
            wire._previous = 'e'*64
            wire._phase_snapshot = (4, wire._previous, 'closed')
            return result
        with patch.object(wire, 'acknowledge_retirement', side_effect=changed):
            with self.assertRaises(native.NativeAcquisitionError):
                self.adapter.retire(frame)
        self.terminal()

    def test_binding_mutation_after_staging_frame_generation_is_not_staging(self):
        frame = self.request(); original = wait_protocol._WaitAcquisitionExchange.reply
        def changed(wire, **kwargs):
            result = original(wire, **kwargs)
            binding = loads(wire._context_snapshot)
            binding['recipient']['recipient_revision'] = 2
            wire._context_snapshot = wire._binding = _canonical(binding)
            return result
        with patch.object(wait_protocol._WaitAcquisitionExchange, 'reply', new=changed):
            self.rejected_stage(frame, before_read=False)

    def test_retirement_replay_is_not_second_receipt(self):
        self.retired()
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter.retire(self.retirement)
        self.terminal()

    def test_post_retirement_deadline_mutation_cannot_certify_cleanup(self):
        self.retired(); self.adapter._deadline += 1
        with self.assertRaises(native.NativeAcquisitionError):
            self.adapter._retired_snapshot_current()

    def test_authenticated_recipient_claim_is_not_independently_observed_channel_identity(self):
        binding = self.binding(); binding['recipient']['recipient_id'] = 'e'*64
        result = self.adapter.stage(self.request(binding))
        summary = self.peer.accept_reply(result)
        self.assertEqual(summary.staged_bytes, 37)
        self.assertNotIn('data', asdict(summary))
        self.assertFalse(hasattr(self.adapter, 'publish'))
        # This is deliberately a synthetic trusted-bootstrap boundary: no
        # recipient process or current human authority has been demonstrated.
        self.assertEqual(bytes(self.peer._buffer), self.DATA)
