"""Real private wait-profile transport; generated fixtures, no human/authority bridge.

Binding values below are trusted test orchestration, not current registry grants
or human approval. Only a future independently reviewed coordinator can supply
those controls. Private staging is quarantined and discarded, never delivered.
"""
from dataclasses import replace
import inspect
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from core import broker_wait_process as process
from core import test_broker_native_commit_peer as helpers
from core.broker_bootstrap import MAGIC, READY_SIZE, ready
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_process import BrokerProcessError
from core.broker_publication_protocol import PublicationCheckExchange
from core.broker_recipient_process import _RecipientWitnessChild
from core.broker_wait_protocol import _WaitOpeningExchange, _WaitAcquisitionExchange
from core.file_read_schema import make_file_read_proposal, inspect_file_read_proposal


class WaitFixtureProcessTests(unittest.TestCase):
    write = helpers.NativeCommitPeerTests.write
    read = helpers.NativeCommitPeerTests.read
    frame = helpers.NativeCommitPeerTests.frame
    wait_exit = helpers.NativeCommitPeerTests.wait_exit
    remaining_output = helpers.NativeCommitPeerTests.remaining_output
    read_to_eof = helpers.NativeCommitPeerTests.read_to_eof
    quiet = helpers.NativeCommitPeerTests.quiet

    def setUp(self):
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(32)
        self.proposal = make_file_read_proposal('unverified generated-fixture label', max_bytes=37)
        self.decision_id = secrets.token_hex(32)
        self.child = None
        self.wire = None
        self.opening = _WaitOpeningExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        try:
            if self.child is not None:
                self.child.close()
        finally:
            self.opening.close()
            if self.wire is not None:
                self.wire.close()

    def boot(self, prefix=''):
        if prefix:
            directory = tempfile.TemporaryDirectory()
            self.addCleanup(directory.cleanup)
            path = Path(directory.name)/'generated-wait-fault.py'
            root = str(Path(__file__).resolve().parent.parent)
            path.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
                'from core import broker_wait_entry as entry\n'+prefix+
                '\ntry: entry.run()\nexcept BaseException: sys.exit(1)\n', encoding='utf-8')
            with patch.object(process._WaitFixtureChild, '_entry_path', return_value=path):
                self.child = process._WaitFixtureChild()
        else:
            self.child = process._WaitFixtureChild()
        self.observation = self.child._observe()
        self.write(MAGIC+self.key+self.session)
        self.assertEqual(self.read(READY_SIZE), ready(self.key, self.session, self.observation.pid))

    def observe(self, prefix='', *, require_live=True):
        self.boot(prefix)
        self.write(self.opening.send(dict(application_id='app', decision_id=self.decision_id,
            proposal_json=self.proposal.canonical_bytes().decode('ascii'))))
        self.observed = self.opening.receive(self.frame())
        self.resource = self.observed['observation']
        self.path = Path(self.resource['display_path'])
        if require_live:
            self.assertTrue(self.path.exists())
        self.assertEqual(self.resource['size_bytes'], 37)

    def request(self, wire_type=_WaitAcquisitionExchange):
        self.wire = wire_type(role='coordinator', key=self.key, session=self.session)
        context = dict(application_id='app', proposal_id=inspect_file_read_proposal(self.proposal).proposal_id,
            grant_id=str(uuid4()), draft_id=str(uuid4()), draft_revision=1, review_id=secrets.token_hex(32),
            decision_id=self.decision_id, registry_session=self.observed['registry_session'],
            **{name: self.resource[name] for name in ('owner_session', 'resource_token', 'volume_serial',
                                                    'file_id', 'size_bytes')},
            max_bytes=37, operation='files.read', recipient='requesting_application')
        recipient = dict(application_id='app', recipient_session=secrets.token_hex(32),
                         recipient_id=secrets.token_hex(32), recipient_revision=1)
        return self.wire.request(context, recipient)

    def stage(self):
        self.request_frame = self.request()
        self.write(self.request_frame)
        summary = self.wire.accept_reply(self.frame())
        self.assertEqual((summary.outcome, summary.staged_bytes), ('staged', 37))
        self.assertEqual(bytes(self.wire._buffer), b'SecurityBrightness synthetic fixture\n')
        with self.assertRaises(TypeError):
            bool(summary)
        return summary

    def failed(self):
        self.assertNotEqual(self.wait_exit(), 0)
        self.assertEqual(self.remaining_output(), b'', 'failed phase must emit no later bytes or ACK')
        self.child.close(); self.child._retired()
        if hasattr(self, 'path'):
            self.assertFalse(self.path.exists())

    def test_fixed_entry_retains_original_guarded_launcher_with_no_selectors(self):
        kind = process._WaitFixtureChild
        self.assertIs(kind.__init__, _RecipientWitnessChild.__init__)
        self.assertEqual({name for name, value in kind.__dict__.items() if inspect.isfunction(value)}, {'_entry_path'})
        self.assertEqual(list(inspect.signature(kind).parameters), [])
        self.assertEqual(kind._entry_path(None), Path(process.__file__).resolve().with_name('broker_wait_entry.py'))
        for selector in ('path', 'entry', 'timeout', 'profile', 'handle', 'callback', 'executable'):
            with self.subTest(selector=selector), self.assertRaises(TypeError):
                kind(**{selector: 'untrusted'})

    def test_genuine_wait_longer_than_old_five_seconds_then_one_quarantined_read(self):
        self.observe()
        original = self.child._observe()
        time.sleep(5.25)  # Actual retained original handle; no patched production deadline.
        self.assertIs(self.child._observe(), original)
        self.assertIsNone(self.child.poll())
        self.stage()
        self.write(self.wire.retire_for_check()); self.child.close_input()
        ack = self.frame()
        self.assertEqual(self.read_to_eof(), b'')
        self.assertEqual(self.wait_exit(), 0)
        self.child.close(); self.child._retired()
        self.assertEqual(self.child._retired_snapshot, (0, True))
        self.assertFalse(self.path.exists())
        receipt = self.wire.accept_retirement_ack(ack)
        self.assertEqual((receipt.staged_bytes, receipt.released_bytes), (37, 0))
        self.assertEqual(bytes(self.wire._buffer), b'SecurityBrightness synthetic fixture\n')
        self.wire.close()
        self.assertEqual(self.wire._buffer, bytearray())

    def test_old_opening_domain_cannot_start_new_fixture_observation(self):
        self.boot()
        old = LiveMetadataExchange(role='coordinator', key=self.key, session=self.session)
        self.addCleanup(old.close)
        self.write(old.send(dict(application_id='app', decision_id=self.decision_id,
            proposal_json=self.proposal.canonical_bytes().decode('ascii'))))
        self.child.close_input()
        self.failed()

    def test_pipelined_bootstrap_and_opening_have_no_buffer_read_ahead_ambiguity(self):
        self.child = process._WaitFixtureChild()
        self.observation = self.child._observe()
        first = self.opening.send(dict(application_id='app', decision_id=self.decision_id,
            proposal_json=self.proposal.canonical_bytes().decode('ascii')))
        self.write(MAGIC+self.key+self.session+first)
        self.assertEqual(self.read(READY_SIZE), ready(self.key, self.session, self.observation.pid))
        value = self.opening.receive(self.frame())
        self.path = Path(value['observation']['display_path'])
        self.assertTrue(self.path.exists())
        self.child.close_input()
        self.failed()

    def test_oversized_frame_prefix_closes_fixture_without_waiting_for_body(self):
        self.observe()
        self.write((2**32-1).to_bytes(4, 'big'))
        self.failed()

    def test_old_acquisition_domain_cannot_read_new_wait_fixture(self):
        self.observe()
        self.write(self.request(PublicationCheckExchange)); self.child.close_input()
        self.failed()

    def test_closed_parent_input_before_acquisition_removes_original_fixture(self):
        self.observe()
        self.child.close_input()
        self.failed()

    def test_wait_expiry_cannot_become_fresh_acquisition_on_new_frame(self):
        self.observe(prefix='from core import broker_wait_phase as phase\n'
            'original_open = entry.WaitNativeFixtureAdapter.open\n'
            'def expire(adapter, frame):\n'
            '    value = original_open(adapter, frame)\n'
            '    phase.monotonic = lambda: time.monotonic()+31\n'
            '    return value\n'
            'entry.WaitNativeFixtureAdapter.open = expire\n', require_live=False)
        # Expiry is observed by the original worker before any later input can
        # revive acquisition; even its original native fixture is now retired.
        self.failed()

    def test_acquisition_expiry_removes_fixture_and_never_acknowledges_late_retirement(self):
        self.observe(); self.stage()
        retirement = self.wire.retire_for_check()
        time.sleep(5.25)
        self.assertFalse(self.path.exists(), 'original child worker must dispose its expired fixture')
        self.assertEqual(self.wire._buffer, bytearray())
        self.assertTrue(retirement)  # A previously constructed frame cannot keep the child alive.
        self.failed()

    def test_consumed_acquisition_request_replay_is_not_retirement(self):
        self.observe(); self.stage()
        self.write(self.request_frame); self.child.close_input()
        self.failed()
        self.wire.close(); self.assertEqual(self.wire._buffer, bytearray())

    def test_trailing_input_withholds_ack_after_valid_staging(self):
        self.observe(); self.stage()
        self.write(self.wire.retire_for_check()+b'x'); self.child.close_input()
        self.failed()

    def test_crash_after_private_staging_has_no_retirement_or_publication(self):
        self.observe(); self.stage()
        self.child._ownership.check(self.child._ownership.k.TerminateProcess(self.child._owned[4], 7))
        self.assertEqual(self.wait_exit(), 7)
        self.assertEqual(self.remaining_output(), b'')
        self.child.close(); self.child._retired()
        self.assertFalse(self.path.exists())
        self.wire.close(); self.assertEqual(self.wire._buffer, bytearray())

    def test_native_observation_copy_cannot_replace_original_process_ownership(self):
        self.boot()
        original = self.child._issued_observation
        self.child._issued_observation = replace(original)
        try:
            with self.assertRaises(BrokerProcessError):
                self.child._observe()
        finally:
            self.child._issued_observation = original

    def test_independent_child_watchdog_does_not_wait_for_input_progress(self):
        self.boot(prefix='original_timer = entry.threading.Timer\n'
            'def watchdog(interval, callback, *args, **kwargs):\n'
            '    return original_timer(.2 if interval == 40 else interval, callback, *args, **kwargs)\n'
            'entry.threading.Timer = watchdog\n')
        self.assertEqual(self.wait_exit(), 1)
        self.assertEqual(self.remaining_output(), b'')
