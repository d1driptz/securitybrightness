"""Real private child metadata tests. Scripted answers are not human review."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from core import broker_review_host as host
from core import broker_process as process
from core import broker_transport as transport
from core.broker_live_review import LiveBrokerReview
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_review_profile import _ReviewWaitExchange
from core.broker_protocol import BrokerProtocolError
from core.file_read_constraint import FileReadConstraint
from core.file_read_review import FileReadReviewLedger
from core.file_read_schema import make_file_read_proposal
from core.registry import ApplicationRegistry


class BrokerReviewHostTests(unittest.TestCase):
    def setUp(self):
        slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        slot.start(); self.addCleanup(slot.stop)
        self.registry = ApplicationRegistry(); self.addCleanup(self.registry.close)
        self.credential = self.registry.register('app', ['files.read'])
        self.ledger = FileReadReviewLedger()
        self.draft = self.ledger.create(FileReadConstraint('app', 'label', max_bytes=128))
        self.proposal = make_file_read_proposal('label', max_bytes=128)
        self.host = host.BrokerReviewHost(self.registry, self.ledger)
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.addCleanup(self.pool.shutdown, wait=True)
        self.addCleanup(self.host.close)

    def run_host(self):
        return self.host.worker.run('app', self.credential, self.proposal, self.draft.draft_id, 1)

    def start(self):
        future = self.pool.submit(self.run_host)
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            pending = self.host.operator.pending()
            if pending: return future, pending[0]
            if future.done(): future.result()
            time.sleep(.002)
        self.fail('no prompt')

    def reject(self, future, display):
        with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=3)
        self.assertFalse(Path(display.display_path).exists())
        self.assertEqual(self.host.operator.pending(), ())

    def test_real_allow_only_returns_retired_metadata_after_deletion(self):
        before = self.registry.get('app')
        future, display = self.start()
        path = Path(display.display_path); self.assertTrue(path.exists())
        queued = self.host.operator.respond(display, 'ALLOW ONCE')
        with self.assertRaises(TypeError): bool(queued)
        receipt = future.result(timeout=2)
        self.assertEqual((receipt.decision, receipt.lifecycle), ('allow_once', 'retired'))
        self.assertFalse(hasattr(receipt, 'data'))
        self.assertFalse(path.exists())
        self.assertIs(self.registry.get('app'), before)
        self.assertNotIn(self.credential, receipt.canonical_display.decode())
        with self.assertRaises(TypeError): bool(receipt)
        self.assertEqual(self.host.operator.pending(), ())

    def test_deny_retires_and_deletes_fixture(self):
        future, display = self.start()
        self.host.operator.respond(display, 'DENY')
        self.assertEqual(future.result(timeout=2).decision, 'deny')
        self.assertFalse(Path(display.display_path).exists())

    def test_cancel_while_waiting_kills_child_and_deletes_fixture(self):
        future, display = self.start(); self.host.operator.cancel()
        self.reject(future, display)

    def test_timeout_while_waiting_deletes_fixture(self):
        future, display = self.start()
        # Shorten only after reaching the phase under test; startup is not review.
        self.host._deadline = time.monotonic()+.05
        self.reject(future, display)

    def test_cancel_before_start_never_launches(self):
        self.host.close()
        with patch.object(host, '_ReviewWaitChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_bad_credential_never_launches(self):
        self.credential = 'wrong'
        with patch.object(host, '_ReviewWaitChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_operator_and_worker_ports_are_separate(self):
        for name in ('pending', 'respond', 'operator'): self.assertFalse(hasattr(self.host.worker, name))
        self.assertFalse(hasattr(self.host.operator, 'run'))

    def test_forged_display_cancels_session(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(replace(display), 'ALLOW ONCE')
        self.reject(future, display)

    def test_mutated_display_cancels_session(self):
        future, display = self.start()
        object.__setattr__(display, 'max_bytes', 4096)
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)

    def test_inexact_answer_cancels_session(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'allow once')
        self.reject(future, display)

    def test_registry_revocation_after_display_rejects_answer(self):
        future, display = self.start(); self.registry.revoke('app')
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)

    def test_rotation_after_display_rejects_answer(self):
        future, display = self.start(); self.registry.rotate_credential('app')
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)

    def test_draft_revocation_after_display_rejects_answer(self):
        future, display = self.start(); self.ledger.revoke(self.draft.draft_id, 1)
        self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)

    def test_replay_cannot_launch_again(self):
        future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
        future.result(timeout=2)
        with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')
        with patch.object(host, '_ReviewWaitChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_duplicate_worker_cancels_original(self):
        future, display = self.start()
        with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.reject(future, display)

    def test_shared_admission_slot_blocks_launch(self):
        transport._slot.acquire()
        with patch.object(host, '_ReviewWaitChild') as launch:
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
            launch.assert_not_called()

    def test_cleanup_revocation_prevents_receipt(self):
        original = process._ReviewWaitChild.close
        def close(child):
            original(child); self.registry.revoke('app')
        with patch.object(process._ReviewWaitChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_cleanup_cancellation_prevents_receipt(self):
        original = process._ReviewWaitChild.close
        def close(child):
            original(child); self.host.close()
        with patch.object(process._ReviewWaitChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def test_cleanup_failure_poisons_slot(self):
        original = process._ReviewWaitChild.close
        def close(child):
            original(child); raise process.BrokerProcessError('process_cleanup_failed')
        with patch.object(process._ReviewWaitChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)
        self.assertFalse(transport._slot.acquire(blocking=False))

    def test_diagnostic_lifetimes_and_domains_remain_separate(self):
        with self.assertRaises(ValueError): LiveBrokerReview(self.registry, self.ledger, key=b'k'*32, session=b's'*32, timeout=30)
        coordinator = _ReviewWaitExchange(role='coordinator', key=b'k'*32, session=b's'*32)
        diagnostic = LiveMetadataExchange(role='broker', key=b'k'*32, session=b's'*32)
        frame = coordinator.send(dict(application_id='app', decision_id='d'*64,
                                      proposal_json=self.proposal.canonical_bytes().decode()))
        with self.assertRaises(BrokerProtocolError): diagnostic.receive(frame)
        for value in (True, 0, 31, float('inf'), float('nan'), '30'):
            with self.assertRaises(ValueError): host.BrokerReviewHost(self.registry, self.ledger, timeout=value)

    def test_crash_after_observation_prevents_receipt(self):
        original = process._ReviewWaitChild.poll
        killed = threading.Event()
        def poll(child):
            if self.host._display is not None and not killed.is_set():
                killed.set(); child.close()
            return original(child)
        with patch.object(process._ReviewWaitChild, 'poll', poll):
            future = self.pool.submit(self.run_host)
            with self.assertRaises(host.BrokerReviewHostError): future.result(timeout=3)
        self.assertTrue(killed.is_set())

    def test_duplicate_queued_answer_cancels_before_recording(self):
        future, display = self.start()
        with self.host._condition:
            self.host.operator.respond(display, 'ALLOW ONCE')
            with self.assertRaises(host.BrokerReviewHostError): self.host.operator.respond(display, 'ALLOW ONCE')
        self.reject(future, display)

    def test_expiry_during_cleanup_prevents_receipt(self):
        original = process._ReviewWaitChild.close
        def close(child):
            original(child); self.host._deadline = time.monotonic()
        with patch.object(process._ReviewWaitChild, 'close', close):
            future, display = self.start(); self.host.operator.respond(display, 'ALLOW ONCE')
            self.reject(future, display)

    def helper(self, body):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        entry = Path(folder.name)/'child.py'
        entry.write_text('import sys,os,time\nsys.path.insert(0,'+repr(str(Path(__file__).resolve().parent.parent))+')\n'
                         'from core.broker_child_entry import exact\n'
                         'from core.broker_bootstrap import ready\n'
                         'from core.broker_review_profile import _ReviewWaitExchange\n'
                         'from core.broker_live_entry import read_frame\n'+body, encoding='utf-8')
        return patch.object(process._ReviewWaitChild, '_entry_path', return_value=entry)

    def test_bad_startup_never_publishes_prompt(self):
        with self.helper("boot=exact(sys.stdin.buffer,72)\nsys.stdout.buffer.write(ready(boot[8:40],boot[40:],os.getpid()+1));sys.stdout.buffer.flush()"):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.host.operator.pending(), ())

    def test_startup_hang_is_bounded(self):
        self.host.close()
        self.host = host.BrokerReviewHost(self.registry, self.ledger, timeout=.2)
        self.addCleanup(self.host.close)
        with self.helper('time.sleep(60)'):
            with self.assertRaises(host.BrokerReviewHostError): self.run_host()
        self.assertEqual(self.host.operator.pending(), ())

    def test_valid_ack_with_trailing_output_or_failure_is_rejected(self):
        from core.test_broker_live import observed
        body = ("boot=exact(sys.stdin.buffer,72)\nkey,session=boot[8:40],boot[40:]\n"
                "sys.stdout.buffer.write(ready(key,session,os.getpid()));sys.stdout.buffer.flush()\n"
                "exchange=_ReviewWaitExchange(role='broker',key=key,session=session)\n"
                "exchange.receive(read_frame(sys.stdin.buffer))\n"
                'sys.stdout.buffer.write(exchange.send('+repr(observed())+'));sys.stdout.buffer.flush()\n'
                "finish=exchange.receive(read_frame(sys.stdin.buffer))\nassert not sys.stdin.buffer.read(1)\n"
                "sys.stdout.buffer.write(exchange.send(dict(**finish,outcome='denied',lifecycle='retired')));sys.stdout.buffer.flush()\n")
        for ending in ("sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()", 'os._exit(9)', 'time.sleep(60)'):
            with self.subTest(ending=ending):
                self.host.close()
                self.host = host.BrokerReviewHost(self.registry, self.ledger)
                self.addCleanup(self.host.close)
                with self.helper(body+ending):
                    future, display = self.start()
                    self.host.operator.respond(display, 'ALLOW ONCE')
                    if ending == 'time.sleep(60)':
                        self.host._deadline = time.monotonic()+.5
                    self.reject(future, display)

    def test_human_wait_profile_survives_old_diagnostic_watchdog(self):
        self.host.close()
        self.host = host.BrokerReviewHost(self.registry, self.ledger, timeout=15)
        self.addCleanup(self.host.close)
        future, display = self.start()
        time.sleep(10.2)
        self.assertFalse(future.done())
        self.assertTrue(Path(display.display_path).exists())
        self.host.operator.respond(display, 'DENY')
        self.assertEqual(future.result(timeout=2).decision, 'deny')
        self.assertFalse(Path(display.display_path).exists())

    def test_independent_review_child_watchdog_removes_abandoned_fixture(self):
        from core.broker_bootstrap import MAGIC, READY_SIZE, ready
        from core.json_input import loads
        child = process._ReviewWaitChild(); self.addCleanup(child.close)
        deadline = time.monotonic()+5
        def read(size):
            output = bytearray()
            while len(output) < size:
                if time.monotonic() >= deadline: self.fail('startup deadline')
                try:
                    data = os.read(child.stdout_fd, size-len(output))
                    self.assertTrue(data); output.extend(data)
                except BlockingIOError: time.sleep(.002)
            return bytes(output)
        def write(data):
            while data:
                if time.monotonic() >= deadline: self.fail('startup deadline')
                try:
                    count = os.write(child.stdin_fd, data)
                    self.assertGreater(count, 0); data = data[count:]
                except BlockingIOError: time.sleep(.002)
        key, session = os.urandom(32), os.urandom(32)
        exchange = _ReviewWaitExchange(role='coordinator', key=key, session=session)
        write(MAGIC+key+session)
        self.assertEqual(read(READY_SIZE), ready(key, session, child.pid))
        write(exchange.send(dict(application_id='app', decision_id='d'*64, proposal_json=self.proposal.canonical_bytes().decode())))
        prefix = read(4); size = int.from_bytes(prefix, 'big'); self.assertLessEqual(size, 8224)
        observation = exchange.receive(prefix+read(size))
        path = Path(observation['observation']['display_path']); self.assertTrue(path.exists())
        watchdog_deadline = time.monotonic()+37
        while child.poll() is None and time.monotonic() < watchdog_deadline: time.sleep(.02)
        self.assertIsNotNone(child.poll()); self.assertNotEqual(child.poll(), 0)
        self.assertFalse(path.exists())
