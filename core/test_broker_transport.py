"""Adversarial transport tests; helper scripts never enter the public API."""
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from core import broker_transport as transport
from core import broker_process as process
from core.broker_protocol import FixtureBrokerExchange


def binding():
    return dict(application_id='test', proposal_id='sbp2_sha256_'+'a'*64,
                resource_token='b'*64, decision_id='c'*64, max_bytes=32)


class BrokerTransportTests(unittest.TestCase):
    def setUp(self):
        self.slot = patch.object(transport, '_slot', threading.BoundedSemaphore(1))
        self.slot.start()
        self.addCleanup(self.slot.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.children = []
        original = transport._ChildProcess
        def launch():
            child = original()
            self.children.append(child)
            return child
        self.launch = patch.object(transport, '_ChildProcess', side_effect=launch)
        self.launch.start()
        self.addCleanup(self.launch.stop)

    def tearDown(self):
        for child in self.children:
            self.assertIsNotNone(child._exit)
            self.assertIsNone(child._process)
            self.assertIsNone(child._job)
            self.assertEqual(child._fds, set())

    def helper(self, body):
        entry = Path(self.temp.name) / 'fault.py'
        root = str(Path(__file__).resolve().parent.parent)
        entry.write_text('import sys, os, time\nsys.path.insert(0, '+repr(root)+')\n'
                         'from core.broker_child_entry import exact\n'
                         'from core.broker_bootstrap import ready\n'
                         'from core.broker_protocol import FixtureBrokerExchange\n'+body,
                         encoding='utf-8')
        return patch.object(process, '_entry', return_value=entry)

    START = "boot=exact(sys.stdin.buffer,72)\nkey,session=boot[8:40],boot[40:]\n"
    READY = "sys.stdout.buffer.write(ready(key,session,os.getpid()));sys.stdout.buffer.flush()\n"
    REQUEST = ("prefix=exact(sys.stdin.buffer,4)\nframe=prefix+exact(sys.stdin.buffer,int.from_bytes(prefix,'big'))\n"
               "assert not sys.stdin.buffer.read(1)\nexchange=FixtureBrokerExchange(role='broker',key=key,session=session)\n"
               "exchange.accept_request(frame)\n")
    REPLY = "reply=exchange.reply(outcome='denied')\nsys.stdout.buffer.write(reply);sys.stdout.buffer.flush()\n"

    def test_fixed_child_denies_and_fresh_sessions(self):
        with patch.object(transport.secrets, 'token_bytes', wraps=transport.secrets.token_bytes) as random:
            for _ in range(2):
                result = transport.probe(binding())
                self.assertEqual((result.outcome, result.data), ('denied', b''))
                with self.assertRaises(TypeError): bool(result)
            self.assertEqual(random.call_count, 4)
        self.assertNotEqual(self.children[0].pid, self.children[1].pid)

    def test_bad_binding_never_launches(self):
        for bad in [None, {}, dict(binding(), path='C:\\private'), dict(binding(), max_bytes=True)]:
            with self.assertRaises(transport.BrokerTransportError): transport.probe(bad)
        self.assertEqual(self.children, [])

    def test_bad_options(self):
        for timeout in [True, 0, -1, 11, float('nan'), float('inf'), '1']:
            with self.assertRaises(transport.BrokerTransportError): transport.probe(binding(), timeout=timeout)
        with self.assertRaises(transport.BrokerTransportError): transport.probe(binding(), cancel=lambda: False)
        self.assertEqual(self.children, [])

    def test_cancel_before_launch(self):
        cancel = threading.Event(); cancel.set()
        with self.assertRaisesRegex(transport.BrokerTransportError, 'cancelled'):
            transport.probe(binding(), cancel=cancel)
        self.assertEqual(self.children, [])

    def test_busy_has_no_queue(self):
        transport._slot.acquire()
        with self.assertRaisesRegex(transport.BrokerTransportError, 'busy'):
            transport.probe(binding())
        self.assertEqual(self.children, [])

    def test_crash_startup(self):
        with self.helper('os._exit(7)\n'):
            with self.assertRaises(transport.BrokerTransportError): transport.probe(binding())

    def test_timeout_startup(self):
        with self.helper('time.sleep(30)\n'):
            with self.assertRaisesRegex(transport.BrokerTransportError, 'deadline'):
                transport.probe(binding(), timeout=.2)

    def test_cancel_running(self):
        cancel = threading.Event()
        timer = threading.Timer(.2, cancel.set); timer.start()
        try:
            with self.helper('time.sleep(30)\n'):
                with self.assertRaisesRegex(transport.BrokerTransportError, 'cancelled'):
                    transport.probe(binding(), cancel=cancel)
        finally: timer.join()

    def test_bad_startup_identity_session_and_mac(self):
        for code in ["ready(key,session,os.getpid()+1)", "ready(key,b'x'*32,os.getpid())", "ready(b'x'*32,session,os.getpid())"]:
            with self.subTest(code=code), self.helper(self.START+'sys.stdout.buffer.write('+code+');sys.stdout.buffer.flush()\n'):
                with self.assertRaisesRegex(transport.BrokerTransportError, 'startup_rejected'):
                    transport.probe(binding())

    def test_partial_and_oversized_and_trailing_output(self):
        for output in ["b'x'", "b'x'*100000", "(999999).to_bytes(4,'big')", "reply[:-1]", "reply+b'x'", "reply+reply"]:
            body = self.START+self.READY+self.REQUEST+"reply=exchange.reply(outcome='denied')\n"
            with self.subTest(output=output), self.helper(body+'sys.stdout.buffer.write('+output+');sys.stdout.buffer.flush()\n'):
                with self.assertRaises(transport.BrokerTransportError): transport.probe(binding())

    def test_authenticated_data_still_disabled(self):
        body = self.START+self.READY+self.REQUEST+"sys.stdout.buffer.write(exchange.reply(outcome='buffered',data=b'secret'));sys.stdout.buffer.flush()\n"
        with self.helper(body):
            with self.assertRaisesRegex(transport.BrokerTransportError, 'delivery_disabled'):
                transport.probe(binding())

    def test_valid_reply_then_crash_or_hang_is_not_success(self):
        for ending in ['os._exit(3)', 'time.sleep(30)']:
            with self.subTest(ending=ending), self.helper(self.START+self.READY+self.REQUEST+self.REPLY+ending+'\n'):
                with self.assertRaises(transport.BrokerTransportError): transport.probe(binding(), timeout=1)

    def test_environment_is_not_inherited(self):
        body = "assert 'SB_SECRET' not in os.environ\nassert 'PYTHONPATH' not in os.environ\nassert sys.flags.isolated and sys.flags.no_site\n"
        with patch.dict(os.environ, SB_SECRET='not-for-child', PYTHONPATH='C:\\untrusted'), self.helper(body+self.START+self.READY+self.REQUEST+self.REPLY):
            self.assertEqual(transport.probe(binding()).outcome, 'denied')

    def test_cancel_after_cleanup_prevents_publication(self):
        cancel = threading.Event()
        original = process._ChildProcess.close
        def close(child):
            original(child)
            cancel.set()
        with patch.object(process._ChildProcess, 'close', close):
            with self.assertRaisesRegex(transport.BrokerTransportError, 'cancelled'):
                transport.probe(binding(), cancel=cancel)

    def test_cleanup_failure_poison(self):
        original = process._ChildProcess.close
        def close(child):
            original(child)
            raise process.BrokerProcessError('process_cleanup_failed')
        with patch.object(process._ChildProcess, 'close', close):
            with self.assertRaises(transport.BrokerTransportError): transport.probe(binding())
        with self.assertRaisesRegex(transport.BrokerTransportError, 'busy'):
            transport.probe(binding())

    def test_native_launch_failure_no_fallback(self):
        with patch.object(process, '_WinApi', side_effect=process.BrokerProcessError('native_process_failure')):
            with self.assertRaises(transport.BrokerTransportError): transport.probe(binding())

    def test_coordinator_death_kills_waiting_child(self):
        import subprocess
        import sys
        import ctypes as c
        from ctypes import wintypes as w
        source = ("from core.broker_process import _ChildProcess; import os,sys; "
                  "child=_ChildProcess(); print(child.pid,flush=True); sys.stdin.readline(); os._exit(0)")
        parent = subprocess.Popen([sys.executable, '-c', source], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        handle = None
        api = process._WinApi()
        api.k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        api.k.OpenProcess.restype = w.HANDLE
        try:
            pid = int(parent.stdout.readline())
            handle = api.check(api.k.OpenProcess(0x100000, False, pid))
            parent.communicate('exit\n', timeout=5)
            self.assertEqual(parent.returncode, 0)
            self.assertEqual(api.k.WaitForSingleObject(handle, 3000), 0)
        finally:
            if parent.poll() is None:
                parent.kill(); parent.communicate(timeout=5)
            if handle:
                api.close(handle)

    def test_second_process_in_job_is_rejected(self):
        body = ("import subprocess\n"
                "try:\n subprocess.Popen([sys.executable,'-c','pass'])\n"
                "except OSError:\n pass\n"
                "else:\n os._exit(9)\n")
        with self.helper(body+self.START+self.READY+self.REQUEST+self.REPLY):
            self.assertEqual(transport.probe(binding()).outcome, 'denied')

    def test_tampered_reply_is_rejected(self):
        body = self.START+self.READY+self.REQUEST+"reply=exchange.reply(outcome='denied')\n"
        body += "sys.stdout.buffer.write(reply[:-1]+bytes([reply[-1]^1]));sys.stdout.buffer.flush()\n"
        with self.helper(body):
            with self.assertRaises(transport.BrokerTransportError): transport.probe(binding())

    def test_request_mutation_after_snapshot_cannot_change_binding(self):
        value = binding()
        original = process._ChildProcess
        def launch():
            value['application_id'] = 'substituted'
            child = original()
            self.children.append(child)
            return child
        with patch.object(transport, '_ChildProcess', side_effect=launch):
            result = transport.probe(value)
        self.assertIn(b'"application_id":"test"', result.canonical_binding)

    def test_expiry_during_cleanup_prevents_publication(self):
        original = process._ChildProcess.close
        def close(child):
            original(child)
            time.sleep(.3)
        with patch.object(process._ChildProcess, 'close', close):
            with self.assertRaisesRegex(transport.BrokerTransportError, 'deadline'):
                transport.probe(binding(), timeout=.3)
