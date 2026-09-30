"""Adversarial four-step codec and real-child metadata session tests."""
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from core.broker_live_protocol import LiveMetadataExchange
from core.broker_protocol import BrokerProtocolError, _canonical
from core.broker_observation import ObservationExchange
from core.file_read_schema import make_file_read_proposal
from core import broker_live_transport as live
from core import broker_transport as transport
from core import broker_process as process
from core.broker_bootstrap import MAGIC,READY_SIZE


def request():
    return dict(application_id='app',decision_id='d'*64,
        proposal_json=make_file_read_proposal('untrusted text',max_bytes=128).canonical_bytes().decode())


def observed():
    return dict(registry_session='e'*64,observation=dict(owner_session='a'*64,resource_token='b'*64,
        volume_serial=42,file_id='c'*32,size_bytes=37,display_path='display label'))


def finish(action='verify',observation=None):
    return dict(action=action,observation_digest=hashlib.sha256(_canonical(observed() if observation is None else observation)).hexdigest())


class LiveProtocolTests(unittest.TestCase):
    def pair(self):
        return [LiveMetadataExchange(role=role,key=b'k'*32,session=b's'*32) for role in ('coordinator','broker')]

    def opened(self):
        coordinator,broker=self.pair()
        self.assertEqual(broker.receive(coordinator.send(request())),request())
        return coordinator,broker

    def ready(self):
        coordinator,broker=self.opened()
        self.assertEqual(coordinator.receive(broker.send(observed())),observed())
        return coordinator,broker

    def test_verify_and_cancel_four_steps_then_terminal(self):
        for action in ['verify','cancel']:
            coordinator,broker=self.ready()
            value=finish(action)
            self.assertEqual(broker.receive(coordinator.send(value)),value)
            acknowledgement=dict(**value,outcome='denied',lifecycle='retired')
            self.assertEqual(coordinator.receive(broker.send(acknowledgement)),acknowledgement)
            for endpoint in [coordinator,broker]:
                with self.assertRaises(BrokerProtocolError): endpoint.send(request())

    def test_wrong_order_or_role_is_terminal(self):
        coordinator,broker=self.pair()
        with self.assertRaises(BrokerProtocolError): broker.send(observed())
        with self.assertRaises(BrokerProtocolError): broker.receive(coordinator.send(request()))
        coordinator,broker=self.opened()
        with self.assertRaises(BrokerProtocolError): coordinator.send(finish())
        with self.assertRaises(BrokerProtocolError): coordinator.receive(broker.send(observed()))

    def test_replayed_open_retires_broker(self):
        coordinator,broker=self.pair(); frame=coordinator.send(request());broker.receive(frame)
        with self.assertRaises(BrokerProtocolError): broker.receive(frame)
        with self.assertRaises(BrokerProtocolError): broker.send(observed())

    def test_spliced_observation_cannot_follow_different_request(self):
        coordinator,broker=self.opened()
        other_coordinator,other_broker=self.pair()
        other_broker.receive(other_coordinator.send(dict(request(),application_id='other')))
        with self.assertRaises(BrokerProtocolError): coordinator.receive(other_broker.send(observed()))

    def test_spliced_finish_cannot_follow_different_observation(self):
        coordinator,broker=self.ready()
        other_coordinator,other_broker=self.opened()
        changed=observed();changed['observation']['file_id']='f'*32
        other_coordinator.receive(other_broker.send(changed))
        with self.assertRaises(BrokerProtocolError): broker.receive(other_coordinator.send(finish(observation=changed)))

    def test_signed_wrong_steps_previous_or_canonical_encoding(self):
        for patch_value in [dict(step=True),dict(step=2),dict(previous='f'*64),dict(message_json=' '+_canonical(observed()).decode())]:
            coordinator,broker=self.opened()
            payload=dict(step=1,previous=broker._previous,message_json=_canonical(observed()).decode())
            payload.update(patch_value)
            with self.assertRaises(BrokerProtocolError): coordinator.receive(broker._encode('reply',payload))

    def test_wrong_resource_digest_or_unknown_finish_action(self):
        for value in [dict(finish(),observation_digest='0'*64),dict(finish(),action='read'),dict(finish(),approved=True)]:
            coordinator,broker=self.ready()
            with self.assertRaises(BrokerProtocolError): coordinator.send(value)

    def test_allow_data_or_wrong_retirement_rejected_even_signed(self):
        base=dict(**finish(),outcome='denied',lifecycle='retired')
        for value in [dict(base,outcome='allowed'),dict(base,data='secret'),dict(base,lifecycle='live'),dict(base,action='cancel')]:
            coordinator,broker=self.ready();broker.receive(coordinator.send(finish()))
            payload=dict(step=3,previous=broker._previous,message_json=_canonical(value).decode())
            with self.assertRaises(BrokerProtocolError): coordinator.receive(broker._encode('reply',payload))

    def test_cross_domain_and_wrong_session(self):
        coordinator,broker=self.pair(); frame=coordinator.send(request())
        other=ObservationExchange(role='broker',key=b'k'*32,session=b's'*32)
        with self.assertRaises(BrokerProtocolError): other.accept_request(frame)
        other=LiveMetadataExchange(role='broker',key=b'k'*32,session=b'x'*32)
        with self.assertRaises(BrokerProtocolError): other.receive(frame)

    def test_inherited_codec_methods_cannot_bypass_steps(self):
        for name in ['request','accept_request','reply','accept_reply']:
            coordinator,broker=self.pair()
            with self.assertRaises(BrokerProtocolError): getattr(coordinator,name)(request())
            with self.assertRaises(BrokerProtocolError): coordinator.send(request())

    def test_bad_registry_and_metadata(self):
        for value in [dict(observed(),registry_session='a'*64),dict(observed(),registry_session=True),
                      dict(observed(),authority=True),dict(observed(),observation={})]:
            coordinator,broker=self.opened()
            with self.assertRaises(BrokerProtocolError): broker.send(value)

    def test_mutation_does_not_rewrite_transcript(self):
        coordinator,broker=self.opened()
        value=observed();frame=broker.send(value);value['observation']['size_bytes']=999
        received=coordinator.receive(frame);received['observation']['resource_token']='f'*64
        self.assertEqual(broker.receive(coordinator.send(finish())),finish())


class LiveTransportTests(unittest.TestCase):
    def setUp(self):
        self.slot=patch.object(transport,'_slot',threading.BoundedSemaphore(1));self.slot.start();self.addCleanup(self.slot.stop)
        self.proposal=make_file_read_proposal('untrusted text',max_bytes=128)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)

    def diagnose(self,**kwargs):
        return live.diagnose_session('app',self.proposal,'d'*64,**kwargs)

    def helper(self,body):
        entry=Path(self.temp.name)/'child.py';root=str(Path(__file__).resolve().parent.parent)
        entry.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core.broker_child_entry import exact\nfrom core.broker_bootstrap import ready\n'
            'from core.broker_live_protocol import LiveMetadataExchange\n'
            'from core.broker_live_entry import read_frame\n'+body,encoding='utf-8')
        return patch.object(process._LiveMetadataChild,'_entry_path',return_value=entry)

    PRELUDE=("boot=exact(sys.stdin.buffer,72)\nkey,session=boot[8:40],boot[40:]\n"
        "sys.stdout.buffer.write(ready(key,session,os.getpid()));sys.stdout.buffer.flush()\n"
        "exchange=LiveMetadataExchange(role='broker',key=key,session=session)\nexchange.receive(read_frame(sys.stdin.buffer))\n")

    def test_real_verify_and_cancel_only_publish_after_deletion(self):
        original=LiveMetadataExchange.receive
        seen=[]
        def receive(endpoint,frame):
            result=original(endpoint,frame)
            if endpoint._role=='coordinator' and endpoint._step==2:
                path=Path(result['observation']['display_path']);self.assertTrue(path.exists());seen.append(path)
            return result
        with patch.object(LiveMetadataExchange,'receive',receive):
            for action in ['verify','cancel']:
                result=self.diagnose(action=action)
                self.assertEqual((result.action,result.outcome,result.lifecycle,result.data),(action,'denied','retired',b''))
                self.assertEqual(result.canonical_request,_canonical(request()))
                with self.assertRaises(TypeError): bool(result)
        self.assertEqual(len(seen),2)
        for path in seen:self.assertFalse(path.exists())

    def test_cancel_after_observation_destroys_live_fixture(self):
        original=LiveMetadataExchange.receive;cancel=threading.Event();seen=[]
        def receive(endpoint,frame):
            result=original(endpoint,frame)
            if endpoint._role=='coordinator' and endpoint._step==2:
                seen.append(Path(result['observation']['display_path']));cancel.set()
            return result
        with patch.object(LiveMetadataExchange,'receive',receive):
            with self.assertRaises(transport.BrokerTransportError): self.diagnose(cancel=cancel)
        self.assertEqual(len(seen),1);self.assertFalse(seen[0].exists())

    def test_invalid_input_and_cancel_never_launch(self):
        with patch.object(live,'_LiveMetadataChild') as launch:
            for options in [dict(action='read'),dict(timeout=True),dict(timeout=11),dict(cancel=lambda:False)]:
                with self.assertRaises(transport.BrokerTransportError):self.diagnose(**options)
            cancel=threading.Event();cancel.set()
            with self.assertRaises(transport.BrokerTransportError):self.diagnose(cancel=cancel)
            launch.assert_not_called()

    def test_shared_admission_slot(self):
        transport._slot.acquire()
        with self.assertRaisesRegex(transport.BrokerTransportError,'busy'):self.diagnose()

    def test_startup_crash_and_hang(self):
        for body in ['os._exit(9)','time.sleep(30)']:
            with self.helper(body):
                with self.assertRaises(transport.BrokerTransportError):self.diagnose(timeout=.3)

    def test_valid_observation_is_not_enough_for_a_result(self):
        body=self.PRELUDE+'sys.stdout.buffer.write(exchange.send('+repr(observed())+'));sys.stdout.buffer.flush()\n'
        for ending in ['os._exit(4)','time.sleep(30)']:
            with self.helper(body+ending):
                with self.assertRaises(transport.BrokerTransportError):self.diagnose(timeout=.5)

    def test_final_reply_with_crash_extra_output_or_hang_rejected(self):
        body=self.PRELUDE+'sys.stdout.buffer.write(exchange.send('+repr(observed())+'));sys.stdout.buffer.flush()\n'
        body+='finish=exchange.receive(read_frame(sys.stdin.buffer))\nassert not sys.stdin.buffer.read(1)\n'
        body+="sys.stdout.buffer.write(exchange.send(dict(**finish,outcome='denied',lifecycle='retired')));sys.stdout.buffer.flush()\n"
        for ending in ['os._exit(4)',"sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()",'time.sleep(30)']:
            with self.helper(body+ending):
                with self.assertRaises(transport.BrokerTransportError):self.diagnose(timeout=.5)

    def test_cleanup_failure_poisons_slot(self):
        original=process._LiveMetadataChild.close
        def close(child):
            original(child);raise process.BrokerProcessError('process_cleanup_failed')
        with patch.object(process._LiveMetadataChild,'close',close):
            with self.assertRaises(transport.BrokerTransportError):self.diagnose()
        with self.assertRaisesRegex(transport.BrokerTransportError,'busy'):self.diagnose()

    def test_independent_watchdog_retires_idle_live_child(self):
        # Drive only the first round, then withhold the terminal message entirely.
        from core.broker_live_entry import read_frame
        child=process._LiveMetadataChild()
        def read(size):
            output=bytearray();deadline=time.monotonic()+5
            while len(output)<size:
                if time.monotonic()>=deadline:self.fail('startup timeout')
                try:
                    chunk=os.read(child.stdout_fd,size-len(output))
                    if not chunk:self.fail('unexpected EOF')
                    output.extend(chunk)
                except BlockingIOError:time.sleep(.002)
            return bytes(output)
        try:
            key,identity=b'k'*32,b's'*32
            exchange=LiveMetadataExchange(role='coordinator',key=key,session=identity)
            os.write(child.stdin_fd,MAGIC+key+identity);read(READY_SIZE)
            os.write(child.stdin_fd,exchange.send(request()))
            prefix=read(4);value=exchange.receive(prefix+read(int.from_bytes(prefix,'big')))
            path=Path(value['observation']['display_path']);self.assertTrue(path.exists())
            deadline=time.monotonic()+12
            while child.poll() is None and time.monotonic()<deadline:time.sleep(.05)
            self.assertIsNotNone(child.poll());self.assertNotEqual(child.poll(),0)
            self.assertFalse(path.exists())
        finally:child.close()

    def test_partial_flooded_and_wrong_ready_output(self):
        for output in ["b'x'", "(999999).to_bytes(4,'big')", "b'x'*100000"]:
            with self.helper(self.PRELUDE+'sys.stdout.buffer.write('+output+');sys.stdout.buffer.flush()'):
                with self.assertRaises(transport.BrokerTransportError):self.diagnose()
        body="boot=exact(sys.stdin.buffer,72)\nsys.stdout.buffer.write(ready(boot[8:40],boot[40:],os.getpid()+1));sys.stdout.buffer.flush()"
        with self.helper(body):
            with self.assertRaises(transport.BrokerTransportError):self.diagnose()

    def test_cancellation_during_final_cleanup_prevents_receipt(self):
        cancel=threading.Event();original=process._LiveMetadataChild.close
        def close(child):
            original(child);cancel.set()
        with patch.object(process._LiveMetadataChild,'close',close):
            with self.assertRaises(transport.BrokerTransportError):self.diagnose(cancel=cancel)
