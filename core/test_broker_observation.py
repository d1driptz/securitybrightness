"""Observation transport tests use only generated fixtures and test helpers."""
from dataclasses import FrozenInstanceError
import io
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from core.broker_observation import ObservationExchange, proposal_from_text
from core.broker_protocol import FixtureBrokerExchange, BrokerProtocolError, _canonical
from core.file_read_schema import make_file_read_proposal
from core.json_input import loads
from core import broker_transport as transport
from core import broker_process as process


def request():
    return dict(application_id='app', decision_id='d'*64,
                proposal_json=make_file_read_proposal('unverified label', max_bytes=128).canonical_bytes().decode())


def observation():
    return dict(owner_session='a'*64,resource_token='b'*64,volume_serial=42,
                file_id='c'*32,size_bytes=37,display_path='display only')


class ObservationProtocolTests(unittest.TestCase):
    def pair(self):
        return [ObservationExchange(role=role,key=b'k'*32,session=b's'*32) for role in ('coordinator','broker')]

    def ready(self):
        coordinator, broker = self.pair()
        broker.accept_request(coordinator.request(request()))
        return coordinator, broker

    def test_roundtrip_retired_denial_without_content(self):
        coordinator, broker = self.ready()
        result = coordinator.accept_reply(broker.reply(observation=observation()))
        self.assertEqual((result.outcome,result.data,result.lifecycle),('denied',b'','retired'))
        self.assertEqual(result.inspect(), observation())
        self.assertNotIn('display only', repr(result))
        with self.assertRaises(TypeError): bool(result)
        with self.assertRaises(FrozenInstanceError): result.lifecycle = 'live'

    def test_request_and_result_detached(self):
        coordinator, broker = self.pair()
        value = request(); frame = coordinator.request(value)
        value['application_id'] = 'other'
        self.assertEqual(loads(broker.accept_request(frame)),request())
        result = coordinator.accept_reply(broker.reply(observation=observation()))
        changed = result.inspect(); changed['resource_token'] = '0'*64
        self.assertEqual(result.inspect(),observation())

    def test_replay_and_wrong_order_close_endpoint(self):
        coordinator, broker = self.pair()
        frame = coordinator.request(request())
        broker.accept_request(frame)
        with self.assertRaises(BrokerProtocolError): broker.accept_request(frame)
        with self.assertRaises(BrokerProtocolError): broker.reply(observation=observation())
        coordinator, broker = self.ready()
        reply = broker.reply(observation=observation()); coordinator.accept_reply(reply)
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(reply)
        with self.assertRaises(BrokerProtocolError): coordinator.request(request())

    def test_requester_cannot_supply_resource_or_authority(self):
        for name in ['resource_token','observation','path','authority','approved','key','session']:
            coordinator, _ = self.pair()
            with self.assertRaises(BrokerProtocolError): coordinator.request(dict(request(), **{name:'injected'}))

    def test_proposal_versions_and_schema_are_strict(self):
        payload = loads(request()['proposal_json'])
        for version in [True,1,3,'2']:
            changed = dict(payload,version=version)
            with self.assertRaises(ValueError): proposal_from_text(_canonical(changed).decode())
        for changed in [dict(payload,operation='files.delete'),dict(payload,approved=True),
                        dict(payload,effects=dict(payload['effects'],recipient='other'))]:
            with self.assertRaises(ValueError): proposal_from_text(_canonical(changed).decode())
        with self.assertRaises(ValueError): proposal_from_text(' '+request()['proposal_json'])
        with self.assertRaises(ValueError): proposal_from_text('x'*4097)

    def test_bad_metadata_even_when_signed(self):
        cases = [dict(observation(),volume_serial=True),dict(observation(),volume_serial=-1),
                 dict(observation(),volume_serial=2**64),dict(observation(),file_id='c'*31),
                 dict(observation(),size_bytes=True),dict(observation(),size_bytes=38),
                 dict(observation(),display_path='x'*1025),dict(observation(),display_path='x\0'),
                 dict(observation(),display_path='\ud800'),dict(observation(),permission=True),
                 dict(observation(),owner_session='b'*64)]
        for value in cases:
            coordinator, broker = self.ready()
            frame = broker._encode('reply',dict(request=request(),observation=value,outcome='denied',lifecycle='retired'))
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(b'')

    def test_all_request_substitution_fields_rejected(self):
        for name, value in [('application_id','other'),('decision_id','e'*64),
                            ('proposal_json',make_file_read_proposal('other',max_bytes=128).canonical_bytes().decode())]:
            coordinator, broker = self.ready()
            changed = dict(request(),**{name:value})
            frame = broker._encode('reply',dict(request=changed,observation=observation(),outcome='denied',lifecycle='retired'))
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)

    def test_live_allow_or_data_fields_rejected(self):
        base = dict(request=request(),observation=observation(),outcome='denied',lifecycle='retired')
        for changed in [dict(base,lifecycle='live'),dict(base,outcome='buffered'),dict(base,data='secret'),dict(base,grant=True)]:
            coordinator, broker = self.ready()
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(broker._encode('reply',changed))

    def test_session_key_and_domain_separation(self):
        coordinator, broker = self.pair()
        frame = coordinator.request(request())
        for peer in [ObservationExchange(role='broker',key=b'x'*32,session=b's'*32),
                     ObservationExchange(role='broker',key=b'k'*32,session=b'x'*32),
                     FixtureBrokerExchange(role='broker',key=b'k'*32,session=b's'*32)]:
            with self.assertRaises(BrokerProtocolError): peer.accept_request(frame)
        with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(frame)

    def test_partial_extra_tampered_and_oversized_frames(self):
        for alter in [lambda x:x[:-1],lambda x:x+b'x',lambda x:x[:-1]+bytes([x[-1]^1]),lambda x:b'x'*9000]:
            coordinator, broker = self.ready()
            frame = broker.reply(observation=observation())
            with self.assertRaises(BrokerProtocolError): coordinator.accept_reply(alter(frame))

    def test_invalid_observation_closes_sender(self):
        _,broker = self.ready()
        with self.assertRaises(BrokerProtocolError): broker.reply(observation={})
        with self.assertRaises(BrokerProtocolError): broker.reply(observation=observation())


class ObservationTransportTests(unittest.TestCase):
    def setUp(self):
        self.slot = patch.object(transport,'_slot',threading.BoundedSemaphore(1)); self.slot.start()
        self.addCleanup(self.slot.stop)
        self.proposal = make_file_read_proposal('not a pathname', max_bytes=128)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)

    def run_probe(self, **kwargs):
        return transport.observe_fixture('app', self.proposal, 'd'*64, **kwargs)

    def helper(self, body):
        entry = Path(self.temp.name)/'helper.py'
        root = str(Path(__file__).resolve().parent.parent)
        entry.write_text('import sys,os,time\nsys.path.insert(0,'+repr(root)+')\n'
            'from core.broker_child_entry import exact\n'
            'from core.broker_bootstrap import ready\n'
            'from core.broker_observation import ObservationExchange\n'+body,encoding='utf-8')
        return patch.object(process._ObservationChild,'_entry_path',return_value=entry)

    PRELUDE = ("boot=exact(sys.stdin.buffer,72)\nkey,session=boot[8:40],boot[40:]\n"
               "sys.stdout.buffer.write(ready(key,session,os.getpid()));sys.stdout.buffer.flush()\n"
               "prefix=exact(sys.stdin.buffer,4)\nframe=prefix+exact(sys.stdin.buffer,int.from_bytes(prefix,'big'))\n"
               "assert not sys.stdin.buffer.read(1)\n"
               "exchange=ObservationExchange(role='broker',key=key,session=session)\nexchange.accept_request(frame)\n")

    def test_real_child_returns_only_retired_deleted_fixture(self):
        result = self.run_probe()
        self.assertEqual((result.outcome,result.data,result.lifecycle),('denied',b'','retired'))
        info = result.inspect()
        self.assertEqual(info['size_bytes'],37)
        self.assertEqual(len(info['file_id']),32)
        self.assertFalse(Path(info['display_path']).exists())
        self.assertFalse(Path(info['display_path']).parent.exists())
        second = self.run_probe().inspect()
        self.assertNotEqual(info['owner_session'],second['owner_session'])
        self.assertNotEqual(info['resource_token'],second['resource_token'])

    def test_invalid_request_never_launches(self):
        with patch.object(process,'_ObservationChild') as launch:
            for app,proposal,decision in [('app',{},'d'*64),('app',self.proposal,'bad'),
                                        ('app',make_file_read_proposal('x',max_bytes=36),'d'*64)]:
                with self.assertRaises(transport.BrokerTransportError):
                    transport.observe_fixture(app,proposal,decision)
            launch.assert_not_called()

    def test_cancellation_before_launch(self):
        cancel = threading.Event(); cancel.set()
        with patch.object(process,'_ObservationChild') as launch:
            with self.assertRaises(transport.BrokerTransportError): self.run_probe(cancel=cancel)
            launch.assert_not_called()

    def test_startup_crash_timeout_and_cancel(self):
        with self.helper('os._exit(3)\n'):
            with self.assertRaises(transport.BrokerTransportError): self.run_probe()
        with self.helper('time.sleep(30)\n'):
            with self.assertRaises(transport.BrokerTransportError): self.run_probe(timeout=.2)
            cancel = threading.Event(); timer = threading.Timer(.2,cancel.set); timer.start()
            try:
                with self.assertRaises(transport.BrokerTransportError): self.run_probe(cancel=cancel)
            finally: timer.join()

    def test_authenticated_reply_then_crash_hang_or_extra_bytes(self):
        reply = "sys.stdout.buffer.write(exchange.reply(observation="+repr(observation())+"));sys.stdout.buffer.flush()\n"
        for ending in ['os._exit(5)','time.sleep(30)',"sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush()"]:
            with self.helper(self.PRELUDE+reply+ending+'\n'):
                with self.assertRaises(transport.BrokerTransportError): self.run_probe(timeout=1)

    def test_shared_slot_does_not_allow_second_profile_bypass(self):
        transport._slot.acquire()
        with self.assertRaisesRegex(transport.BrokerTransportError,'busy'): self.run_probe()

    def test_failed_fixture_cleanup_has_no_reply(self):
        # Run fixed orchestration in-process with real generated resources and a
        # cleanup failure; output may contain readiness, never an observation.
        from core import broker_observation_entry as entry
        from core.broker_bootstrap import MAGIC,READY_SIZE
        from core.broker_resource import BrokerFixtureOwner, BrokerResourceError
        coordinator = ObservationExchange(role='coordinator',key=b'k'*32,session=b's'*32)
        source = io.BytesIO(MAGIC+b'k'*32+b's'*32+coordinator.request(request()))
        sink = io.BytesIO()
        class Stream:
            def __init__(self,buffer): self.buffer=buffer
        original = BrokerFixtureOwner.close
        def close(owner):
            original(owner)
            raise BrokerResourceError('injected_cleanup_failure')
        with patch.object(entry.sys,'stdin',Stream(source)),patch.object(entry.sys,'stdout',Stream(sink)),patch.object(BrokerFixtureOwner,'close',close):
            with self.assertRaises(BrokerResourceError): entry.main()
        self.assertEqual(len(sink.getvalue()),READY_SIZE)
