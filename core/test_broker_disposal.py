"""Actual Windows crash/disposal tests on fixed generated contents only."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from core import broker_resource as resource
from core import broker_process as process


class BrokerDisposalTests(unittest.TestCase):
    def test_forced_exit_and_kill_delete_without_python_cleanup(self):
        for ending in ['os._exit(9)', 'time.sleep(30)']:
            code = ('from core.broker_resource import BrokerFixtureOwner; import os,sys,time; '
                    'owner=BrokerFixtureOwner(); print(owner._path,flush=True); sys.stdin.readline(); '+ending)
            child = subprocess.Popen([sys.executable,'-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,text=True)
            try:
                path=Path(child.stdout.readline().strip())
                self.assertTrue(path.name.startswith('sb-broker-fixture-'))
                self.assertTrue(path.exists())
                if 'sleep' in ending:
                    child.kill(); child.communicate(timeout=5)
                else:
                    child.communicate('exit\n',timeout=5)
                self.assertFalse(path.exists())
            finally:
                if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_job_close_deletes_child_owned_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            entry=Path(temp)/'fixture-child.py'
            root=str(Path(__file__).resolve().parent.parent)
            entry.write_text('import sys,time\nsys.path.insert(0,'+repr(root)+')\n'
                'from core.broker_resource import BrokerFixtureOwner\nowner=BrokerFixtureOwner()\n'
                'print(owner._path,flush=True)\ntime.sleep(30)\n',encoding='utf-8')
            with patch.object(process._ObservationChild,'_entry_path',return_value=entry):
                child=process._ObservationChild()
                try:
                    output=bytearray(); deadline=time.monotonic()+5
                    while not output.endswith(b'\n'):
                        if time.monotonic()>=deadline: self.fail('child startup timeout')
                        try:
                            chunk=os.read(child.stdout_fd,1)
                            if not chunk: self.fail('child exited without fixture')
                            output.extend(chunk)
                            self.assertLess(len(output),4096)
                        except BlockingIOError: time.sleep(.002)
                    path=Path(output.decode().strip())
                    self.assertTrue(path.exists())
                finally: child.close()
                self.assertFalse(path.exists())

    def test_failure_transferring_native_handle_still_deletes(self):
        import msvcrt
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(resource.tempfile,'gettempdir',return_value=temp),patch.object(msvcrt,'open_osfhandle',side_effect=OSError('failed')):
                with self.assertRaises(resource.BrokerResourceError): resource.BrokerFixtureOwner()
            self.assertEqual(list(Path(temp).iterdir()),[])

    def test_atomic_create_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/('sb-broker-fixture-'+'b'*64+'.txt')
            path.write_bytes(b'generated collision sentinel')
            with patch.object(resource.tempfile,'gettempdir',return_value=temp),patch.object(resource.secrets,'token_hex',side_effect=['a'*64,'b'*64]):
                with self.assertRaises(resource.BrokerResourceError): resource.BrokerFixtureOwner()
            self.assertEqual(path.read_bytes(),b'generated collision sentinel')

    def test_creation_handle_has_no_native_content_read_access(self):
        import ctypes as c
        from ctypes import wintypes as w
        with resource.BrokerFixtureOwner() as owner:
            read=owner._native.k.ReadFile
            read.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p]
            read.restype=w.BOOL
            buffer=c.create_string_buffer(64); count=w.DWORD()
            self.assertFalse(read(owner._handle,buffer,64,c.byref(count),None))
            self.assertEqual(count.value,0)
            self.assertEqual(buffer.raw,b'\0'*64)

    def test_no_directory_created_and_same_parent_survives(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(resource.tempfile,'gettempdir',return_value=temp):
                with resource.BrokerFixtureOwner() as owner:
                    path=Path(owner._path)
                    self.assertEqual(path.parent,Path(temp))
                    self.assertEqual(list(Path(temp).iterdir()),[path])
                self.assertEqual(list(Path(temp).iterdir()),[])
