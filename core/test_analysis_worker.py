import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from file_security import analyze_bytes
from file_security import worker


class AnalysisWorkerTests(unittest.TestCase):
    def test_real_worker_roundtrip_and_input_boundary(self):
        for content in [b'', b'-----BEGIN PRIVATE KEY-----\n' * 8, b'\xff', b'\x00', b'x' * 1048576]:
            with self.subTest(size=len(content)):
                self.assertEqual(worker.analyze_in_worker(content), analyze_bytes(content))

    def test_fixed_launch_does_not_inherit_secret_environment(self):
        real_popen = subprocess.Popen
        launches = []
        def launch(args, **kwargs):
            launches.append((args, kwargs))
            return real_popen(args, **kwargs)
        with patch.dict(os.environ, {'SB_ADMIN_TOKEN': 'synthetic-secret', 'PYTHONPATH': 'untrusted'}), patch.object(worker.subprocess, 'Popen', side_effect=launch):
            worker.analyze_in_worker(b'ordinary text')
        args, options = launches[0]
        self.assertEqual(args[:3], [sys.executable, '-I', '-S'])
        self.assertTrue(args[3].endswith('worker_entry.py'))
        self.assertNotIn('SB_ADMIN_TOKEN', options['env'])
        self.assertNotIn('PYTHONPATH', options['env'])
        self.assertTrue(options['close_fds'])
        self.assertFalse(options.get('shell', False))
        if os.name == 'nt':
            self.assertEqual(options['creationflags'], subprocess.CREATE_NO_WINDOW)

    def run_fault(self, code, expected, timeout=5):
        real_popen = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = real_popen([sys.executable, '-I', '-S', '-c', code], **kwargs)
            children.append(child)
            return child
        with patch.object(worker.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(worker.AnalysisUnavailable, expected):
                worker.analyze_in_worker(b'', timeout=timeout)
        self.assertTrue(children)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdin.closed)
        self.assertTrue(children[0].stdout.closed)
        # A failed request must not retain the single admission slot.
        self.assertTrue(worker._slot.acquire(blocking=False))
        worker._slot.release()

    def test_timeout_kills_and_reaps_worker(self):
        self.run_fault('import time; time.sleep(30)', 'analysis_timeout', timeout=0.2)

    def test_output_flood_is_bounded_and_worker_failure_is_not_clean(self):
        self.run_fault("import sys; sys.stdout.buffer.write(b'x' * 20000); sys.stdout.buffer.flush()", 'analysis_output_limit')
        self.run_fault('import sys; sys.exit(7)', 'analysis_worker_failed')

    def test_invalid_or_wrong_artifact_output_is_rejected(self):
        self.run_fault("print('{}')", 'analysis_invalid_result')
        forged = json.dumps(analyze_bytes(b'other input').to_dict())
        self.run_fault('print(' + repr(forged) + ')', 'analysis_invalid_result')

    def test_busy_and_oversized_input_do_not_launch_children(self):
        worker._slot.acquire()
        try:
            with patch.object(worker.subprocess, 'Popen', side_effect=AssertionError('must not launch')):
                with self.assertRaisesRegex(worker.AnalysisUnavailable, 'analysis_busy'):
                    worker.analyze_in_worker(b'ordinary text')
                self.assertEqual(worker.analyze_in_worker(b'x' * 1048577).reason, 'input_too_large')
        finally:
            worker._slot.release()

    def test_launch_failure_and_invalid_parameters_do_not_become_results(self):
        with patch.object(worker.subprocess, 'Popen', side_effect=OSError('synthetic secret')):
            with self.assertRaisesRegex(worker.AnalysisUnavailable, '^analysis_transport_unavailable$'):
                worker.analyze_in_worker(b'ordinary text')
        for timeout in [True, 0, -1, float('nan'), float('inf'), 61, 10 ** 1000, '5']:
            with self.assertRaises(ValueError):
                worker.analyze_in_worker(b'', timeout=timeout)
        with self.assertRaises(TypeError):
            worker.analyze_in_worker('path.txt')

    def test_unconfirmed_cleanup_closes_admission_until_restart(self):
        real_popen = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = real_popen(args, **kwargs)
            children.append(child)
            child.wait = Mock(side_effect=subprocess.TimeoutExpired('fixed-worker', 1))
            return child
        try:
            with patch.object(worker.subprocess, 'Popen', side_effect=launch):
                with self.assertRaisesRegex(worker.AnalysisUnavailable, 'analysis_cleanup_failed'):
                    worker.analyze_in_worker(b'ordinary text')
            with self.assertRaisesRegex(worker.AnalysisUnavailable, 'analysis_busy'):
                worker.analyze_in_worker(b'ordinary text')
        finally:
            for child in children:
                real_popen.wait(child, timeout=5)
            worker._slot.release()  # restore test isolation, not product recovery
