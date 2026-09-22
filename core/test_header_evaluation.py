import json
import unittest
from unittest.mock import patch

from evaluations.header_corpus import cases, run_evaluation
from file_security.text_analysis import analyze_bytes


class HeaderEvaluationTests(unittest.TestCase):
    def test_real_worker_corpus_reports_blind_spots_separately(self):
        report = run_evaluation()
        self.assertEqual(report['status'], 'expected_behavior', report)
        self.assertEqual(len(report['cases']), 23)
        self.assertEqual(len({case.name for case in cases()}), 23)
        self.assertEqual({key: value['cases'] for key, value in report['groups'].items()},
                         {'supported_marker': 7, 'benign_no_marker': 4,
                          'benign_literal_match': 2, 'known_miss': 6, 'rejected_input': 4})
        self.assertIn('not detection success', report['meaning'])
        self.assertNotIn('BEGIN PRIVATE KEY', json.dumps(report))

    def test_silent_empty_results_are_mismatches_not_success(self):
        def drop_findings(content):
            from dataclasses import replace
            return replace(analyze_bytes(content), findings=())
        with patch('evaluations.header_corpus.analyze_in_worker', side_effect=drop_findings):
            report = run_evaluation()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['groups']['supported_marker']['mismatch'], 7)
        self.assertEqual(report['groups']['benign_literal_match']['mismatch'], 2)
        self.assertEqual(report['groups']['known_miss']['expected_behavior'], 6)

    def test_worker_failures_cannot_be_reported_as_known_misses(self):
        with patch('evaluations.header_corpus.analyze_in_worker', side_effect=RuntimeError('SYNTHETIC_SECRET')):
            report = run_evaluation()
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(all(row['outcome'] == 'unavailable' for row in report['cases']))
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(report))

    def test_new_analyzer_version_needs_deliberate_evaluation_migration(self):
        from dataclasses import replace
        with patch('evaluations.header_corpus.analyze_in_worker',
                   side_effect=lambda content: replace(analyze_bytes(content), analyzer_version='future/2')):
            report = run_evaluation()
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(all(row['outcome'] == 'mismatch' for row in report['cases']))
