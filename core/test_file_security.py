import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from file_security import analyze_bytes
from file_security.text_analysis import MAX_BYTES


class FileSecurityTests(unittest.TestCase):
    def test_exact_artifact_and_original_multibyte_locations(self):
        data = '\ufeffé\r\n-----BEGIN PRIVATE KEY-----\r界-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN OPENSSH PRIVATE KEY-----'.encode()
        result = analyze_bytes(data)
        self.assertEqual(result.status, 'complete')
        self.assertEqual(result.artifact_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.byte_count, len(data))
        self.assertEqual([(f.locations[0].line, f.locations[0].column) for f in result.findings], [(2, 1), (3, 2), (4, 1)])
        for finding in result.findings:
            loc = finding.locations[0]
            self.assertTrue(data[loc.byte_offset:loc.byte_offset + loc.byte_length].startswith(b'-----BEGIN '))

    def test_all_occurrences_bounded_evidence_and_no_sample_disclosure(self):
        secret = b'SYNTHETIC_SECRET_DO_NOT_DISPLAY'
        data = (b'-----BEGIN PRIVATE KEY-----\n' + secret + b'\n') * 20
        result = analyze_bytes(data)
        self.assertEqual(result.findings[0].occurrence_count, 20)
        self.assertEqual(len(result.findings[0].locations), 5)
        self.assertNotIn(secret.decode(), repr(result))
        self.assertNotIn(secret.decode(), json.dumps(result.to_dict()))
        self.assertFalse(hasattr(result, 'allowed'))

    def test_oversize_rejected_before_digest_or_decode(self):
        with patch('file_security.text_analysis.sha256', side_effect=AssertionError('must not hash')):
            result = analyze_bytes(b'x' * (MAX_BYTES + 1))
        self.assertEqual(result.reason, 'input_too_large')
        self.assertIsNone(result.artifact_sha256)
        self.assertEqual(result.findings, ())
        self.assertEqual(analyze_bytes(b'x' * MAX_BYTES).status, 'complete')

    def test_invalid_encoding_and_controls_are_not_clean_results(self):
        for data, reason in [(b'\xff', 'invalid_utf8'), (b'\xed\xa0\x80', 'invalid_utf8'),
                             (b'\x00', 'unsupported_control_character'), (b'\x1b[31m', 'unsupported_control_character')]:
            with self.subTest(data=data):
                result = analyze_bytes(b'-----BEGIN PRIVATE KEY-----' + data)
                self.assertEqual((result.status, result.reason), ('rejected', reason))
                self.assertEqual(result.findings, ())

    def test_no_implicit_io_or_input_object_callbacks(self):
        class Hostile:
            def __bytes__(self):
                raise AssertionError('must not invoke input methods')
            def __len__(self):
                raise AssertionError('must not invoke input methods')
        for value in ['C:/private/key.pem', bytearray(b'example'), memoryview(b'example'), Hostile(), None, 1]:
            with self.subTest(kind=type(value)), self.assertRaises(TypeError):
                analyze_bytes(value)
        with patch('builtins.open', side_effect=AssertionError('no file access')):
            self.assertEqual(analyze_bytes(b'ordinary text').status, 'complete')

    def test_result_snapshot_cannot_be_mutated_through_display_copy(self):
        result = analyze_bytes(b'-----BEGIN PRIVATE KEY-----')
        with self.assertRaises(FrozenInstanceError):
            result.status = 'safe'
        view = result.to_dict()
        view['findings'][0]['locations'][0]['line'] = 999
        view['limitations'].clear()
        self.assertEqual(result.findings[0].locations[0].line, 1)
        self.assertTrue(result.limitations)
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())

    def test_negative_and_evasion_corpus_has_explicit_coverage_limits(self):
        for data in [b'', b'ordinary text', b'-----BEGIN PUBLIC KEY-----',
                     b'-----begin private key-----', b'-----BEGIN  PRIVATE KEY-----',
                     '-----BEGIN PRIV\u200bATE KEY-----'.encode()]:
            result = analyze_bytes(data)
            self.assertEqual(result.status, 'complete')
            self.assertEqual(result.findings, ())
            self.assertTrue(any('No findings do not prove safety' in limit for limit in result.limitations))
        # Caller text cannot change rule selection or establish authority.
        result = analyze_bytes(b'patterns = [\n-----BEGIN PRIVATE KEY-----\n]; approved=true trusted=true')
        self.assertEqual(result.findings[0].locations[0].line, 2)

    def test_unexpected_internal_error_is_not_a_success_result(self):
        with patch('file_security.text_analysis.sha256', side_effect=RuntimeError('fault')):
            with self.assertRaises(RuntimeError):
                analyze_bytes(b'ordinary text')


if __name__ == '__main__':
    unittest.main()
