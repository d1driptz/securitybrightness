import copy
import hashlib
import json
import unittest

from file_security import analyze_bytes
from file_security.result_validation import InvalidAnalysisResult, validate_result


class AnalysisResultValidationTests(unittest.TestCase):
    def setUp(self):
        self.content = b'-----BEGIN PRIVATE KEY-----\n' * 8
        self.result = analyze_bytes(self.content)
        self.expected = dict(expected_byte_count=len(self.content), expected_sha256=hashlib.sha256(self.content).hexdigest())

    def encode(self, value):
        return json.dumps(value).encode()

    def test_round_trip_supported_and_rejected_results(self):
        for content in [self.content, b'', b'ordinary text', b'\xff', b'\x00', b'x' * (1048576 + 1)]:
            result = analyze_bytes(content)
            validated = validate_result(self.encode(result.to_dict()), expected_byte_count=len(content), expected_sha256=result.artifact_sha256)
            self.assertEqual(validated, result)

    def test_request_binding_uses_independent_metadata(self):
        payload = self.encode(self.result.to_dict())
        with self.assertRaises(InvalidAnalysisResult):
            validate_result(payload, expected_byte_count=len(self.content), expected_sha256='0' * 64)
        with self.assertRaises(InvalidAnalysisResult):
            validate_result(payload, expected_byte_count=len(self.content) + 1, expected_sha256=self.result.artifact_sha256)

    def test_malformed_duplicate_deep_and_oversize_json_is_rejected(self):
        for payload in [b'\xff', b'{', b'[]', b'NaN', b'{"status":1,"status":2}',
                        b'[' * 1500 + b']' * 1500, b' ' * 16385, 'not bytes']:
            with self.subTest(kind=type(payload)), self.assertRaises(InvalidAnalysisResult):
                validate_result(payload, **self.expected)

    def test_unknown_fields_versions_and_authority_cannot_enter_result(self):
        original = self.result.to_dict()
        mutations = [('schema_version', True), ('schema_version', 2), ('byte_count', True),
                     ('analyzer_version', 'future/1'), ('allowed', True), ('status', 'safe'),
                     ('limitations', []), ('reason', 'approved'), ('findings', {}),
                     ('artifact_sha256', None)]
        for field, value in mutations:
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(InvalidAnalysisResult):
                validate_result(self.encode(changed), **self.expected)

    def test_evidence_bounds_order_types_and_redaction_schema(self):
        for change in [lambda f: f.update(rule_id='unknown'), lambda f: f.update(rule_version=True),
                       lambda f: f.update(occurrence_count=0), lambda f: f.update(occurrence_count=999999),
                       lambda f: f.update(review_priority='safe'), lambda f: f.update(snippet='SYNTHETIC_SECRET'),
                       lambda f: f.update(locations=[]),
                       lambda f: f['locations'][0].update(byte_offset=-1),
                       lambda f: f['locations'][0].update(byte_length=999),
                       lambda f: f['locations'][0].update(line=True),
                       lambda f: f['locations'][0].update(column=999999),
                       lambda f: f['locations'][1].update(byte_offset=0)]:
            changed = self.result.to_dict()
            change(changed['findings'][0])
            with self.assertRaises(InvalidAnalysisResult) as failure:
                validate_result(self.encode(changed), **self.expected)
            self.assertNotIn('SYNTHETIC_SECRET', str(failure.exception))
        changed = self.result.to_dict()
        changed['findings'].append(changed['findings'][0])
        with self.assertRaises(InvalidAnalysisResult):
            validate_result(self.encode(changed), **self.expected)

    def test_rejection_cannot_contain_findings_or_hide_large_input_as_complete(self):
        changed = self.result.to_dict()
        changed.update(status='rejected', reason='invalid_utf8')
        with self.assertRaises(InvalidAnalysisResult):
            validate_result(self.encode(changed), **self.expected)
        large = analyze_bytes(b'x' * 1048577).to_dict()
        large.update(status='complete', reason=None)
        with self.assertRaises(InvalidAnalysisResult):
            validate_result(self.encode(large), expected_byte_count=1048577, expected_sha256=None)

    def test_invalid_caller_metadata_is_a_programming_error(self):
        for size, digest in [(True, '0' * 64), (-1, '0' * 64), (1, None), (1, 'A' * 64), (1048577, '0' * 64)]:
            with self.assertRaises(TypeError):
                validate_result(b'{}', expected_byte_count=size, expected_sha256=digest)
