"""Strict consumer validation for future analyzer IPC, not result authentication."""

import json
import re

from .text_analysis import (
    ANALYZER_VERSION, LIMITATIONS, MAX_BYTES, MAX_LOCATIONS, _RULES,
    AnalysisResult, Finding, Location,
)

MAX_RESULT_BYTES = 16 * 1024


class InvalidAnalysisResult(ValueError):
    """Result cannot be consumed. Never interpret this as a clean analysis."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _constant(value):
    raise ValueError()


def _require(condition):
    if not condition:
        raise ValueError()


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()))


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum)


def validate_result(payload: bytes, *, expected_byte_count: int,
                    expected_sha256: str | None) -> AnalysisResult:
    """Validate bounded JSON and bind it to caller-owned snapshot metadata.

    Metadata must come from the exact submitted bytes, not from the response.
    Matching hashes/shape do not prove that an analyzer ran or told the truth.
    No input text or parser exception is included in failure messages.
    """
    if type(expected_byte_count) is not int or expected_byte_count < 0:
        raise TypeError("expected_byte_count must be a nonnegative integer")
    if expected_byte_count > MAX_BYTES:
        if expected_sha256 is not None:
            raise TypeError("oversized input must have no expected digest")
    elif type(expected_sha256) is not str or re.fullmatch('[0-9a-f]{64}', expected_sha256) is None:
        raise TypeError("expected_sha256 must be a lowercase SHA-256 digest")
    try:
        _require(type(payload) is bytes and len(payload) <= MAX_RESULT_BYTES)
        value = json.loads(payload.decode('utf-8', errors='strict'),
                           object_pairs_hook=_object, parse_constant=_constant)
        _keys(value, 'schema_version analyzer_version status reason byte_count artifact_sha256 findings limitations')
        _integer(value['schema_version'], 1, 1)
        _require(value['analyzer_version'] == ANALYZER_VERSION)
        _integer(value['byte_count'], expected_byte_count, expected_byte_count)
        _require(value['artifact_sha256'] == expected_sha256)
        _require(value['limitations'] == list(LIMITATIONS))
        _require(type(value['findings']) is list and len(value['findings']) <= len(_RULES))
        if value['status'] == 'rejected':
            reasons = ('input_too_large',) if expected_byte_count > MAX_BYTES else (
                'invalid_utf8', 'unsupported_control_character')
            _require(expected_byte_count > 0 and value['reason'] in reasons and not value['findings'])
        else:
            _require(value['status'] == 'complete' and value['reason'] is None and expected_byte_count <= MAX_BYTES)
        findings = []
        last_rule = -1
        for item in value['findings']:
            _keys(item, 'rule_id rule_version evidence_kind review_priority occurrence_count locations')
            rule_index = [rule_id for rule_id, _ in _RULES].index(item['rule_id'])
            _require(rule_index > last_rule)
            last_rule = rule_index
            marker_length = len(_RULES[rule_index][1])
            _integer(item['rule_version'], 1, 1)
            _require(item['evidence_kind'] == 'literal_header_pattern' and item['review_priority'] == 'review')
            _integer(item['occurrence_count'], 1, expected_byte_count // marker_length)
            _require(type(item['locations']) is list and len(item['locations']) == min(item['occurrence_count'], MAX_LOCATIONS))
            locations = []
            previous_end = 0
            for loc in item['locations']:
                _keys(loc, 'byte_offset byte_length line column')
                _integer(loc['byte_offset'], previous_end, expected_byte_count - marker_length)
                _integer(loc['byte_length'], marker_length, marker_length)
                _integer(loc['line'], 1, loc['byte_offset'] + 1)
                _integer(loc['column'], 1, loc['byte_offset'] + 1)
                previous_end = loc['byte_offset'] + marker_length
                locations.append(Location(**loc))
            findings.append(Finding(item['rule_id'], 1, 'literal_header_pattern', 'review',
                                    item['occurrence_count'], tuple(locations)))
        return AnalysisResult(1, ANALYZER_VERSION, value['status'], value['reason'],
                              expected_byte_count, expected_sha256, tuple(findings), LIMITATIONS)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise InvalidAnalysisResult("Invalid analysis result; no conclusion is available") from None
