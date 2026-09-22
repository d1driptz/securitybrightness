"""Reproducible synthetic coverage evaluation, not a malware benchmark.

Run from the repository root: python -m evaluations.header_corpus
Only packaged synthetic bytes enter the fixed analyzer. No selected files,
network requests, credentials, authority callbacks or sample execution.
"""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import time

from file_security.worker import analyze_in_worker

CORPUS_VERSION = 'synthetic-header-coverage/1'
EVALUATED_ANALYZER_VERSION = 'text-headers/1'


@dataclass(frozen=True)
class Case:
    name: str
    group: str
    content: bytes
    counts: tuple[tuple[str, int], ...] = ()
    rejection: str | None = None


def cases() -> tuple[Case, ...]:
    # Expected rule IDs/counts are authored independently of the implementation's
    # rule table. These are header-shaped strings, never working private keys.
    pk = b'-----BEGIN PRIVATE KEY-----'
    rsa = b'-----BEGIN RSA PRIVATE KEY-----'
    ssh = b'-----BEGIN OPENSSH PRIVATE KEY-----'
    return (
        Case('pkcs8', 'supported_marker', pk, (('pem.private-key', 1),)),
        Case('rsa', 'supported_marker', rsa, (('pem.rsa-private-key', 1),)),
        Case('openssh', 'supported_marker', ssh, (('openssh.private-key', 1),)),
        Case('mixed_unicode_lines', 'supported_marker', '\ufeffé\r\n'.encode() + pk + b'\r' + rsa + b'\n' + ssh,
             (('pem.private-key', 1), ('pem.rsa-private-key', 1), ('openssh.private-key', 1))),
        Case('repeated_markers', 'supported_marker', (pk + b'\n') * 30, (('pem.private-key', 30),)),
        Case('caller_exemption_text', 'supported_marker', b'patterns = [\n' + pk + b'\n]; trusted=true',
             (('pem.private-key', 1),)),
        Case('size_limit_marker', 'supported_marker', b'x' * (1048576 - len(pk)) + pk,
             (('pem.private-key', 1),)),
        Case('empty', 'benign_no_marker', b''),
        Case('public_key', 'benign_no_marker', b'-----BEGIN PUBLIC KEY-----'),
        Case('ordinary_text', 'benign_no_marker', b'Inspecting bills is not permission to transfer money.'),
        Case('size_limit_plain', 'benign_no_marker', b'x' * 1048576),
        # Matches in documentation are expected: the analyzer cannot establish
        # whether usable secret material exists. Do not count these as true keys.
        Case('quoted_documentation', 'benign_literal_match', b'Example only: "' + pk + b'"',
             (('pem.private-key', 1),)),
        Case('comment_without_key', 'benign_literal_match', b'# ' + rsa,
             (('pem.rsa-private-key', 1),)),
        Case('lowercase', 'known_miss', pk.lower()),
        Case('extra_space', 'known_miss', b'-----BEGIN  PRIVATE KEY-----'),
        Case('zero_width_split', 'known_miss', '-----BEGIN PRIV\u200bATE KEY-----'.encode()),
        Case('escaped_text', 'known_miss', b'-----BEGIN PRIV\\u0041TE KEY-----'),
        Case('encrypted_header', 'known_miss', b'-----BEGIN ENCRYPTED PRIVATE KEY-----'),
        Case('ec_header', 'known_miss', b'-----BEGIN EC PRIVATE KEY-----'),
        Case('invalid_utf8', 'rejected_input', pk + b'\xff', rejection='invalid_utf8'),
        Case('nul_after_marker', 'rejected_input', pk + b'\x00', rejection='unsupported_control_character'),
        Case('utf16', 'rejected_input', pk.decode().encode('utf-16'), rejection='invalid_utf8'),
        Case('over_size_limit', 'rejected_input', b'x' * 1048577, rejection='input_too_large'),
    )


def run_evaluation() -> dict:
    """Measure the shipped worker/validator pipeline against a fixed corpus.

    Errors and mismatches are distinct; neither becomes an empty successful
    analysis. Reports contain fixture IDs, not contents or exception messages.
    Duration is diagnostic on this machine, not a throughput or deadline claim.
    """
    rows = []
    for case in cases():
        started = time.monotonic()
        try:
            result = analyze_in_worker(case.content)
            counts = tuple((finding.rule_id, finding.occurrence_count) for finding in result.findings)
            expected_status = 'rejected' if case.rejection else 'complete'
            expected_digest = None if case.rejection == 'input_too_large' else sha256(case.content).hexdigest()
            matched = (result.analyzer_version == EVALUATED_ANALYZER_VERSION
                       and result.status == expected_status and result.reason == case.rejection
                       and result.byte_count == len(case.content) and result.artifact_sha256 == expected_digest
                       and counts == case.counts)
            outcome = 'expected_behavior' if matched else 'mismatch'
        except Exception:
            # Developer diagnostic boundary: don't echo arbitrary parser/runtime
            # errors. Interrupted evaluation still exits via KeyboardInterrupt.
            outcome = 'unavailable'
        rows.append({'case': case.name, 'group': case.group, 'outcome': outcome,
                     'elapsed_ms': round((time.monotonic() - started) * 1000, 3)})
    groups = {}
    for row in rows:
        group = groups.setdefault(row['group'], {'cases': 0, 'expected_behavior': 0, 'mismatch': 0, 'unavailable': 0})
        group['cases'] += 1
        group[row['outcome']] += 1
    return {'corpus_version': CORPUS_VERSION, 'analyzer_version': EVALUATED_ANALYZER_VERSION,
            'status': 'expected_behavior' if all(row['outcome'] == 'expected_behavior' for row in rows) else 'failed',
            'meaning': 'Synthetic contract behavior only; known misses and benign matches are limitations, not detection success.',
            'groups': groups, 'cases': rows}


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = run_evaluation()
    print(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
    return 0 if report['status'] == 'expected_behavior' else 1


if __name__ == '__main__':
    raise SystemExit(main())
