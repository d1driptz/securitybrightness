# Supplied-content analysis contract v1

Implemented: `file_security.analyze_bytes`, an independent standard-library-only Python component. This is the first File Security analysis contract, not the installed scanner experience or a port of all browser rules. Neither the HTTP service nor desktop calls it yet. No network endpoint or sample acquisition is introduced.

## Threat boundary and authority

An already-authorized caller supplies an immutable bytes snapshot. Content is untrusted data, never instructions or a path. The analyzer imports no authorization modules and accepts no registry, credential, administrative context or operator callback. It does not open paths, execute samples, use a model, contact a network, alter grants or modify/quarantine files. The caller is responsible for legitimate acquisition; this API grants no right to read anything.

This is dependency/authority separation, not OS isolation: Python components sharing a process can compromise each other. A worker availability boundary and eventually justified platform isolation remain separate work. A result is forgeable local data, not signed evidence, an authorization decision or an enforcement capability. Never use `status == "complete"` as permission to execute or as a safety verdict.

## Input and result

`analyze_bytes(content)` accepts exact `bytes` only, rejecting subclasses and other types with TypeError before invoking their methods. Inputs over 1 MiB are rejected before hashing or decoding. Accepted-size inputs use strict UTF-8 decoding; invalid encoding and C0 controls other than tab/CR/LF produce rejected results with no findings. This does not establish that remaining input is an ordinary text file. No extension guessing, lossy replacement, normalization, archive expansion or recursive parsing occurs.

Results are frozen snapshots with a detached JSON-compatible `to_dict()` view:

- `schema_version`: 1; `analyzer_version`: text-headers/1.
- `status`: complete or rejected; `reason`: null or input_too_large, invalid_utf8, unsupported_control_character. Unexpected internal exceptions propagate; adapters must report analysis failure, never a clean result.
- `byte_count` and `artifact_sha256`: exact supplied byte length/digest, with no digest for oversized input. A digest is content correlation, not provenance, authenticity, secrecy or proof that a current file still has these bytes.
- Findings: stable rule ID/version, evidence kind literal_header_pattern, priority review, total occurrence count and at most five locations per rule. Offsets/lengths are zero-based original bytes; lines and Unicode-code-point columns are one-based, with CRLF/CR/LF line breaks. Tabs and BOM count as code points, not visual columns.
- Limitations always accompany results. No raw source, snippets, filenames, credentials, permission booleans or human decisions appear in the result. A digest can still disclose equality or aid guessing; do not send results externally or retain them by default.

Exactly three case-sensitive literal markers are searched: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY and BEGIN OPENSSH PRIVATE KEY, each inside the conventional five-dash delimiters. They identify possible private-key headers, not valid private keys. Example documentation can match. Lowercase, extra spaces, Unicode substitutions, other key formats, encrypted/obfuscated content and malware without those strings can be missed. Numeric confidence and threat severity would not be justified by these rules.

The implementation makes three bounded searches over at most 1 MiB and computes at most 15 locations. This is a work/input bound, not an enforced wall-clock deadline, process memory quota or safe parser sandbox. Source bytes remain in caller/runtime memory; redaction is not secure erasure. Hashing a bounded rejected encoding does not imply that it was analyzed successfully.

## Evidence and migration

`core/test_file_security.py` covers original multibyte/line-ending locations, digest binding, positive/negative/evasion fixtures, bounded retained evidence, source non-disclosure, exact size boundary, malformed content, hostile input types, detached immutable output and internal faults. Synthetic fixtures establish narrow behavior; no detection benchmark, malware coverage or independent assessment is claimed.

Next dependencies: a bounded analysis worker with explicit timeout/error semantics and adversarial availability tests, broader evaluated corpora, consumer-side result validation before IPC reuse, and user-facing evidence/limitations. Desktop integration must not embed sample processing inside the trusted approval callback or grant scanner results authority. Retain the independent browser prototype until a deliberate migration has evidence and compatibility handling. Binary/archive parsers, remediation, external models and privileged observation are not implied by this contract.
