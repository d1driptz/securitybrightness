# Synthetic file-header coverage evaluation

Run `python -m evaluations.header_corpus` from the repository root. The command prints a JSON report and exits nonzero on any mismatch or unavailable analysis. It accepts no sample paths, corpus plugins, commands or credentials. It generates only packaged synthetic byte strings, never working private keys, and uses the same fixed analyzer worker and consumer validator as the desktop. Oversized input takes the worker API's existing rejection path before child creation.

This implements a reproducible, narrow part of development-sequence step 3. It is **not a malware benchmark, detection-accuracy score, independent assessment or authority decision**. A successful run means the documented behavior, including blind spots, remains reproducible. Do not use the report to approve files or actions.

## Corpus and interpretation

Corpus `synthetic-header-coverage/1` has 23 cases for analyzer `text-headers/1`:

| Group | Cases | Expected behavior and meaning |
| --- | ---: | --- |
| Supported marker | 7 | Three supported shapes, mixed Unicode/line endings, repeated occurrences, caller-authored exemption text, and a marker at the exact 1 MiB limit. Counts must match independently authored expectations. No usable key material is established. |
| Benign without a marker | 4 | Empty/plain text, a public-key header and plain input at the size limit produce no findings. No general safety inference follows. |
| Benign literal match | 2 | A quoted documentation example and a comment match. These demonstrate the absence of semantic/valid-key verification, not true-positive secret detection. |
| Known miss | 6 | Lowercase, extra spacing, zero-width splitting, escaped text, encrypted-key and EC-key headers do not match. Expected misses are explicitly reported as limitations, not successful detection. |
| Rejected input | 4 | Invalid UTF-8, a NUL after a marker, UTF-16 and an oversized snapshot are rejected, never classified as clean. |

The runner checks status/rejection, analyzer version, byte length/digest and rule occurrence counts. Location accuracy, schema attacks, hostile caller types, timeout/crash/flooding/cancellation and acquisition behavior have separate regression suites; this corpus does not replace them. The report identifies corpus/analyzer versions, case IDs, outcome counts by group and elapsed time per case. It does not print sample contents or exception messages. Keep the repository commit with a report for exact implementation provenance; version labels alone do not authenticate a report.

Elapsed time includes normal worker startup/transport and is diagnostic for the current machine, not a portable performance threshold or hard real-time promise. Cases run sequentially through the existing shared worker slot, with the default five-second deadline per eligible sample. Busy/timeout/runtime errors remain `unavailable`, make the evaluation fail, and are never counted as a known miss. The parent has no new OS memory quota or sandbox. The generated corpus has a small fixed size; it is not an arbitrary corpus-ingestion API.

## Reproduction and remaining work

`core/test_header_evaluation.py` runs the real pipeline, verifies group accounting, and deliberately simulates omitted findings and worker failures to ensure the evaluator does not turn them into success. Existing tests continue to cover the runtime contract. Actual evaluation results and regression timings are recorded in [the development log](DEVELOPMENT_LOG.md).

The corpus is small, synthetic and selected by the same project that implements the analyzer. It cannot estimate population precision/recall, establish malware coverage, validate cryptographic material, prove resistance to all obfuscation, measure peak process memory or establish a security isolation guarantee. Broader representative datasets, independently reviewed labeling, parser threat models and external assessment remain planned. Changes to detection must deliberately update the corpus expectations/version and explain altered coverage; do not remove a failing case merely to improve the score.

This developer tool adds no UI verdict, network upload, runtime authority, persistent report storage, remediation or execution capability. The [File Security contract](file-security.md) and prototype A limitations remain unchanged.
