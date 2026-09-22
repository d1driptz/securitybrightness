# Read-only decision history

The desktop Decision history tab reads the existing configured `core.logger.LOG_FILE` only when the operator presses Refresh. It does not change policy, grants, approval state, the log format, retention or audit failure behavior. There is no new HTTP endpoint, export, clear-history action or background monitoring. The panel receives a snapshot-reader callback, not registry or human-approval authority.

## What is implemented

`core.history.read_decision_history` reads at most 4 MiB plus one overflow byte. Oversized, unreadable, malformed, duplicate-key, invalid-encoding or structurally unsupported logs produce HistoryUnavailable without reflecting file contents. A missing file is a distinct missing snapshot and is never created by reading. An empty valid array is an available snapshot with zero stored records. Neither proves that no requests/actions occurred.

The reader coordinates with the logger's existing in-process lock, waiting at most 250 ms to acquire it. Reading holds that lock to avoid disrupting atomic replacement on Windows; parsing happens after release. The read is off the UI thread but has no hard filesystem deadline. A slow provider at the configured audit path can delay writers while the snapshot is read; the existing logger also relies on that filesystem. No cross-process coordination, tamper resistance or storage-custody guarantee is introduced.

Strict parsing uses the existing JSON depth/duplicate/non-finite checks. Immutable summaries contain at most the last 100 records, newest append position first. This is append order, not verified chronology. Summaries show recorded timestamp, canonical-shaped request ID, bounded application ID, recognized action, decision, policy rule and human-control classification. Legacy missing or unsupported fields remain unknown; application identity is never inferred from the caller-controlled source field. Unknown records are represented rather than silently discarded.

Targets, details, raw reasons and source strings are omitted from the projection. Displayed application IDs are escaped to make control/bidirectional characters literal. Identifiers and timestamps can still be sensitive; this is field minimization, not universal semantic secret detection. The underlying audit file can still contain free-form sensitive data and is not repaired or sanitized by viewing it.

Refresh clears the old display while a single background snapshot is pending. A failure shows history unavailable, not an empty log or an apparently current older snapshot. Closing cancels the UI timer; a late reader result cannot touch destroyed widgets. There is no automatic retry or unbounded request queue. Human-review tab priority and explicit approval semantics remain unchanged.

## What records do not prove

- An allow record is neither proof of execution nor an ongoing grant.
- A recorded application name or classification is not current application authority, strong human identity or authenticated provenance of this file.
- Local records can be modified or deleted under prototype A. Shape validation is not authenticity or completeness.
- Failed reviews/revalidation, application lifecycle changes, unlock/lock and file analyses are not comprehensively logged. An absent record cannot prove that nothing happened.

Full security history still requires lifecycle/transaction design, retention/recovery policy, coverage of failures/outcomes and justified integrity protections. This view deliberately consumes the existing decision log without pretending that those capabilities exist.

Evidence: `core/test_history.py` exercises real logger round trips without mutation, immutable/minimized output, append-order limits, legacy/unknown data, busy/error/malformed/missing/empty/oversized distinctions, and actual Tk refresh/error/escaping/closure behavior. Widget tests are functional, not a manual visual/accessibility audit or an independent security assessment.
