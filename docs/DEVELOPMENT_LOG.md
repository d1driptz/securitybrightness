# Development batches

## Reproducible file-header coverage evaluation

- Added a developer-only, version-pinned 23-case synthetic corpus and JSON report using the real fixed worker/consumer validator. Separate groups retain supported markers (7), benign inputs without markers (4), benign literal matches (2), known misses (6) and rejected inputs (4). Expected blind spots are not counted as successful detection.
- The standalone evaluation reproduced all 23 expectations with no mismatches/unavailable results; diagnostic aggregate elapsed time was 4601.013ms, maximum single-case time 622.731ms on this machine. These timings are not portable performance or deadline claims. No working keys, imported datasets, selected paths, network requests or new runtime authority are involved.
- Regression tests exercise the real corpus, silent finding loss, worker failure and unsupported analyzer-version migration. Final full suite: 230 Python tests in 30.917s plus 8 browser tests in 36.7717ms (238 total), no failures/skips/Tk warnings; existing Windows temporary-directory ACL shim used.
- Reviewed code, corpus expectations, reporting/exit semantics, no-source error handling and documentation against the authorization-only boundary. Whitespace checks passed and generated audit changes excluded. Publication is recorded by this entry's commit and branch history.
- Limits: small same-project synthetic corpus, no population precision/recall, malware or cryptographic validation, independent labeling, peak-memory benchmark or OS isolation. Runtime detector coverage is unchanged. Broader representative evaluation and stronger protection remain planned.

## Decision-history policy compatibility correction

- Reassessment found that history recognized `destructive_action` instead of the policy's actual `change_or_execute` rule. Corrected the display allowlist; no policy or authority behavior changed.
- Added a real authorization-to-log-to-history regression covering every current policy rule, including denied human review and blocked operations. Unknown rules still remain unrecognized instead of exposing free-form content.
- Full regression: 226 Python tests in 29.691s and 8 browser tests in 67.5765ms (234 total), no failures/skips/Tk warnings; existing Windows temporary-directory ACL shim used. Reviewed the complete diff and whitespace checks. The history view retains all previously documented integrity, coverage and read-deadline limitations.
- Publication is recorded by this entry's commit and branch history.

## Read-only desktop decision history

- Added bounded immutable summaries of the existing configured audit file and an explicit-refresh desktop tab with no grant, approval, export or deletion controls. It shows at most 100 latest append-position records; unknown/legacy fields remain unknown and source data never supplies application identity.
- Omitted targets, details, raw reasons and source strings, escaped application identifiers, distinguished missing/empty/unavailable history, and cleared stale results on refresh/failure. Parsing uses strict JSON and a 4 MiB input cap; read coordination reuses the logger's lock without changing writes or retention.
- Focused history/desktop/file-review suites: 13 passed in 2.730s. Final regression: 225 Python tests in 30.637s plus 8 browser tests in 158.9928ms (233 total), no failures/skips/Tk warnings. Existing Windows temporary-directory ACL shim used. Tests cover actual audit round trips without mutation, immutable/minimized output, legacy/unknown records, limits, corrupt/missing/empty/busy/error handling and actual widget refresh/escaping/closure.
- Reviewed read-only authority boundaries, field projection, stale/error behavior, UI lifecycle and compatibility. Documentation separates these summaries from execution evidence, current grants and authenticated provenance. Whitespace checks passed and generated audit changes excluded. Publication is recorded by this entry's commit and branch history.
- Limits: unsigned local logs, incomplete lifecycle/failure/analysis coverage, identifiers may remain sensitive, no semantic secret guarantee, no filesystem read deadline, and potential writer delay while the configured file is read. This is visibility into existing records, not comprehensive security history or tamper-proof evidence.

## Fixed acquisition helper and shared transport

- Resumed the interrupted batch without replacing the existing desktop work. File acquisition now runs in a fixed, cancellable helper, removing filesystem reads from the desktop parent. A bounded path message goes over stdin, snapshot bytes return through a capped pipe, and fixed exit codes produce non-sensitive failures. No selected path or contents appear in process arguments.
- Reused the analyzer's admission, deadline, cancellation, stripped environment, hidden Windows launch and cleanup implementation for the two allowlisted helpers. Analyzer output still binds to the parent's snapshot digest. No arbitrary command, sample execution, HTTP capability, file write or increased privilege was added.
- Removed an intermediate entry-point import that would have modified the parent's import path; regression evidence checks path stability. Updated the desktop to call acquisition before analysis and corrected stale current/planned documentation.
- Focused worker/widget/desktop suites: 20 passed in 15.451s. Full regression: 220 Python tests in 35.949s plus 8 browser-script tests in 244.1512ms (228 total), no failures/skips/Tk warnings. Existing Windows temporary-directory ACL shim used. Real-process evidence includes exact 1 MiB transfer, oversized/missing-file rejection, stalled helper timeout/reaping, output flooding, private path transport and pre-launch cancellation.
- Reviewed the complete transport/acquisition/UI diff, failure mapping, fixed entry-point boundary, source non-disclosure and documentation. Whitespace checks passed; generated audit changes excluded. Publication is recorded by this entry's commit and branch history.
- Limits: normal OS account privileges, non-atomic path checks, no hard real-time OS startup/kill guarantees or abrupt-parent descendant containment, no secure erasure and only three literal header patterns. The trusted acquisition helper establishes what bytes it read; a digest does not independently prove path provenance. The core remains authorization-only.

## Operator-selected desktop header review

- Added a separate File Security prototype tab for explicit selection of one regular UTF-8 file up to 1 MiB. Bounded read-only acquisition checks type, existing reparse/symlink components, opened identity and size/mtime changes; the fixed worker returns validated redacted evidence. No automatic scan, directory crawl, file modification, analysis endpoint, result persistence or authority change was added.
- The panel receives no registry, credentials or approval channel. Background acquisition/analysis keeps Human Review responsive and incoming reviews retain priority. Display identifies the selected path safely and reports snapshot digest, rule locations/counts and coverage limits without secret bodies.
- Review fixed UI timer cleanup and worker shutdown: closure cancels active analysis, delayed reads cannot launch after cancellation, and final shutdown locks authority/closes review before bounded job cleanup. Repeated Tk test roots are garbage-collected on their owning thread rather than background threads.
- Focused widget/worker/desktop run: 17 tests passed in 4.687s. Final full suite: 217 Python tests in 25.712s and 8 browser tests in 35.1521ms (225 total), no failures/skips/Tk warnings. Existing Windows temporary-directory ACL shim used. Tests cover actual Tk-to-worker operation, redaction, cancellation, changed/missing/oversized files, pending-review priority, closure during delayed I/O and real child cancellation/reaping. This is not manual visual/accessibility validation.
- Reviewed all acquisition/UI/worker changes against prototype A, authority callbacks, stale results, shutdown order and documented claims. Updated README, current product/architecture statements, desktop/contract guides and sequence. Whitespace checks passed; generated audit changes excluded. Publication is recorded by this entry's commit and branch history.
- Limits: three literal header shapes only; ordinary account privileges; in-process acquisition with no hard filesystem deadline; non-atomic path/metadata checks; mapped/provider-backed filesystem access may occur for a selected path; no secure memory erasure, malware verdict, quarantine, strong sandbox or protection against hostile same-user processes. The core remains authorization-only.

## Fixed analysis worker and availability handling

- Added a fixed isolated-mode Python analyzer launcher with supplied-byte stdin, bounded nonblocking output, caller-owned digest validation, one admitted request, monotonic deadlines and kill/reap cleanup. No caller-selected command/path/environment/callback, shell, sample execution, authority import or model dependency is accepted.
- Child environment excludes application/admin secrets and Python injection variables, extra handles are closed, stderr is discarded and Windows workers have no console window. This is availability handling under prototype A, not reduced OS privileges or a hostile-process sandbox.
- Review identified unconfirmed cleanup as an admission risk; cleanup failure now keeps admission closed until restart, preventing repeated launches from accumulating potentially live children. Added the corresponding regression.
- Final suite: 210 Python tests passed in 22.664s; unchanged browser suite 8 passed in 54.3626ms (218 total, no failures/skips). Python used the existing Windows temporary-directory ACL shim. Worker tests launch real children and cover maximum input, timeout reaping, output floods, crashes, invalid/wrong-artifact results, environment separation, busy/oversize admission and cleanup failure.
- Reviewed code, transport bounds, fixed launch/secret handling, timeout and exceptional cleanup, documentation and whitespace. Test-generated audit changes excluded. Publication is recorded by this entry's commit and branch history.
- Limits: no hard process-creation deadline, memory quota, restricted token or descendant containment; trusted runtime/install and same-user environment remain required. The API is synchronous and is not connected to the desktop or HTTP service. No acquisition, malware verdict, enforcement or human authority was added.

## Bounded analysis-result consumer validation

- Added strict 16 KiB JSON result validation with exact schema/version/limitations, independent expected digest/length binding, bounded evidence and reconstruction into immutable records. Unknown authority/source fields, duplicate keys, malformed numbers/types, incompatible status/reason and invalid locations fail without reflecting payload contents.
- Kept result correlation distinct from authenticity: a compromised analyzer can still omit or fabricate plausible findings. This is the consumer prerequisite for future IPC, not an IPC transport, sandbox or permission decision.
- Focused analysis suites: 15 passed in 0.235s. Full regression: 202 Python tests in 19.841s plus 8 browser tests in 40.3052ms, all passed (210 total, no skips). Python used the existing Windows temporary-directory ACL shim.
- Reviewed validator bounds, nested duplicate handling, boolean rejection, failure behavior, independent metadata and documentation. Whitespace checks passed; generated audit data excluded. Publication is recorded by this entry's commit and branch history.
- Remaining dependencies: worker availability/cleanup, evaluated broader detection and desktop acquisition/evidence presentation. No new authority, model dependency, sample execution or privileged access was introduced.

## Supplied-content File Security contract v1

- Added an independent analysis-only Python API over exact immutable bytes. Three literal private-key header rules return versioned redacted findings, bounded locations/counts, exact-byte digests and explicit unsupported-input reasons. There is no file acquisition, network/model, authority import, human approval or execution path.
- Documented input/output semantics, adversarial coverage, digest privacy, unsupported encodings/formats and migration dependencies. This advances the platform sequence's analysis contract, not a desktop scanner or malware engine. Existing browser and authorization APIs are unchanged.
- Focused tests: 8 passed in 0.325s. Full suite: 195 Python tests passed in 22.349s, plus 8 browser-script tests in 49.5445ms (203 total, no failures/skips). Python tests used the existing Windows temporary-directory ACL shim. Tests include malformed/control data, exact size boundary, immutable display snapshots, adversarial type rejection, fault propagation and evasion/negative fixtures.
- Reviewed all new source and tests, authority dependencies, redaction, location semantics and documentation; whitespace checks passed. Publication is recorded by this entry's commit and branch history.
- Limits: no process isolation/deadline, no result authenticity, no binary/archive analysis, no desktop acquisition, and only three exact header patterns. A complete result means those rules ran, never that an artifact is safe or authorized. Consumer validation and worker availability precede UI reuse.

This log records scope, evidence and limits, not a claim of complete security. Commit history supplies the exact diff for each entry. All batches preserve authorization-only behavior. Test runs below used `python -m unittest discover -s core -p "test_*.py" -v` on Windows; in this sandbox an external test-only temporary-directory permission shim was needed. It changes temporary-directory creation permissions, not authorization/audit code. It is not shipped in the repository.

## Product vision and architecture - 2626152

- Separated current implementation, planned product and optional future extensions, linked implementation evidence, and shortened README without discarding the service reference.
- Full suite: 149 passed in 9.171s. Reviewed code/documentation consistency and local Markdown links.
- Published and remotely verified on securitybrightness-core.

## Terminal review context - 2f19f32

- Show request/source/action/target/category/required scope in both review modes; label requester explanations unverified; state per-proposal authorization limits.
- Full suite: 152 passed in 10.204s. Reviewed escaping, ordinary denial/retry, strong confirmation and avoiding unrelated detail disclosure.
- Published and remotely verified on securitybrightness-core.

## Prepared SDK proposals - ac3da35

- Added ActionProposal as an immutable JSON snapshot of the existing request, with independent inspection copies and ApplicationClient.check_proposal. Existing check calls use the same validation and transport path.
- Baseline: 152 passed in 7.276s. Focused proposal/SDK suite: 14 passed. Full suite: 157 passed in 9.778s.
- Regression evidence covers nested mutation isolation through real HTTP/audit, authority-field rejection, invalid/deep/cyclic/oversize JSON, scope changes and credential revocation between explicit submissions.
- Reviewed final diff: no HTTP schema, policy, approval or execution changes; no retries/caching. Publication is recorded by this entry's commit and branch history.
- Remaining limits: a local snapshot is not a signed capability, a versioned structured-effects protocol or downstream binding. Same-process Python callers remain trusted. Persistent grants, separate human identity, asynchronous approval and controlled resource integrations remain unimplemented.

## Policy explanations in human review - e23e459

- Default terminal reviews receive the permission engine's actual policy rule, policy assessment and review reason. Caller-authored fields cannot replace these explanations; custom approval-provider signatures remain unchanged.
- Focused SDK/approval/permission suite: 33 passed in 1.875s. Full suite: 159 passed in 18.681s.
- End-to-end regressions exercise the real terminal provider through SDK/HTTP, sensitive-read denial, request/audit correlation, and strong confirmation rejecting yes while accepting ALLOW.
- Reviewed diff: no authorization rule, scope, credential or execution changes. All displayed explanations use terminal escaping. Publication is recorded by this entry's commit and branch history.
- Remaining limits: these are deterministic policy explanations, not independently verified effects. Review still blocks the service thread; separate human identity and asynchronous review remain design dependencies.

## Proposed lifecycle and human-authority decision

- Reassessed the next product dependency after both implementation batches were published and remotely verified (ac3da35 and e23e459).
- Recorded a proposed structured/asynchronous workflow, invariants and two explicit first-release threat-model options. No option is selected; no approval endpoint or authority change is implemented.
- Documentation-only review against current service, SDK and architecture. The unchanged code baseline passed 159 tests in 18.681s; local documentation links were checked. No additional test-count claim for a documentation change.
- Owner input is required before choosing a new graphical human-approval trust boundary. This is the architecture's human-authority decision gate, not a routine implementation approval.

## Accepted A and optional desktop human review - 0a66b54

- Owner selected the trusted local Windows operator model A. Recorded B as a required isolation/human-authority milestone before any strong local enforcement claim against hostile same-user applications.
- Added a Tk desktop reviewer and a credential-free immutable review-message boundary. The default terminal service and application /check API retain their behavior; the desktop service selects the new provider explicitly.
- The bounded ephemeral channel binds answers to fresh pending IDs, checks strong confirmation, rejects replay/late responses and fails closed on timeout/closure. Application and admin tokens have no HTTP human-approval route. No executor was introduced.
- Baseline: 159 passed in 8.881s. Focused channel/desktop/SDK suite: 22 passed in 3.755s. Final full suite: 169 passed in 11.236s, no skips on this Windows environment. The real Tk widget test exercised explicit approval, strong confirmation, escaped display and window closure with an outstanding review; this is functional widget testing, not a manual visual/accessibility audit.
- Reviewed code, documentation consistency and local links. Default provider compatibility, scope/policy denials, SDK/audit correlation and fail-closed 503 behavior pass regression checks. Publication is recorded by this entry's commit and branch history.
- Remaining limits: trusted same-user environment; no isolated IPC/human-presence proof, no persistent grants/review queue, no application-management UI. HTTP still waits synchronously and blocks other requests during review; revocation is not atomic with pending approval. Failed channel attempts do not create final decision audit records. SDK timeouts may precede the 120-second review expiry and remain unknown outcomes.

## Separate trusted authorization context from proposal details - 84eb1a1

- Context-backed SecurityEvents now retain immutable AuthorizationContext separately. Identity, scope and human-control participation use that authority exclusively; mixed context/legacy fields are rejected at construction.
- Kept AuthorizationContext.apply and no-context trusted Python behavior for compatibility. HTTP/SDK request and response formats are unchanged. Documented migration for custom providers and audit consumers: context-backed details no longer duplicate authority; top-level authoritative decision fields remain.
- Focused authorization/SDK/channel suite: 28 passed in 1.271s. Full suite: 173 passed in 10.575s, no skips in this environment.
- Regression evidence covers authority-free details through the API and real HTTP audit, rejection of mixed input, context precedence despite later detail mutation, and human review for an unauthenticated context. Reviewed all identity/scope consumers and the final diff.
- Publication is recorded by this entry's commit and branch history. Remaining limits: legacy no-context Python remains trusted; same-process code can replace objects; this data separation is not B's OS isolation or downstream enforcement.

## Read-only desktop application authority view - 92ccec9

- Added immutable ApplicationSummary registry snapshots without credentials or hashes, and a desktop Applications tab showing IDs, trust and scopes. Selected rows expose the full escaped scope list. Refresh is read-only and never participates in authorization.
- An arriving review selects the Human review tab without submitting any answer. Registration/rotation/revocation/permission changes remain on the existing administrative path; no new HTTP routes or authority were added.
- Focused registry/desktop suite: 20 passed in 0.395s. Final full suite: 174 passed in 11.391s, no skips in this environment.
- Reviewed credential non-disclosure, immutable snapshots across update/rotation/revocation, actual Tk population/removal/selection, switching to pending review, and existing strong-confirmation/closure behavior. Documentation links and final diff checked.
- Publication is recorded by this entry's commit and branch history. Remaining limits: display can be stale between refreshes, grants remain ephemeral and broad, lifecycle controls are not in the GUI, and prototype A does not protect against hostile same-user processes.

## Persistent authority activation decision proposal

- After remotely verifying all three A-aligned implementation batches, assessed persistence as the next product dependency so applications need not be reprovisioned after every restart.
- Recorded two startup activation choices and storage/rollback constraints. No persistence, unlock endpoint or lifetime extension is implemented by this documentation.
- Reviewed against the current ephemeral registry and accepted A-to-B migration. Unchanged code baseline: 174 passed in 11.391s; documentation links checked. This is not an additional test-count milestone.
- Owner input is required because surviving a restart changes the lifetime/activation of human-delegated authority, not merely the file format.

## Explicit-unlock persistence and final authority revalidation

- Recorded the accepted unlock rule and expanded protection mission: trust is not authority, observed is not controlled, and SecurityBrightness components require separate least-privilege boundaries. Device Security, File Security and Security Assistant remain planned, not implemented protection claims.
- Added opt-in versioned SQLite storage, single-owner transactions, strict startup validation and commit-before-success lifecycle changes. Persistent authority starts inactive, including new/changed/rotated versions. No activation flag or raw application credential is stored.
- Desktop authority inspection shows stored/active state, identity, scope, creation/change metadata and lifetime. Human-confirmed exact-version unlock, locking and inactive revocation do not have HTTP equivalents. Persistent mode rejects the legacy admin-only check bypass; default session-only compatibility remains.
- Registered requests capture an activation lease and revalidate after review under the same registry lock as audit persistence. Revocation, rotation, scope changes, locking and lock-and-reunlock cannot revive an old review.
- Baseline: 174 passed in 9.762s. Focused persistence/desktop run: 13 passed in 7.766s before adding the real SQLite write-denial regression. Final full suite: 187 passed in 19.807s, no skips. Windows test cleanup was corrected to close its SQLite connections explicitly; no product security behavior was mocked to make the suite pass.
- Reviewed privilege boundaries, store corruption/version/lifetime rejection, actual SQLite rollback, second-owner rejection, credential non-disclosure, stale UI confirmations, failed admin writes and real SDK/HTTP post-review invalidation. Publication is recorded by this entry's commit and branch history.
- Limits: prototype A, inherited Windows directory permissions, no DPAPI/encryption/rollback protection, no timestamp expiry/one-shot grants, no comprehensive lifecycle audit, separate registry and decision-audit transactions, synchronous HTTP and no downstream execution binding. Stronger claims require B and independent evidence.

## Scanner correctness and grounded platform sequence

- Preserved the interrupted batch and completed its review. Removed the input-controlled scanning exclusion, restored original locations, redacted match values, counted all rule occurrences with bounded examples, fixed private-key header matching and repaired dismissal without claiming remediation.
- Added a 1 MiB selection limit, supported-extension checks, rejection of oversized/NUL-containing decoded content, and protection against stale asynchronous reads. Clarified heuristic priority, no-findings limitations and local-only review. No authorization, credential, approval or execution behavior changed.
- Added the source-grounded platform assessment and development sequence, separating current desktop/core and text-pattern behavior from planned File Security, Device Security, Security Assistant, structured evidence and isolated Windows authority.
- Final verification: 187 core tests passed in 36.759s; 8 scanner tests passed in 314.2097ms. Total 195, no failures or skips. The core suite used the existing Windows temporary-directory ACL compatibility shim; scanner tests execute the real page script with a minimal DOM substitute. No browser visual/accessibility or malware-coverage claim is implied.
- Reviewed the complete source/test/documentation diff and whitespace checks. Test-generated audit changes were excluded. Publication is recorded by this entry's commit and branch history.
- Remaining scanner limits: main-thread regex execution has no CPU deadline, incomplete binary/encoding validation, uncalibrated rules and false positives/negatives. No desktop scanner integration, malware engine, model, monitoring, quarantine or executor was added. See PLATFORM_DEVELOPMENT.md for the dependency sequence and owner decision gates.

## Structured primitive review after bf2a152 (2026-09-26)

- Fetched and reviewed all 11 commits through remote `6916023fc0837e6c7fc3eaf72b6d8f91b86e0685`. Original laptop checkout remains at the handoff because Git metadata writes were denied; fixes are in a separate local working copy on `securitybrightness-core`.
- Repaired literal newline escapes that made two implementation modules and one test module unimportable. Restored the tested prohibition on implicit boolean conversion of constraint matches.
- Rejected authority fields after tuple-to-JSON normalization; bounded recursive validation and prohibited non-string object keys before encoding. Enforced ASCII before Unicode case conversion and used the same identifier validation for constrained authority.
- Preserved exact resource-reference text so trimming cannot collapse distinct proposals. Constraint applicability now rejects nonempty effects/resource attributes unsupported by its schema. Validated decision identity syntax and made legacy action migration a fixed explicit table.
- Added nine adversarial regression tests covering those boundaries and complete-snapshot binding. Updated behavior and design-gate documentation. No v1 service, SDK, registry, policy, or execution changes.
- Validation: all 268 Python tests passed in 46.536 seconds, no skips; all 8 JavaScript scanner tests passed. `git diff --check` passed. Python 3.14's ordinary full run encountered Windows sandbox temporary-directory ACL failures. The successful full run used a local harness outside the repository that only lets test temporary directories under a dedicated workspace scratch folder inherit its ACL, consistent with the earlier recorded Windows test workaround. Product permission checks were not mocked or relaxed. The 38 structured tests also passed without the ACL workaround (29 existing plus 9 new).
- No enforcement claim: bindings remain caller-constructible inspection data, not approval or execution capabilities. Authenticated issuer/application binding, final policy/grant revalidation, replay semantics, operation-specific schemas and real resource identity remain gates before a protected-path prototype. Runtime `security_events.json` is excluded from the change.

- Final pre-publication review: corrected an encoding error in the design-gate heading; confirmed no live v1 imports of the draft primitives. Reran all 268 Python tests (33.615 seconds, no skips) and all 8 scanner tests successfully. The same workspace-only temporary-directory ACL test harness was used. Remote head was still `6916023` before committing.

## Roadmap step 4: bounded file-read schema (2026-09-26)

- Published the preceding reviewed hardening batch as `24b5544b6486ee53349ce66dac96ddf91cb73b0b` on `securitybrightness-core`, verified against GitHub. Runtime `security_events.json` was not included.
- Implemented the next milestone locally: pure construction/inspection helpers for `file_read.v1`, one descriptive file resource, explicit whole-file byte limit from 1 through 1,048,576, and recipient `requesting_application`. No defaults, alternative recipients, attributes, extra effect fields, or automatic legacy conversion are accepted.
- The immutable inspection result carries the complete proposal identity and rejects boolean conversion. Schema inspection performs no filesystem access. Requester context remains untrusted, and the existing constraint evaluator still rejects the unsupported effects. No live service/SDK, grants, human authority, persistence or execution behavior changed.
- Added 12 regression tests and a precise contract document. Final review checked unknown/missing fields, byte-count type confusion, resource cardinality, context/authority injection, exact decision binding, snapshot detachment, no filesystem access and continued fail-closed constraint behavior.
- Validation: all 280 Python tests passed in 31.061 seconds with no skips using the same workspace-only Windows temporary-directory ACL harness; all 8 scanner tests passed. The 12 new tests also passed directly without that harness. Diff whitespace checks passed.
- This milestone is separate from the preceding hardening batch; publication is recorded by its commit history. Next dependency: effect-aware constraints and authenticated decision/application provenance, with final revocation/replay semantics, before any separately designed protected file-access path.

- Final adversarial review expanded the existing 12 schema tests with reference aliases/Unicode differences, reserved authority keys across containers, cyclic/deep/nonfinite/malformed context, the exact shared message-size boundary, and generic structured-snapshot compatibility. No schema implementation changes were needed. All 280 Python tests passed in 32.712 seconds (no skips, same workspace-only Windows temporary-directory harness), and all 8 scanner tests passed. References remain unverified descriptive text. Runtime `security_events.json` is excluded.

## Roadmap step 5 preparation: effect-aware file-read constraints (2026-09-26)

- Published and verified the adversarially reviewed file-read schema at `b113bf9ebec279fbb791c5f69b5b3f6fac328e81` on `securitybrightness-core`. Its 280 Python tests and 8 scanner tests passed; runtime `security_events.json` was excluded.
- Added a separate inactive `FileReadConstraint` snapshot and explicit applicability evaluator. The proposed application must match the owner, the strict file-read schema must validate, reference text must match exactly, and the proposed byte limit must not exceed the constraint ceiling. No wildcard/path normalization or broad-constraint fallback is introduced.
- Reused existing application/lifetime validation and strict file-read proposal validation. The full constraint envelope is bounded, inspection copies are detached, and implicit boolean conversion is forbidden. Session/unlimited labels remain metadata only; unsupported modes fail validation.
- Added 12 tests for immutable snapshots, complete-message limits, ownership, byte-boundary behavior, reference ambiguity, malformed/unknown effects, attributes, mutation/context injection, decision identity changes, v1/generic evaluator separation and absence of file access.
- Validation: all 292 Python tests passed in 30.228 seconds with no skips using the documented workspace-only Windows temporary-directory ACL harness; all 8 scanner tests passed. The 12 new tests also passed directly. Whitespace checks and review of production imports confirmed the new helpers are not consumed by live authorization.
- Publication of this draft is recorded by its commit history. Step 5 is not complete: authenticated authoritative issuance, grant/version identity, persistence/activation, final revalidation, revocation, lifetime and replay semantics remain gates. No component performs file access or active authorization, and a path/reference string is never verified file identity.

- Final pre-publication adversarial review added four regression tests for every required effect, JSON type confusion, both byte-ceiling extremes, mutated effect inputs, owner/reference/limit spoofing through context, complete-snapshot binding and unsupported operation/resource/effect extensions. No implementation correction was needed. All 296 Python tests passed in 30.065 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. Runtime `security_events.json` was excluded.

## Step 5 preparation: versioned draft-review lifecycle (2026-09-26)

- Published and verified the inactive effect-aware constraint milestone at `0920b86dd17e95beb279207434ebe717ae9f9b4d` after 296 Python tests and 8 scanner tests passed. Runtime `security_events.json` was excluded.
- Added a separate bounded session-local draft ledger, generated draft IDs, monotonic expected revisions, owner-preserving replacement, terminal draft revocation and one outstanding exact-proposal review per draft. Replacing identical content still invalidates earlier review state. Revoked draft IDs are never recycled within the session.
- Review freshness requires the exact locally issued outstanding ticket, the current ledger session and draft revision, the supplied application owner and exact canonical proposal identity. New review supersedes old review; discarding a stale/copied ticket cannot retire its replacement. Checks and mutations share a lock.
- Added 12 tests covering stale/concurrent updates, terminal revocation, immutable views, altered owner/proposal/context, copied/cross-session tickets, capacity, invalid inputs and absence of filesystem access. Full verification: all 308 Python tests passed in 32.337 seconds with no skips using the documented workspace-only Windows test-folder harness; all 8 scanner tests passed. Focused new tests also pass without the harness, and whitespace checks pass.
- Publication of this draft is recorded by its commit history. There is deliberately no human approval, activation, allow decision, persistence or execution API. Freshness is only a point-in-time fact and does not atomically authorize a future effect. `/check` and all live v1 behavior remain unchanged. References remain unverified text.
- Remaining gates include authenticated reviewer/application provenance, authoritative grant issuance and activation, grant/credential version binding, persistent recovery/unlock, expiry/use accounting, durable revocation, final revalidation, replay semantics and real resource identity/enforcement design. This prototype does not claim those gates are solved.

- Final adversarial review (2026-09-27): rejected duplicate generated draft IDs before mutation, so an identity-generation failure cannot overwrite or resurrect a draft. Added four tests for collisions, concurrent duplicate reviews, revocation/review races and requester/copied-state broadening attempts. All 312 Python tests passed in 31.670 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. Review state remains non-authoritative, and `/check` and file access are unchanged. Runtime `security_events.json` is excluded.

## Registry-bound draft review prerequisite (2026-09-27)

- Published and verified the adversarially reviewed lifecycle milestone at `44931a9f452829edc37282edd401bd8c1f11a6bf` after 312 Python tests and 8 scanner tests passed. The duplicate generated-ID overwrite edge case was closed; runtime `security_events.json` was excluded.
- Added an isolated coordinator binding draft review tickets to an authenticated existing application snapshot and registry activation lease. No registry/service changes are needed. Old evidence becomes stale on credential rotation, permission/trust changes, revocation/re-registration, persistent lock/re-unlock, storage failure or registry closure.
- Retained exact proposal/owner/draft binding, issued-ticket identity checks and supersession/discard semantics. Lock order is coordinator, registry lease, then draft ledger. Tickets expose no credential/hash, and the coordinator does not retain raw credentials.
- Added 10 regression tests, including existing SQLite-backed inactive startup and lock/re-unlock semantics, storage failure, registry/draft invalidation, copied/cross-coordinator evidence, an authentication/lease-capture race and no filesystem access by the new coordinator.
- All 322 Python tests passed in 34.179 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. Whitespace checks passed. No production caller imports the new coordinator, and `/check` remains unchanged.
- Publication of this draft is recorded by its commit history. A current review is not a policy/scope check, human approval or execution lease; a regression test explicitly covers current evidence for an authenticated record with no scopes. No active structured authorization, file access or enforcement is introduced. The resource references remain unverified.
- The gate matrix in registry-bound-review.md separates tested registry/draft freshness from remaining trusted resource identity, human-decision provenance, approved constrained-grant lifecycle, final proposal/version revalidation, revocation/replay consumption and downstream operation binding. No protection claim is made.

- Final adversarial review (2026-09-27): unexpected registry/review-state exceptions now permanently retire the pending evidence and return a redacted non-current result. Invalid proposal argument types are rejected before this infrastructure-failure boundary. Added six tests for lookup failure/recovery, corrupt/missing state, reused grant IDs, stale allow bindings, delayed consumption and concurrent registry mutation. All 328 Python tests passed in 29.954 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. No live `/check`, v1 or file-access code changed, and `security_events.json` is excluded.

## Adapter observation and exact-operation contract model (2026-09-27)

- Published and verified registry-bound review at `b06d1533b05da86b90a108f6b8f0d2df282b247c` after 328 Python tests and 8 scanner tests passed. Unexpected state failures now retire evidence permanently; runtime `security_events.json` was excluded.
- Added a separate bounded adapter-observation session model and exact file-read operation bindings. Supplied volume/file metadata and display labels never come from automatic proposal/context parsing. Only exact locally issued live observations and bindings match; application/proposal/effect changes, release, replacement, supersession or cross-session/copy attempts fail matching.
- Replacement retires old evidence before validating new reports. Tombstones and ID-collision rejection prevent session-local identity reuse. Observed sizes must fit the explicit proposed byte ceiling. Unknown/network/nonregular/reparse profiles fail validation. Reports remain caller-supplied synthetic metadata, not OS-verified facts.
- Added 12 tests covering structural provenance separation, metadata types, same-path/different-file reports, alias observations, replacement with identical/changed metadata, failed replacement, lifetime replay, mutation, exact proposal binding, capacity and absence of file access. All 340 Python tests passed in 33.669 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. Focused new tests also passed directly. Whitespace checks passed.
- Consulted primary Microsoft documentation for handle identity, file-ID lifetime limits, access/sharing and reparse behavior. The design requires a future retained-handle collector and explicit Windows race/namespace policy, not path normalization or a metadata-only identity claim. Source links and the end-to-end denial gate are documented in resource-observation-binding.md.
- Publication of this model is recorded by its commit history. No Windows calls, real handles, file access, `/check` integration, active authorization or enforcement were added. Synthetic-report tests do not close the resource-identity gate. The remaining gates include trusted collection, human/authority envelope binding, final revalidation and replay/use accounting, exact downstream operation binding and a controlled real-operation denial demonstration.

- Observation model final review (2026-09-27): added irreversible session closure, safe rejection of malformed copied IDs and a UTF-16 path-length bound. Four added tests cover these conditions, unsupported schema/effect fields and the intentional separation between resource matching and current registry authority. All 344 Python tests passed in 38.890 seconds with no skips using the documented Windows test-folder harness; all 8 scanner tests passed. No real collector or execution path is part of this commit.

## Windows retained-handle identity prerequisite (2026-09-27)

- Published observation model `fef2db107c80bd26844948ecc15400cf74d581ed` after 344 Python and 8 scanner tests passed.
- Added a separate inactive Windows metadata-only collector using handle-relative component traversal and native volume/file identity. It rejects unsupported namespaces, reparse points, hard links, case-sensitive directories, remote/non-NTFS resources and missing metadata. Retained handles, exact issued observation lifetimes, bounded sessions, terminal invalidation and fail-closed cleanup keep requester labels separate from OS identity.
- Added 28 tests, including real Windows fixture tests for junctions, hard links, case/slash aliases, parent replacement during traversal, writes, replacement/deletion/recreation, read-access denial on metadata handles, copied reports, binding mismatch, query failures and cleanup faults. Tests exposed that metadata-only share flags do not exclude writers; implementation/documentation explicitly preserve content stability as an unresolved gate.
- Complete validation: 372 Python tests passed in 39.072 seconds with no skips using the documented workspace-only Windows temporary-directory ACL harness; all 8 scanner tests passed. No live v1 or `/check` changes, content-read implementation or enforcement claim. Runtime `security_events.json` remains excluded.

## Combined resource-review evidence prerequisite (2026-09-27)

- Published Windows collector `972c2a59feda6ab14dbee649a27d4b70a3a9388f` after 372 Python and 8 scanner tests passed.
- Added inactive bounded envelopes pairing exact registry/draft review evidence, application/proposal identity and the collector's observation/operation binding. Review checks bracket native resource validation; injected credential/grant/draft changes invalidate the evidence. Supersession, retirement, copied/transferred evidence, duplicate IDs and concurrent captures are tested. This remains non-atomic sampling: it neither records human approval nor supplies permission, a consumption lease or one-use execution.
- Further narrowed Windows drive traversal to an OS-reported actual volume root, rejecting aliases into subdirectories before relative traversal; this shape check is a namespace policy, not resource identity. Added its regression test and 16 combined-envelope tests.
- Complete verification: 389 Python tests passed in 38.425 seconds with no skips using the documented workspace-only Windows temporary-directory ACL harness; all 8 scanner tests passed. Reviewed imports confirm no active `/check` or v1 caller consumes these primitives. Runtime `security_events.json` is excluded.
- Stopped at the explicit product decision described in resource-review-envelopes.md: does human consent cover a file object plus bounded effect or exact immutable bytes? Metadata-only handles cannot establish the latter. The document defines the fixture-only denial experiment and remaining trusted acquisition/human-control, authoritative grant/decision, content-stability and atomic consumption/revocation/replay gates. No reader or enforcement experiment was introduced.

## First controlled fixture read enforcement (2026-09-29)

- Continued from `3af7057b68cc3928e718222df11090c7ac8d18ff`. Owner selected consent to the verified file object plus bounded read effect, not immutable bytes.
- Added a separate opt-in fixture-only bootstrap, application/operator ports and Windows retained-object read adapter. The bootstrap creates and pins one synthetic file; no caller pathname, arbitrary read, write/delete operation or process execution is accepted. The adapter requests read access through the retained object, verifies its identity and buffers at most 4,096 bytes.
- Current authenticated registry scope plus separate exact-envelope operator approval is mandatory, including for trusted applications. Review lifetime is 60 seconds without renewal, IDs/capacity are bounded, and the first attempt burns approval even on failure. Registry and experiment lifecycle locks define publication/revocation ordering. Final checks and handle closure precede protected-byte delivery; failures do not release partial results.
- Added 39 adversarial tests using actual synthetic Windows fixtures. Coverage includes native read suppression on preflight denial, allow/replay, concurrent consumption/revocation, wrong owner/resource/proposal/effect, stale review/grants, persistent lock/re-unlock, malformed/oversized inputs, duplicate IDs, expiry before/during reads, short/error reads, failed metadata/closure, ordinary writer exclusion and existing writable mappings. Operator decisions and terminal input are explicitly simulated in tests. A manual interactive demo accepts no paths or automatic-approval flags.
- Complete verification: 428 Python tests passed in 41.090 seconds with no skips using the documented workspace-only Windows temporary-directory ACL harness; all 8 scanner tests passed. Existing service, SDK, `/check` and v1 production modules are unchanged; new experiment imports are confined to its demo and tests. Runtime `security_events.json` is excluded.
- Proven claim: this one controlled integration can prevent a denied native read and withhold all application-visible bytes on later failure. Not proven: direct Windows access prevention, hostile in-process isolation, external human identity, immutable contents, durable decision audit, or bounded cancellation of hung native I/O. A revoke arriving during the guarded read waits for that attempt; it is not retroactive cancellation. Work stops at this single fixture path.

## Dedicated fixture security review and interactive owner walkthrough (2026-09-29)

- Reviewed pushed milestone `d62e4e40edec5ca27f17d6b9b7889b22622937f6` against approval bypass/replay, ownership/proposal/resource/effect substitution, registry/draft staleness, post-buffer failures, collisions, capacity and expiry/revocation races.
- Reproduced a real expiry defect: a freshness inspection could cross the deadline after the initial clock check and still publish a read result or review display. Added terminal deadline checks after inspection, before display publication and at final result publication. Regression tests first failed on the old code, then passed with the correction. Added coverage for expiry during approval/evidence retirement, review evidence without permission, post-buffer draft revocation and nonrecyclable retired capacity.
- Expanded the opt-in human walkthrough to explicit DENY, ALLOW ONCE, replay, revoked/stale/expired decisions, changed effects and a second generated resource requiring separate approval. Nine typed decisions and a real 65-second expiry wait; no clock mutation, path input, automatic approval or personal files. Automated script checks use explicitly separate test-only input/time mocks and do not establish completion of a human demonstration.
- Documented the current trusted host/operator/registry/collector/reader boundary and the next isolated read-broker gate. A smaller broker can contain native/handle authority, but authenticated channels, capability and peer binding, staged delivery, cancellation and revocation fencing require tests before a real cooperating application. No broker or broader executor was introduced.
- Verification: 47 focused fixture tests passed; complete suite passed 436 Python tests in 38.179 seconds with no skips using the documented Windows workspace test-folder harness, plus all 8 scanner tests. `/check` and v1 production behavior remain unchanged. Runtime `security_events.json` is excluded. Owner walkthrough is ready but has not been completed by a person in this session.
