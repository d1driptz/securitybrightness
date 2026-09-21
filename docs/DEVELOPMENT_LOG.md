# Development batches

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
