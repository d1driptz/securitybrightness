# Development batches

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
