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

## Prepared SDK proposals

- Added ActionProposal as an immutable JSON snapshot of the existing request, with independent inspection copies and ApplicationClient.check_proposal. Existing check calls use the same validation and transport path.
- Baseline: 152 passed in 7.276s. Focused proposal/SDK suite: 14 passed. Full suite: 157 passed in 9.778s.
- Regression evidence covers nested mutation isolation through real HTTP/audit, authority-field rejection, invalid/deep/cyclic/oversize JSON, scope changes and credential revocation between explicit submissions.
- Reviewed final diff: no HTTP schema, policy, approval or execution changes; no retries/caching. Publication is recorded by this entry's commit and branch history.
- Remaining limits: a local snapshot is not a signed capability, a versioned structured-effects protocol or downstream binding. Same-process Python callers remain trusted. Persistent grants, separate human identity, asynchronous approval and controlled resource integrations remain unimplemented.
