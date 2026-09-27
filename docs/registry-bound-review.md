# Registry-bound review freshness (inactive prototype)

`RegistryBoundFileReadReviews` adds a tested prerequisite for authority lifecycle binding: review freshness is tied to an application authenticated by the existing registry and its captured activation lease. This module is not imported by `/check`, the SDK, policy engine, file analyzer or any execution path. It does not activate, change or persist authority and has no approval or allow operation.

## What is bound

Beginning review authenticates the supplied application credential against the existing registry. It captures the existing `authorization_lease` and, while that lease is current, obtains an exact-proposal review ticket from the isolated draft ledger. The returned immutable ticket exposes the draft ticket and existing grant ID, never the credential or its hash. The coordinator retains only the ticket and registry lease callback; raw credentials are not retained.

Checking review recognizes only the exact outstanding ticket issued by that coordinator. Under the captured lease it checks the ledger's session, draft revision, revocation state, application owner and full canonical proposal identity. Credential rotation, registry permission/trust changes, revocation, re-registration, closure and failed storage invalidate the old registry snapshot. Persistent lock-and-reunlock invalidates its activation lease even when the grant ID stays the same. These failures retire the coordinator's pending review and cannot be repaired by changing requester context.

One review is retained per draft. New review supersedes old review, copied/cross-coordinator tickets are rejected, and discarding an old ticket cannot retire its replacement. Lock ordering is coordinator, registry lease, then draft ledger. The wrapper does not add callbacks to live registry operations.

## Current evidence is not authority

A `current` result is point-in-time evidence of authenticated registry liveness plus unchanged draft/proposal state. It is not a scope check, policy result, human decision, grant issuance, file-read capability or atomic authorization for a later effect. Tests intentionally demonstrate that an authenticated record with no scopes can still produce current review evidence: interpreting it as permission would be incorrect. The constraint draft remains caller-constructible by trusted in-process code and is not an operator-approved constrained grant.

Repeated freshness checks do not consume authority and do not implement replay prevention for operations. Any result can become stale after the locks are released. This is a trusted in-process prototype, not a cross-process authentication boundary or protection against hostile code mutating private objects. Credentials are used only to establish the initial existing application snapshot; a ticket is not proof of a new caller's credential possession.

References remain untrusted descriptive text. The module performs no file access, path resolution, resource verification, or execution. Persistent registry storage exercised by tests is existing authority storage, not a newly protected file-read path.

## Remaining activation and enforcement gates

| Gate | Evidence now available | Still required before activation/enforcement |
| --- | --- | --- |
| Application/registry lifecycle binding | Credential authentication, exact registry snapshot and activation-lease invalidation | Approved structured-grant issuance bound to authoritative versions; a trusted public boundary |
| Proposal/version freshness | Exact canonical proposal, owner, draft revision and ticket identity | Trusted human-decision provenance and binding; revalidation at final authorization |
| Revocation and replay | Old draft and registry reviews become stale after tested changes | Defined execution replay/use accounting, durable constrained-grant lifecycle and atomic consumption |
| Trusted resource identity | None; strings remain descriptions | Trusted adapter-owned resource identity and race/link/replacement handling |
| Downstream operation binding | None; no operation exists | Exact operation bound to verified resource, effects, current authority and human decision |
| Real enforcement | None | Controlled integration where denial or failure genuinely prevents the protected operation, with bypass/failure tests |

No row is bypassed by a current review result. Existing v1 authorization behavior is unchanged. A real-operation protection claim remains prohibited until the final row is demonstrated.

## Final failure and race review

Unexpected registry/review-state failures retire the pending ticket and return `review_state_unavailable` without disclosing exception text. Recovery does not restore that ticket. Invalid proposal argument types are rejected before this failure boundary. Tests simulate corrupt/missing records, grant-ID reuse with a changed registry object, and lookup failure followed by recovery. This does not claim tamper-proof storage or detect malicious private-memory rollback that was never observed; trusted-process and durable rollback-protection limits remain.

Concurrent revocation serializes with a freshness check under the registry lease. A check completed before revocation can report current, but a subsequent check must fail. Old immutable freshness or proposal-decision records do not change retrospectively and are not accepted as tickets or authority. No human review decision is collected by this prototype.
