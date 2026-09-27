# File-read draft review lifecycle (inactive prototype)

This advances roadmap step 5's versioning and stale-review prerequisites. It does not implement an active grant lifecycle or authorize any operation. `FileReadReviewLedger` is an isolated, bounded, process-local store for constraint drafts and outstanding review snapshots. It has no approve, activate, unlock, allow, persist or execute method, and is not used by `/check`, the SDK, registry, policy engine or file analyzer.

## Draft state transitions

| Event | Result | Outstanding review |
| --- | --- | --- |
| Create a constraint draft | New generated ID, revision 1, not revoked | None |
| Replace using the exact expected revision | Same owner and ID, revision increases even for identical content | Invalidated |
| Revoke using the exact expected revision | Revision increases; revoked state is terminal | Invalidated |
| Begin review of an applicable proposal and exact draft revision | Draft unchanged; new session-local ticket | Previous ticket superseded |
| Discard an exact issued ticket | Draft unchanged | Only that ticket retired |

All mutation and freshness checks run under one lock. Stale, malformed or boolean revision values are rejected. A replacement cannot transfer ownership; that requires a separate new draft. Revoked IDs occupy capacity until the ledger is discarded and cannot be restored. Default capacity is 128 drafts, configurable from 1 through 4096; at most one review is outstanding per draft. There is no persistence or import path, so constructing a new ledger cannot resume old review tickets.

## Review freshness invariants

`begin_review` requires the explicit owner and a proposal that fits the exact inactive file-read constraint. It records the full canonical proposal identity, owner, generated ledger session, draft ID and revision. Invalid review attempts do not replace an existing current ticket.

`check_review` recognizes only the exact ticket object issued by that ledger and still outstanding. A copied or caller-constructed object with identical fields is insufficient. It then checks the current draft revision/revocation state, supplied owner and exact proposal identity. Changing the reference, byte ceiling or requester context invalidates the content binding even if the revised proposal would fit the constraint. A new review supersedes the old one; discarding an old or copied ticket cannot discard its replacement.

Drafts, tickets and freshness results are immutable inspection objects that reject implicit boolean conversion. Constraint inspection copies remain detached. These checks model trusted in-process coordination, not authentication or a defense against hostile code able to alter private Python state. Application IDs supplied by callers are not authenticated human or application identities.

## Deliberate limits

A current review means only that this ledger's draft and exact proposal agree at the moment of the check. It does not record a human decision and is never an allow result or capability. A draft can change immediately after the lock is released; no protected effect is coupled atomically to freshness. This prototype therefore cannot establish final execution revalidation or prevent operation replay.

References remain untrusted descriptive text. No filesystem existence, path safety, handle identity, link handling, or file content is examined. The model does not open files.

Actual authority issuance, trusted reviewer authentication, explicit activation, grant/credential version binding, persistent recovery with human unlock, expiry/use accounting, durable revocation, final revalidation and enforcement replay handling remain separate gates. Before any protected operation, verified resource identity and an isolated enforcement design must also be solved. Session/unlimited constraint labels still do not implement those authority semantics.

Tests cover immutable inspection, expected-revision races, replacement with identical content, terminal revocation, owner transfer rejection, exact proposal changes, cross-session and copied-ticket rejection, supersession/discard behavior, bounded capacity, fail-closed input handling and absence of filesystem access.

Generated draft identity collisions fail before any state change, including collisions with revoked drafts. Adversarial tests also cover simultaneous duplicate reviews and revocation racing review creation: after revocation completes no outstanding ticket remains current. This does not make a previously returned freshness result an atomic execution lease.
