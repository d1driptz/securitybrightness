# Inactive coordinator-owned pending broker review

`PendingBrokerReview` is a local, single-request prototype. It is not connected
to child IPC, the owner walkthrough, `/check`, v1 or the protected reader. It
owns one generated fixture session and records operator review evidence only.
There is no file-read, execution, scope-grant or authorization-result API.

## Separate roles and exact snapshots

Trusted bootstrap constructs the model with an existing application registry and
draft ledger, then distributes application and operator ports separately. The
application port can propose and consume evidence; it has no display, record or
operator-cancel method. The operator port can display, record `allow_once`/`deny`
evidence and cancel. This is logical API separation inside a trusted process,
not authentication of a real human or isolation from hostile Python. No new
human walkthrough is claimed.

Proposing authenticates the current application credential and requires existing
`files.read` (or existing wildcard) authority. It captures a registry activation
lease and a registry-bound draft review, and allocates its own generated resource.
The request ID/decision binding is coordinator-generated. No external observation,
path, grant, approval flag or decision ID is accepted. Plaintext credentials are
not stored in the model, display or result.

The display includes exact application/proposal identity, canonical proposal,
draft revision, grant ID, registry/owner session IDs, resource token, native
volume/file ID, file size, byte bound and display-only path. The original issued
display object and its immutable snapshot must both match when recording review.
Copies and mutations are rejected. Redisplay invalidates prior review evidence;
it cannot carry a previous allow record forward. Duplicate or invalid recording
is terminal. Denial closes resource ownership immediately.

## Freshness and one-use evidence

Before display, recording or consumption, the model checks authority/draft state,
revalidates the retained generated resource, then checks authority/draft state
again. The new broker inspection accepts only the exact locally issued
observation and original binding. Serialized, copied or retired wire receipts
cannot supply live ownership. The whole proposal, including effects/context,
remains bound to the resource. File references and displayed paths remain text,
not resource identity.

Consumption authenticates the application again and requires exact proposal and
current `allow_once` evidence. Its first attempt is terminal, including failure.
It closes the resource, checks authority/draft state again, retires the review
and performs final lease/draft/deadline checks before returning retired evidence.
The result contains a canonical display snapshot and no data or permission field;
implicit boolean conversion is forbidden. Recording and consuming evidence do
not modify or extend registry grants.

The coordinator serializes its methods and holds the registry lease and draft
ledger lock around final retirement. It uses the existing ledger's internal lock
and draft snapshot hooks, with regression tests guarding that coupling. Explicit
post-retirement checks detect same-thread fault injection too. This protects
this local evidence transition; it is not a downstream operation lease or an
atomic distributed authorization decision. External state may change after the
receipt returns, and the resource has already been retired.

The deadline is fixed at sixty seconds and cannot be renewed by redisplay or
recording; the broker session's earlier deadline still applies. Expiry is checked
on operations, not by a background thread in this local model. Trusted bootstrap
must close its context. Existing persistent registry lock/unlock semantics are
honored, including invalidating old activation leases after re-unlock. Legacy
in-memory registry mode has no lock lifecycle; this milestone does not change
that v1 behavior or present it as persistent grant management.

## Adversarial evidence and remaining gates

Tests cover missing authority/credentials, authority without review, denial,
replay, concurrent consumption, copied/mutated displays and requests, duplicate
review, redisplay, proposal substitution, credential rotation, revocation and
same-name registration, persistent lock/re-unlock, draft replacement/revocation,
same-revision constraint mutation, resource changes, serialized observations,
registry lookup failure, expiry during metadata and final retirement, and
registry/draft changes during resource verification or evidence retirement.

Before connecting this model to the child, define authenticated operator input,
a deliberately bounded human-review process lifetime, and a trusted mapping from
live authenticated channel observations to coordinator state. Do not import a
retired receipt as a live observation or treat `allow_once` evidence as permission.
Final acquisition and delivery still need current authority, exact downstream
resource/effect binding, revocation/cancellation fencing and one-use authority
consumption. No content acquisition, staging or broader enforcement is enabled.
