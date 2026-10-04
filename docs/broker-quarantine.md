# Inactive staged-byte quarantine contract

`core/broker_quarantine.py` is a pure, I/O-free protocol draft. No existing broker,
host, desktop, authorization endpoint or protected reader imports it. Tests use
synthetic bytes in memory; this milestone adds no file acquisition or delivery.

The four-frame exchange is:

1. Bind an exact application/proposal, grant ID, draft ID/revision, review ID,
   decision ID, broker resource-session/owner/token, volume/file identity, observed
   size, byte ceiling, `files.read` effect and requesting-application recipient.
2. Receive authenticated staged bytes or DENY. DENY must contain zero bytes.
   Staged data must have exactly the bound observed size within the byte ceiling.
   Only count/digest metadata is returned; the coordinator retains the bytes in
   its private quarantine buffer.
3. Discard: clear the retained buffer before emitting the authenticated discard
   request, bound to both context and staged-data digests.
4. Accept the exact authenticated discard acknowledgement. Return only immutable
   discard evidence reporting zero released bytes, then permanently close.

There is **no release, commit, executor, read or buffer-retrieval API**. Signed
commands or acknowledgements attempting release are rejected. This draft cannot
convert retired review receipts into a read permission, and accepts no authority
flags, pathname, resource reference or arbitrary effect attributes.

## Bounds and fail-closed behavior

Each endpoint has an absolute lifetime of at most five seconds from construction,
including an independent timer that closes idle quarantine state. Staging, viewing
metadata and discard never renew the deadline. Every frame authenticates role,
step, previous-frame hash, exact content and the fresh bootstrap session in a new
MAC domain. Old broker/read/metadata frames are not interchangeable.
Expiry is checked on every transition. Scheduled buffer cleanup depends on thread
scheduling and is not a hard real-time memory-erasure guarantee.

The schema bounds identifiers, canonical UUIDs, draft revisions, resource identity,
observed size and 1–4096 byte ceilings. It rejects duplicate cross-role identities,
unknown fields, unsupported operations/recipients and bool-as-integer confusion.
Frame length is checked before parsing, base64 is bounded/canonical, and decoded
length must match the bound size. Every invalid transition permanently closes the
endpoint and clears its retained buffer. Concurrent discard has at most one winner;
replay cannot resurrect a discarded or expired exchange.

This is API separation inside a trusted process, **not protection against hostile
Python already in that process**. The trusted transport necessarily handles wire
frames containing staged data. Mutable-buffer clearing does not guarantee secure
erasure of immutable Python objects, caller copies, wire frames or OS buffers.
Digests and metadata should stay within the trusted coordinator too.

## What this does not authorize

Context fields and MACs prove binding and key possession only. This module does
not verify current registry authority, human identity, fresh review or the truth
of OS identity claims. It does not claim an authority revocation check merely
because a different grant/revision is rejected by transcript binding. Only a
future trusted coordinator may construct context from current, validated state;
requesters must never supply the context, bootstrap keys or endpoints.

Before any live read or release, separately solve and test:

- Issuing one-use acquisition authority from current registry/grant activation,
  exact fresh review and proposal/resource/effect binding. Review evidence alone
  must not become permission; retired receipts must remain unusable.
- Consuming that authority once at the trusted retained-handle adapter, including
  expiry, cancellation, revocation and native identity validation around staging.
- A final coordinator publication check after buffering and cleanup, serializing
  lifecycle changes at the delivery boundary and withholding all bytes on failure.
- Crash/replay/lost-ack semantics and a controlled generated-fixture experiment
  that genuinely demonstrates denied operations deliver no protected bytes.

Release will need a deliberately separate tested contract; it must not be added
as a permissive flag to this discard-only draft. `/check`, v1, the existing reader,
the process-owned metadata host and the verified desktop walkthrough are unchanged.

The inactive coordinator-side reservation lifecycle is now modeled separately in
[broker-acquisition-draft.md](broker-acquisition-draft.md). It combines live grant
and fresh review checks and permits only one consumption attempt. Its result is
still not acquisition permission: broker liveness, fresh native identity validation
and the retained-resource consumption transition remain explicit unsolved gates.
