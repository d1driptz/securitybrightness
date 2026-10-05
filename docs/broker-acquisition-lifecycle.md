# Inactive live acquisition lifecycle and publication check

`core/broker_acquisition_lifecycle.py` composes the exact inactive acquisition
owner, its live review and the existing authenticated byte quarantine. No existing
host, child, desktop, protected reader, `/check` or v1 route imports it. There is
no file acquisition, native read, arbitrary operation or delivery API. Adapter
frames carry synthetic bytes in tests; publication checks release zero bytes.

## Lifecycle

The separate coordinator port reserves explicit ALLOW ONCE evidence over current
application authority and the exact reviewed proposal/resource/effect context.
The adapter port begins one attempt, stages an authenticated reply, requests
discard and accepts a discard acknowledgement. The separate coordinator port
then performs the final publication check. Port possession and key custody remain
trusted bootstrap assumptions, not independent human authentication.

Beginning burns the original acquisition slot before validation. The source
moves to `acquisition_inflight` rather than being retired at acquisition time.
Thus final checks can still inspect the original live review ticket. The older
draft consumption path cannot bypass this lifecycle, and duplicate or malformed
attempts retire it. No component creates, activates, extends or restores grants.

Every transition checks current registry authority, draft/version, proposal,
review and display snapshots, the exact issued reservation, and the original
deadline. Acquisition and final checks reauthenticate the exact application and
proposal. Lock order is lifecycle, acquisition, review, registry, ledger, codec.
No authority lock is held between calls while an adapter would work or wait.

## Quarantine and cleanup

The existing separate quarantine wire domain binds the complete immutable
reservation context, including application, grant/draft/version, decision/review,
resource session/owner/token, OS-identity claims, size, byte limit and recipient.
Those identity fields remain authenticated reports until a native integration
verifies them. Path strings do not establish identity.

Only an exact bounded staged reply is accepted. DENY cannot carry bytes and
cannot become staged success. Decoded data stays in a private bytearray; the
adapter receives only count/digest metadata. Buffer size and digest are checked
again before discard, and returned staging/retirement evidence is snapshot-checked
to detect mutation. Errors, cancellation, expiry and discard clear the buffer.
Shutdown independently clears the owned bytearray even if closing the codec fails;
source review is retired in a separate cleanup path. Cleanup failure still returns
no successful check. Internal retirement is distinguished from public cancellation
so a cancellation arriving through a cleanup hook cannot produce success.
Clearing is not secure erasure of every immutable transport/Python copy.

Discard clears the coordinator buffer before the peer acknowledgement. An exact
authenticated acknowledgement is required before the final check. It establishes
only that this protocol completed: **it is not proof of native handle closure,
EOF, child exit or job cleanup**. A future process host must establish those facts
independently and must join its child. This composition owns no process.

## Separate final publication check

The final attempt checks current live authority and exact caller/proposal again,
then closes quarantine and retires source review. After all cleanup it rechecks
registry lease, application state, draft, proposal, review/display snapshots,
reservation/evidence mutation and expiry. A failure returns no result and leaves
the attempt spent. A successful result is immutable `eligible_discarded` metadata,
with exactly zero released bytes and no data or later-operation token. The checked
review and resource report cannot be replayed to publish anything afterward.

This deliberately tests final-check ordering without adding an executable path.
The native acquisition adapter, held-resource freshness through acquisition,
process cleanup and final delivery still need a controlled generated-fixture
integration. Neither synthetic staging nor this metadata result expands the
existing fixture protected-reader claim. Application authority alone and review
evidence alone remain insufficient.

The 51 adversarial tests cover live source retention, missing/denied review,
revoked authority, application/proposal/effect mismatch, token copying/mutation,
stage/ack replay, malformed or substituted staging, denied data, oversized input,
buffer/evidence mutation, registry/draft changes, superseding reviews, expiry,
concurrent attempts, reentrant cancellation and codec/source cleanup failures.
Tests use authenticated synthetic peers and bytes; they do not perform native reads
or constitute an owner walkthrough.

The separate [fixed native acquisition adapter](broker-native-acquisition.md) now
tests real generated-fixture reads into this quarantine while retaining zero-byte
discard/publication semantics. The separate inactive
[child-owned discard host](broker-acquisition-host.md) composes it with fixed
process ownership and cleanup checks; no product route or real application
delivery is activated.
