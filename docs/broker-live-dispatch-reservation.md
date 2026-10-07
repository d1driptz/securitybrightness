# Inactive original-source dry reservation

`LiveDispatchReservationDryRun` composes the existing original live
`PublicationCommitDraft` with the [dispatch/loss model](broker-dispatch-model.md).
It consumes and discards the original quarantine. It performs no file access,
payload transport or byte delivery, and no existing host, owner walkthrough,
protected reader, `/check` or v1 route selects it. The fixed native dry-commit
composition remains unchanged and separate.

## Original ownership, not a supplied claim

Construction accepts only the exact original live commit draft, already ready
with its original witnessed Windows child. It accepts no requester binding,
resource observation, retired receipt, callback, executable or endpoint. The
model envelope is derived internally from the draft's original complete
discard-only action/resource/effect/recipient/channel/count/digest binding.

Bootstrap must supply a coherent current owner graph. Registry, ledger, review
manager, source, review, recipient, native child/API and codecs must have the
expected exact types and relationships. Bootstrap performs nonblocking checks
for busy or malformed locks before invoking source validators. This is not
attestation of the history of arbitrary private objects: hostile code controlling
the trusted process/runtime is outside the boundary. Invalid bootstrap inputs
are rejected before the wrapper owns the source; they do not authorize an
operation or necessarily consume an otherwise untouched original draft. Tests
restore preconstruction injected faults before the existing worker performs
disposal, and do not claim the wrapper owns those earlier faults.

After construction, the wrapper captures the original owners, locks, activation
lease, registry/review ledger, native ownership/API, codecs, timers, buffer,
descriptor, envelope and deadlines. Corroborated immutable ownership references
and a separate immutable status history detect mutation, alias deletion,
substitution and rollback. Recovery addresses a single damaged alias, not a
hostile runtime able to rewrite every private anchor. Foreign substitutes are
never used as original cleanup targets.

## Serialized consume and modeled reservation

Preparation and readiness exchange only bounded model metadata with a synthetic
peer in tests. Neither message is authority. The first `reserve_and_discard`
attempt is spent even when its application, credential, proposal or recipient is
invalid. After successful construction, rejection/cancellation retires the
captured source and wipes the original quarantine; restoring a field or making a
new wrapper cannot restore the source's spent review/operation.

The final operation uses the captured lock order: helper, commit, reservation,
source, recipient, acquisition, review, nonblocking review-coordinator guard,
original registry activation lease,
review ledger, native ownership and model ledger. The existing commit performs
current application authentication, exact proposal/recipient checks and required
human-review freshness. Application authority alone and review evidence alone
each fail. No registry or authority lock is held across transport I/O, human wait
or worker join.

The coordinator guard never waits: another coordinator thread can own that lock
while waiting for registry authority already held by the original parent. The
wrapper rejects this contention instead of joining a lock cycle. Cancellation
signals the admitted running worker, which disposes only after the parent's
authority locks unwind. This guard covers the wrapper; existing source paths
retain their prior behavior.

The original commit consumes and discards first. The wrapper rechecks its exact
consumed result/source/proof/native channel, then records the private irreversible
modeled visibility barrier under the same owner/authority serialization. Checks
repeat after model encoding and cleanup, before any result escapes. A failure
after consumption stays source-spent even if the modeled barrier was never
reached. A sibling wrapper or separate draft sharing that source cannot consume
it again.

Revocation completed before reservation prevents consumption. A concurrent
revocation waiting on the original registry lease takes effect after that
critical section; it cannot retroactively change an already produced retired
fact. Subsequent original receipt/freshness checks reject after it takes effect.
The returned fact is never permission for a later operation.

## Zero-byte evidence and disposal

Successful evidence says `reserved_discarded` and `released_bytes: 0`. It contains
the exact binding/count/digest, no payload or capability, and rejects implicit
truth testing. Its `inspect()` returns detached metadata. Expected fields are
checked directly against captured values, not against another potentially
faulty evidence constructor. Archived mutation cannot become a newly accepted
fact through cleanup or resnapshotting.

The model is closed without any simulated write or receiver claim. Its terminal
`outcome_unknown` describes the hypothetical model channel; it does not negate
the actual zero-byte discard-only result or prove anything about delivery. No
wrapper API returns the model visibility notice or original commit notice.
Tests use the private original notice solely to finish the separate synthetic
commit transcript.

The wrapper's lifetime is at most five seconds and never exceeds the original
draft deadline. Idle expiry cancels the original operation. Failure disposes
original local model resources, signals the original worker and wipes the
buffer. Captured codec locks are restored for disposal only, so a foreign lock
does not redirect cleanup. Uncertain/no-op cleanup withholds success and may
continue to report a fixed cleanup error; it is never silently accepted. Normal
repeated close preserves a valid archived success without cancelling the
original worker. Only that worker closes/joins its Windows child, and the
wrapper's evidence does not prove native EOF, zero exit or joined cleanup.

## What remains before delivery

Tests combine a real original fixed Windows witness with synthetic observed
resource bytes, operator decisions and model readiness. They establish original
live authority/source binding and serialized one-use consume/discard. They do
not establish a native payload channel, authenticated cooperating-application
identity, general resource truth, immutable contents, durable restart recovery
or protection against direct Windows access.

The next gate is a separate bounded fixed native payload protocol and private
transport with explicit partial-write, receipt-loss, cancellation, crash and
cleanup behavior. It must remain inactive while tested. A deliberate human-wait
profile and trusted cooperating-application association are still required
before any controlled fixture-delivery composition. Neither a dry receipt nor
this reservation evidence may activate that composition. Application/AI intent
does not equal human permission; SecurityBrightness remains the authorization
and human-control boundary, not an arbitrary executor or antivirus.
