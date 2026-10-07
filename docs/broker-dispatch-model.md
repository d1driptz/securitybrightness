# Inactive publication dispatch and loss model

`PublicationDispatchLedger`, `PublicationDispatchAttempt` and
`PublicationDispatchExchange` model an irreversible visibility boundary and
receipt loss. They perform **no I/O, file access, native dispatch, authority check
or byte delivery**. No existing host, protected reader, desktop/owner walkthrough,
`/check` or v1 route selects them.

The complete original action/recipient/channel/count/digest envelope remains
inside an explicitly discard-only commit. A separate `dispatch_model_only` domain
adds an internally generated attempt ID, canonical bounded metadata and a strict
four-phase transcript. Unknown fields, authority/data/endpoint injection, type
confusion, unsupported effects/modes, ID collisions, mutation and replay fail
closed. The codec does not carry payload bytes. Every file/channel/grant/review
field in its binding is a caller-constructible claim, not trusted observation or
current permission. A valid dry-commit receipt cannot activate this model.

## Modeled boundary and uncertainty

Preparation and readiness precede a model reservation. `begin_model_visibility`
irreversibly records the attempt as spent and visibility as possible **before**
encoding even the metadata notice. This is the intended future ordering immediately
before an operation that may expose a byte; it is not proof that any operation
ran or that a byte reached a receiver.

Before that reservation, cancellation/expiry/rejection leaves `not_started`.
After it, cancellation, expiry, encoding failure, a simulated crash, a partial
write, missing/malformed receipt or peer disappearance leaves `outcome_unknown`.
Even a modeled write count of zero after the reservation is not interpreted as
proof of zero real delivery. The attempt stays spent and cannot retry.

This conservative profile accepts one simulated bounded local write observation.
A partial count (including zero for a nonempty payload) is terminal unknown; the
model has no continuation/retransmission API. A full count can await a receiver
claim. An empty payload still reserves/burns one complete request. Real native
chunking, stream framing and write-return semantics remain unimplemented.

A valid receipt claims exactly the original whole-file count and digest. It is
accepted only after the full modeled write, through the original transcript and
within the original lifetime. Snapshots explicitly say `observed_delivery:
unproven`; they have no `released_bytes` field and reject implicit truth testing.
They contain neither bytes nor executable authority. A receiver claim cannot
restore an attempt, authorize another action or retroactively turn uncertainty
into a zero-delivery guarantee. Cancellation after a sealed terminal claim keeps
only that archived unproven claim; it does not create permission.

## Session-local ownership and cleanup

One bounded in-memory ledger claims each supplied decision ID and resource token
once, without eviction, restoration or ID reuse. Its original attempt ownership
and immutable event journal are checked against current records. Each attempt
captures the original codec, event, timer, binding and deadline. Copies, replaced
records, state rollback, deadline extension and foreign owner/endpoint/snapshot
substitution are rejected. A single corrupted or deleted ownership alias cannot redirect
cleanup or leave the original attempt reusable after rejection.

Cancellation and the modeled visibility transition serialize on the original
ledger lock. The lifetime is capped at five seconds without renewal. Idle expiry
closes the original resources. Key/event/timer disposal is checked independently;
uncertain cleanup poisons the ledger and withholds successful inspection or new
claims. Foreign owner/endpoint objects are preserved. These defenses address
ordinary mutation/fault cases, not hostile code controlling all trusted Python
objects or the runtime, and do not guarantee secure erasure of interpreter copies.

A new ledger/process or fabricated new IDs can model another request. There is
**no global or persistent at-most-once guarantee**, actual source consumption or
restart recovery here. Applications cannot obtain actual authority from either
ledger: neither is connected to an authorization or execution path.

## What tests establish and what remains

Tests use in-memory metadata and simulated cancellation/loss/write observations.
They do not test actual registry revocation, native peer delivery or a real
publication boundary. The existing [fixed native dry commit](broker-native-publication-commit.md)
continues to discard all protected bytes and keeps its original guarantees.

The separate inactive [original-source dry reservation](broker-live-dispatch-reservation.md)
now binds this model to a current original live commit and consumes/discards its
quarantine. It adds no payload transport or delivery. The eventual delivery
integration must bind the model to the actual original source/decision,
current registry authority, separate human control and a trusted recipient. It
must serialize irreversible reserve/spend with those checks and cancellation,
then perform bounded dispatch outside authority waits. The eventual claim must
be precise: cancellation/revocation completed before that reservation blocks
dispatch; later changes cannot retract bytes already observable. A failed or lost
receipt must never enable another delivery, including across any supported
restart boundary.

Fixed native payload framing/cleanup, partial-write behavior, deliberate human-wait
lifetime, trusted cooperating-application onboarding and a controlled generated
fixture delivery experiment remain gates. No dry/model receipt bypasses them.
Application/AI intent does not equal human permission. SecurityBrightness remains
the authorization and human-control boundary, not an arbitrary executor or
antivirus.
