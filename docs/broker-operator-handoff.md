# Inactive trusted-local operator handoff

`BrokerOperatorHandoff` adds a single-prompt handoff around `PendingBrokerReview`.
It is not connected to `/check`, v1, broker IPC, the existing protected reader or
the owner walkthrough. It records review evidence only and has no content-read,
permission-grant or data-delivery operation. Tests are automated simulations;
no new human demonstration is claimed.

## Boundary and exact input

The existing operator channel trusts the local OS session and exposes no
application-facing approval endpoint. This separate prototype uses the same
trust assumption without changing that existing channel. Trusted bootstrap
constructs the handoff and distributes worker/operator ports separately. The
worker can request review but cannot fetch a prompt or submit a response. Only
the trusted UI receives the operator port. Bootstrap must retain the original
pending-model operator port privately rather than also giving it to applications.

A prompt contains a generated 256-bit review ID and an immutable canonical display
snapshot, capped at 16,384 bytes. The underlying display includes exact request,
application, proposal, grant, draft version and native resource bindings. No
credential or authority-grant input is included. The UI must return the exact
issued prompt object, with unchanged ID and snapshot, and exactly `ALLOW ONCE`
or `DENY`. Dictionaries, copied/forged/mutated prompts, truthy values, alternate
text and replay are rejected terminally. A prompt ID alone is not a credential
or permission. Object provenance still rejects copies if identifiers collide.

This is a trusted local UI capability boundary, **not independent authentication
of a person**. It does not prove a human read the display, defend against hostile
code in the trusted Python process, supply Windows Hello, or authenticate a
remote/UI process. There is no network response endpoint or application JSON
field that can submit an approval.

## Queued answers and lifetime

`respond` only queues a response. Its return value explicitly does not confirm
freshness or permission, and forbids boolean conversion. The waiting coordinator
then calls the pending model to revalidate exact display, current registry/draft
and retained resource state before recording evidence. Credential rotation,
revocation, draft changes or redisplay during the wait therefore reject the
queued response. Future UI adapters must distinguish queued from recorded.

The lifetime is positive and finite, at most thirty seconds, beginning when the
worker starts review. Publication, waiting, recording and result return check
the same deadline; listing pending prompts cannot extend it. A daemon timer
closes the model at expiry even after evidence was recorded but never consumed.
The pending model's earlier deadline still applies. Cancellation, invalid input,
duplicate requests, cleanup failure and response replay retire the handoff.
Condition locking serializes response, timer and cancellation transitions.
Expiry while recording cannot publish successful evidence afterward.

The timer is not a hard real-time scheduler guarantee; it waits behind an active
serialized operation, whose final deadline check still rejects late results.
A previously returned evidence record cannot be recalled, but final consumption
still requires current model state. This local timer is separate from the
unchanged ten-second diagnostic-child watchdog. No human waits were inserted
into that child protocol. Before review starts, trusted bootstrap must still
close unused pending-model contexts; this handoff does not reap unrelated state.

## Tests and next gate

Tests exercise explicit responses, exact binding display, role separation,
forged/copied/mutated prompts, replay, duplicate workers, malformed confirmation,
oversized displays, nonce validation, cancellation, expiry during recording,
expiry after recording, cleanup failure, credential rotation, draft revocation,
redisplay and denial without protected bytes or grant changes.

Next define the actual trusted desktop UI/process authentication and transfer
boundary, then deliberately align its human-review lifetime with a live broker
session. Do not serialize an object-provenance check into a bearer approval
endpoint or lengthen the diagnostic watchdog to bypass lifecycle requirements.
The current channel and pending model remain local inactive prerequisites.
Acquisition/delivery authority, revocation fencing and one-use operation binding
still need tests before any broker read is enabled.
