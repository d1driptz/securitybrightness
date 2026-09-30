# Inactive authenticated two-round metadata sessions

`diagnose_session` is an opt-in diagnostic. It is not connected to `/check`, v1,
the protected reader, the owner walkthrough, or any application integration. It
creates one synthetic resource, observes it while held by the child, verifies or
cancels its metadata binding, then retires it. Content reads and delivery are
absent. Every successful result has outcome `denied`, empty data and lifecycle
`retired`; the result is not an authorization decision or a live capability.

## Four authenticated frames

1. Coordinator sends the exact application ID, decision ID and canonical bounded
   file-read proposal. These remain binding fields, not authority.
2. Child issues one resource through its capacity-one ownership registry and
   returns the registry session and strict native observation. The creation
   handle stays in that child while it waits for the next message.
3. Coordinator sends either `verify` or `cancel`, bound to the digest of that exact
   observation. No read, grant, renewal, caller-selected path or callback command
   exists. Verification compares metadata/intent only.
4. Child closes all resource ownership before acknowledging retirement. The
   acknowledgement binds the action and observation digest and permits only
   denied/retired metadata status, never a byte payload.

A distinct MAC domain separates this protocol from both prior codecs. Each frame
also authenticates its exact step number, direction, bootstrap session, canonical
contents and SHA-256 hash of the previous complete frame. Thus the final message
is tied to the entire request/observation history. Wrong-role/order calls, replay,
transcript splicing, malformed fields or failed authentication permanently close
the endpoint. Legacy inherited codec methods are explicitly disabled. Fresh keys
and bootstrap sessions are mandatory; no resumable/importable endpoint exists.
The existing 8,192-byte body limit applies before reads/decoding, and there are
exactly four frames, not an unbounded RPC stream.

## Process and result lifetime

A third fixed packaged child profile uses the existing private pipes, isolated
interpreter, explicit handle inheritance and Windows Job Object. No public
executable/entry override was added. All profiles share the same admission slot;
uncertain process cleanup poisons it. Parent polling checks cancellation and a
finite deadline throughout I/O and after cleanup. A separate child watchdog
terminates the process after ten seconds even if the coordinator leaves the pipe
open without sending the final message. Native delete-on-close removes its owned
fixture when the process terminates. Scheduler/OS integrity remains trusted;
this is not a hard real-time guarantee or power-loss recovery promise.

The public diagnostic never exposes intermediate live metadata or invokes human
review callbacks. It immediately sends the selected terminal action. A result
requires the exact retirement acknowledgement, EOF, successful child exit,
successful cleanup and a final deadline/cancellation check. The result retains
immutable exact request and observation snapshots. An observed frame alone, a
valid final reply followed by a crash, extra output, or a final-cleanup
cancellation cannot produce a result. No retry or recreated session restores any
resource or decision.

The ten-second child bound is intentionally unsuitable for human review. This
milestone tests exchange/ownership retirement, not an interactive approval flow.
The in-memory registry's sixty-second maximum cannot extend this child deadline.
Cancellation is observed/serialized at defined checkpoints and cannot recall a
previously returned receipt. The trusted child and OS still substantiate native
metadata; authentication does not make a malicious child truthful.

## Evidence and next gate

Tests use real generated fixtures to show that a handle is live between rounds,
that both terminal actions delete it, that cancellation after observation kills
and cleans it, and that the independent watchdog destroys an idle live child.
Adversarial tests cover key/session/domain separation, transcript substitution,
wrong sequence types, exact request/observation binding, mutation, inherited API
bypass, replay, signed live/allow/data claims, output bounds, startup/final crashes,
hangs, final-cleanup cancellation and poisoned admission.

A separate [local pending-review prototype](broker-pending-review.md) now tests
registry/draft/resource freshness and one-use operator evidence. It is not wired
into this protocol and accepts no serialized live observation. Before human
review or acquisition across the channel, define authenticated operator input
and a trusted coordinator mapping for the exact live resource/effect.
Define atomic revocation/expiry/cancellation and one-use consumption at acquisition
and final delivery, plus a deliberate review-time child lifetime. Neither the
existing diagnostic action `verify` nor the decision-ID field can supply those
authority checks. Staged-buffer ownership and a controlled broker-read experiment
remain later gates; the existing narrow protected-reader claim is unchanged.
