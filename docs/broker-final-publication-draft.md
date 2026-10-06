# Inactive retained quarantine and recipient-bound final check

The separate publication draft adds an I/O-free prerequisite for eventual final
delivery. No existing child, host, desktop, protected-reader, `/check` or v1 route
imports it. It accepts authenticated synthetic staging frames only. It performs
no file operations, starts no process and delivers no application bytes.

`LogicalPublicationRecipient` is created and distributed by trusted local
bootstrap separately from requester proposals. It owns a generated session and
nonce, an exact issued descriptor, one claim and an irreversible terminal state.
Its fixed version and lifetime of at most five seconds cannot be renewed, rotated
or restored. The descriptor is logical binding evidence: it does not establish
OS peer identity, a person, a process, a PID, a path or a delivery channel. Neither
constructing an owner nor knowing its descriptor grants authority.

`PublicationCheckExchange` uses a distinct authenticated domain and strict wrapper
containing the existing bounded action context and a separate recipient descriptor.
Application/session/recipient/version are bound into every staged, retirement and
acknowledgement digest. Requester authority fields, addresses, paths, unknown fields
and colliding identities are rejected. Existing discard-profile frames cannot be
spliced into this transcript. HMAC proves trusted peer key possession, not resource
truth, permission, human identity or cleanup success.

The new transcript retains the original private coordinator bytearray across
adapter retirement and acknowledgement. Exact typed context/phase snapshots,
original buffer identity, size and digest are checked at each transition. Peer
retirement is only an authenticated cleanup claim. It cannot prove native handle
closure, process exit, EOF, joined cleanup or current registry authority. The
retention timer remains active after acknowledgement and key closure. Expiry,
close, rejection or unsupported release/discard commands wipe retained bytes.
No method returns data or a publication token. Wiping does not promise secure
erasure of immutable Python or transport copies, or hostile-process isolation.

`LivePublicationDraft` composes an exact live acquisition owner with the trusted
logical recipient owner. Reservation requires current authenticated application
scope/grant activation, exact fresh ALLOW ONCE evidence, proposal/draft/revision,
display and resource/effect binding. It claims the recipient once and snapshots
the complete action/recipient envelope before acquisition. The first acquisition
attempt is terminal even when credentials or the reservation are invalid.

Staging and adapter retirement keep source review live, quarantine private and
all original deadlines unchanged. Application authority alone cannot reserve;
review evidence alone cannot bypass revoked or changed authority. Old receipts,
copied descriptors, another recipient owner or requester data cannot create,
transfer, restore, extend or broaden the live claim.

The coordinator performs a separate final attempt only after authenticated peer
retirement. It reauthenticates the exact application/proposal, validates the exact
issued recipient descriptor, current authority/freshness and retained quarantine.
The first attempt is spent before validating even bad final inputs. This remains
a dry run: it clears quarantine and irreversibly retires source and recipient.
After all cleanup it rechecks registry/draft/review/proposal/decision/recipient,
exact issued reservation/staging/retirement identities, complete binding digest,
absence of superseding reviews, cancellation, cleanup state and every deadline.
Reentrant cancellation and cleanup faults withhold the result. Successful output
is count/digest metadata with `eligible_discarded` and zero released bytes; it is
never authority for a later operation.

Lock order is lifecycle, recipient, acquisition, review, registry, ledger, wire.
Recipient close takes only its own lock and calls no coordinator. Registry locks
are not held across external waits. Cancellation/revocation serialize at the
final dry-run boundary; a concurrent change after that boundary cannot turn the
returned retired metadata into permission.

The 124 adversarial tests comprise 33 wire, 14 recipient-owner and 77 lifecycle
tests. They cover exact binding and domain separation, malformed/oversized or
injected fields, version/type confusion, ID collisions, copied or substituted
owners/tokens/receipts, replay/concurrent attempts, buffer mutation/replacement,
retention after acknowledgement, expiry and deadline extension, registry rotation
or regrant, lock/re-unlock, stale/superseded reviews, revocation between transitions,
recipient cancellation and faults or mutation during final cleanup. Every final
check and every rejected path disposes of quarantine and yields no application
bytes. Synthetic peer frames and scripted operator decisions are automated test
orchestration, not a new owner demonstration or real adapter cleanup proof.

## Remaining gates before delivery

This I/O-free draft tests live acquisition and retained quarantine against
synthetic adapter claims. The separate [inactive native/process composition](broker-publication-process.md)
now binds this recipient envelope and tests actual fixed-fixture acquisition,
retained quarantine through native retirement, exact EOF, zero exit and joined
child cleanup before the final dry-run check. Signed acknowledgements cannot
replace those checks. The earlier discard host remains unchanged.

A trusted recipient must then be bound to one real cooperating channel, rather
than treating a logical nonce, application name, PID or path as channel identity.
The actual publication boundary needs a fixed bounded delivery operation and an
explicit linearization point under current grant/review/recipient/cancellation
checks. It must consume once, wipe on failure, reject replay/recipient substitution,
and demonstrate zero bytes for DENY/stale/revoked/expired/changed requests through
the protected generated-fixture path. Joining the human UI also needs deliberate
tested wait-lifetime alignment; the five-second diagnostic must not be extended
by mutating a deadline. No delivery experiment or broader protection is claimed
by these inactive primitives.

No real recipient channel or application delivery has been activated.
