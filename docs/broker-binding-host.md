# Inactive process-owned native-binding host

`BrokerBindingHost` in `core/broker_binding_host.py` owns the fixed metadata-only
binding child. It is separate from the verified desktop host and is not selected
by any desktop, `/check`, v1 or protected-reader route. No content read or delivery
command exists. Generated fixtures are the only resources involved.

Trusted local bootstrap distributes separate worker and operator ports. The
operator can inspect the exact pending display, queue an exact ALLOW ONCE or
DENY response, cancel, and inspect shutdown status. The worker alone owns process
launch, pipe operations, review/reservation state and cleanup. Port possession
remains the accepted trusted-local operator assumption, not independent person
authentication or isolation from hostile code in the trusted process.

The host reuses existing operator-queue controls without changing the existing
host. Its total diagnostic lifetime is at most five seconds, including startup,
operator wait, native retirement and cleanup. This deliberately short profile
is not a new owner walkthrough; tests script responses without claiming human
verification. Neither messages nor review responses extend the deadline.

DENY creates no reservation: the worker kills and joins the child, then retires
review state. ALLOW ONCE reserves the exact live review, exchanges the bound
native metadata, rechecks current review/authority, and requests retirement.
The acknowledgement stays private until exact EOF, zero child exit and confirmed
native cleanup. Only then does the worker validate the acknowledgement and
consume current coordinator evidence. Both outcomes return retired metadata only.

After all cleanup, the host checks cancellation, deadline, current registry lease,
application state, draft/version, proposal, display and reservation snapshot again
under their locks. A child acknowledgement or earlier successful check cannot
substitute for that final validation. The result is not authority for a later
operation; the resource has already been retired.

All profiles share the existing single-child admission slot. Cleanup uncertainty
withholds the result, reports unconfirmed cleanup and poisons admission. Closing
the host signals cancellation; its caller must join the worker. Shutdown status
is unavailable until cleanup completes and never implies permission. A duplicate
worker attempt cancels the original rather than opening another child.

The 32 focused tests cover real allow/deny retirement and deletion, no reservation
on denial, cancellation/expiry, invalid/copy/mutated responses, stale registry and
draft evidence, replay, concurrent worker attempts, admission, launch/cleanup
failure, post-cleanup revocation/expiry/cancellation, registry lookup failure,
and valid acknowledgements followed by trailing output, nonzero exit or a hang.

The next gate is the explicit transition from retirement-only metadata to a live
one-use acquisition lifecycle. Retired receipts must never be repurposed as read
tokens. That design still needs native resource retention through the operation,
bounded quarantine, current-authority/revocation checks and a separate final
publication decision before a new controlled broker-backed read experiment.
The original fixture-only protected-reader claim remains unchanged.
