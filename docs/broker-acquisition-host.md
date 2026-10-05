# Inactive child-owned native acquisition and discard

`BrokerAcquisitionDiscardHost` is a separate diagnostic built on the existing
operator/worker ports. It owns the fixed `broker_acquisition_entry.py` child,
trusted startup, private bounded transport and the live acquisition lifecycle.
No existing desktop, protected-reader, `/check` or v1 route imports it. No owner
walkthrough or real cooperating application is connected to it.

The worker authenticates current application authority and an exact draft/proposal
before launch. A fresh bootstrap secret authenticates the child's startup PID and
transcript. The child creates only the built-in harmless 37-byte fixture and emits
original-handle-derived observation metadata. The separately distributed trusted
operator port receives the exact request/resource display. Application credentials
cannot submit an operator response. Scripted test responses are orchestration and
do not demonstrate a human interaction.

DENY kills and joins the child without reserving or acquiring data. ALLOW ONCE
evidence permits the coordinator to reserve and attempt one exact bounded staging
transition only while grant activation, application identity, proposal, draft
revision, decision and resource/effect binding remain current. The native adapter
checks its original observation and retained handle before and after reading.
The child does not look up current registry authority or authenticate a human;
the trusted coordinator supplies those checks. Neither review nor a signed
request is permission outside this live composition.

Registry revocation after a signed request is sent can race the child's private
native acquisition: the child has no registry authority lease. The coordinator
rejects stale authority before accepting staged data and again at retirement and
the final check. This diagnostic guarantees zero application delivery; it does
not claim that revocation prevents every private native read already in flight.

The authenticated staging frame carries only the fixed fixture's bytes to the
coordinator's private quarantine. Public results expose count/digest and exact
display metadata, never data. Discard clears the owned quarantine before sending
the retirement command. The child revalidates and closes native ownership, checks
cleanup again after its context exits, and emits only a zero-byte discard ack.
The host withholds that ack until exact EOF, zero exit and successful job/process
cleanup. It then confirms retirement and performs the separate final publication
check in discard-only mode. No release API or later-operation token is created.

All cleanup and shared-admission release precede an additional final fence under
the cancellation, lifecycle, registry and draft locks. It checks original
authority, proposal/draft version, review-ticket and display snapshots, the exact
decision, absence of superseding review evidence, reservation/retirement binding
and the original deadlines. Expiry, cancellation or state changes during cleanup
withhold even the diagnostic metadata. Cleanup uncertainty poisons admission and
still reports finished/failed cleanup status; no retry or fallback read exists.

The total host/review/acquisition budget is at most five seconds. This is an
automated prerequisite diagnostic, not a usable human-wait interface. The fixed
child also has an independent ten-second watchdog. Native launch uses the existing
isolated Python startup, fixed entry/cwd, minimal environment, private inherited
pipe handles, hidden window and atomic single-process job with kill-on-close and
CPU/memory limits. Parent cancellation can kill and join a child blocked in a
synchronous native call. Successful completion requires confirmed cleanup.

The coordinator, operator bootstrap, registry/ledger, launcher, Python/OS runtime
and fixed child adapter remain trusted. Moving acquisition to the child separates
native handle and read ownership from the host, and makes interruption possible.
The same-user child is not a restricted-token sandbox or protection against
hostile code inside either trusted process. HMAC authenticates private pipe data;
it does not encrypt it. Buffer clearing does not promise secure erasure of Python
or transport copies. A path is a display label, not resource identity.

This milestone proves generated-fixture acquisition, quarantine and discard through
a controlled private process composition, with zero application bytes released.
It adds no new delivery/enforcement claim. The existing verified protected-reader
claim remains limited to its own fixture path; direct Windows access and immutable
file contents remain outside it.

The 59 host/child tests cover actual native staging/discard, no reservation on
DENY, missing authority or review, exact display/response ownership, replay,
concurrent workers, malformed/startup/native failures, child crashes before and
after buffering, cancellation during a blocked native acquisition, trailing or
nonzero/hung final output, cleanup uncertainty, and registry/draft/proposal/review
mutation at staging, cleanup and final-return boundaries. They verify fixture
deletion, cleared quarantine, joined shutdown and zero-byte public results.

## Gate before a controlled publication experiment

The next stage must deliberately retain quarantine for one final publication,
instead of unconditional discard, without turning retired evidence into a token.
It needs an exact recipient/delivery contract, one terminal consumption attempt,
current grant and exact fresh human control, observed-resource/effect binding,
serialized final revocation/cancellation/expiry checks at the delivery boundary,
and confirmed child/native cleanup. Any failure must dispose of quarantine and
release zero bytes. It must test registry or draft changes and cancellation at
every acquisition, cleanup and publication boundary, duplicate deliveries and
recipient/request/resource substitution.

Only a separate generated-fixture experiment should exercise that contract first.
It must visibly demonstrate DENY yields zero bytes, ALLOW ONCE yields one bounded
delivery, and replay/stale/revoked/expired/changed approvals yield zero. Joining
the owner UI requires a deliberately tested human-wait lifetime; the five-second
diagnostic must not be extended by editing a deadline. A real cooperating
application requires a separately defined adapter/recipient trust boundary.

The separate [inactive final publication draft](broker-final-publication-draft.md)
now tests logical recipient binding and retained quarantine through synthetic peer
retirement, followed by a one-use dry-run final check that still discards all
bytes. This host and its fixed child remain unchanged. Actual native/process
retirement for that new profile, a real recipient channel and delivery remain
separate gates.
