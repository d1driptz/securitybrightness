# Inactive two-worker source rendezvous

`SourceAssociationRendezvousDryRun` coordinates two fixed Python workers and
their two genuine Windows metadata peers. It is not selected by a host, owner
walkthrough, protected reader, `/check` or v1 route. It accepts no payload,
pathname, executable, endpoint or requester-supplied process observation. Its
only possible result is the existing zero-byte historical association fact;
that fact is never permission.

Trusted bootstrap supplies an exact, already-cleaned `LivePublicationDraft`.
The coordinator creates an exact original `LiveChannelPublicationCheck` and a
separate fixed resumable worker. The worker establishes the original native
witness and pauses outside source, registry, review and native ownership locks.
It does not call or replace the existing helper's `run` method. A second fixed
worker creates an exact original commit and performs the original-source/native
association. The original nested source/channel envelope remains unchanged;
the second observed native channel is separate.

Current original application authority, exact source/proposal/resource/effect
binding and separate required human control remain necessary at consume/discard.
The association consumes the original source once, discards its retained buffer,
and retires its new peer. The coordinator resumes the first worker only for
disposal; it cannot authorize a second operation or deliver data. A normally
resumed witness must still be the original live process. Its subsequent forced
termination is cleanup, not a successful protocol retirement receipt.

## Admission, cancellation and retirement

The existing shared one-slot admission is acquired before either new worker
starts. The coordinator captures its original semaphore, condition, primitive
lock and notification method. Admission uses a nonblocking attempt on that
original condition lock, avoiding the blocking condition acquisition inside a
normal semaphore call. There is no new private admission pool or reset API.

Cancellation signals captured original coordinator/association events before
attempting contended guards. The association is joined before the parked witness
is released into disposal, avoiding cleanup racing the association's use of the
source. Original expiry still applies. Only the owning worker closes its native child. Transport waits, native
I/O and thread joins occur outside source/authority locks. Internal control
handoffs are bounded and do not extend the original at-most-five-second deadline.
Source and native ownership guards remain nonblocking. Cleanup joins have a
separate bounded budget; they cannot renew authority.

If the witness itself detects mutation while the association is using its
source, it first signals the captured helper's cancellation. Disposal may retry
captured guard acquisition only after all other guards unwind and within a fixed
cleanup allowance. This removes usability and lets the association stop; it
never retries active validation or erases the original mutation failure. Cleanup
uncertainty still poisons admission even if best-effort disposal subsequently
closes the review.

Admission remains held until both original threads have joined and original
native handles/jobs/descriptors, codecs, keys and retained buffer have
independently verified terminal state, and original timer cancellation signals
are set. The timer threads themselves are not claimed joined. A worker result, joined flag or cleanup
boolean alone is insufficient. Immutable original archives retain native
ownership, session/transcript identity and proof facts after disposal. Missing
archives, restored keys, foreign timer signals or substituted owners cannot
stand in for cleanup. The buffer is independently wiped even when contention
prevents complete disposal; this is not a secure-erasure guarantee for interpreter
or kernel copies.

Cleanup and current authority are separate checks. After both joins, final
validation rechecks the original registry/review/lifecycle bindings without
reopening a closed source or pretending its old native channel is still live.
Confirmed cleanup can release admission after an authority rejection, but it
cannot publish a success fact. Uncertain cleanup irreversibly retains/poisons
the captured admission slot. No timer, retry, fresh wrapper or restored alias
releases it.

The condition lock remains held through terminal sealing, notification and the
post-notification validation. A late failure inside this boundary rolls the slot
back to held before another admission can proceed. The exact sealed history and
typed terminal facts are checked again before return. Corruption after a genuine
release withholds evidence; it cannot safely reclaim a slot that may now belong
to another owner. These mutation checks do not claim protection against hostile
code rewriting the trusted Python runtime.

## Scope and remaining gates

Tests use synthetic resource observations, operator decisions and commit/model
readiness with two genuine fixed Windows children. They are automated security
orchestration, not a completed human walkthrough or installed-application
identity proof. The supplied source was already acquired and cleaned before this
coordinator starts: its earlier acquisition is **not** covered by this new
admission lifetime. No existing protected-reader or service behavior changes.

The 92 added adversarial tests cover separate authority/review requirements,
exact application/proposal/effect/recipient binding, registry and draft changes
at handoff/proof/acknowledgement/final sealing, cancellation, duplicate/replayed
attempts, expiry and peer crashes, malformed inputs, foreign owners/locks/events,
native/codec/proof/history mutation and cleanup uncertainty. The focused suite
passed in 73.614 seconds with no skips. Test orchestration and workspace-only
temporary-directory ACL support are not shipped.

The complete workspace suite passed **2,407 Python tests** in 563.853 seconds
and all **8 scanner tests** in 946.7404 ms, with no skips. Runtime
`security_events.json` is excluded from the milestone commit.

The next composition must retain one controlled admission across the entire
generated-fixture acquisition and review lifecycle, including a deliberate
bounded human-wait profile. Trusted cooperating-application association and
exact original-source/native-recipient payload publication remain separate gates.
The irreversible publication boundary needs explicit partial-write, crash,
lost-receipt, expiry and revocation semantics; no retry may duplicate a possibly
observable delivery. Only a later controlled fixture experiment can establish
that boundary. Historical discard facts cannot activate it.

An inactive [logical-source custody prerequisite](broker-source-admission.md)
now retains that same slot across synthetic source/review/acquisition and a
private retained-admission profile of this rendezvous. Its absolute deadline
cap can only shorten the original lifetime; standalone admission is unchanged.
The original native fixture child and human-wait composition remain unresolved.
Forced cancellation cleanup accepts the original typed `(exit, input_closed)`
snapshot with all original handles closed. Successful association still
separately requires input retirement and zero exit.

The existing fixture protected-reader path remains the narrow enforcement claim.
This primitive proves neither payload delivery, immutable contents, durable/global
at-most-once behavior, installed application identity nor prevention of direct
Windows access. Application/AI intent does not equal human permission.
SecurityBrightness remains the authorization/human-control boundary, not an
arbitrary executor or antivirus.
