# Inactive fixed-peer recipient channel witness

`RecipientChannelProbe` tests a private channel to one fixed cooperating test
peer. It has no file selector, content acquisition, arbitrary launcher, external
endpoint, byte buffer or delivery API. It is separate from the verified fixture
reader and every desktop/owner walkthrough, `/check` and v1 route. Successful
results are retired metadata with zero protected bytes released; they cannot
authorize or restore a later channel or operation.

## Trusted observations and ownership

Trusted local bootstrap supplies exact live acquisition/review and logical
recipient owners separately from requester proposal data. Reservation requires
fresh ALLOW ONCE review evidence and current application/grant/draft/proposal
authority; it binds the complete resource/effect/review context and exact issued
recipient descriptor. Application authority alone cannot reserve. Review evidence
cannot survive changed or revoked authority. The first run attempt is spent
before validating even a copied token, invalid credential or changed proposal.

The separate `_RecipientWitnessChild` launches only `broker_recipient_entry.py`
through the existing fixed interpreter, isolated startup, minimal environment,
private inherited stdio, hidden process and atomic bounded job contract. No PID,
handle, pipe, nonce, executable, callback or observed identity is caller supplied.
The coordinator assigns this fixed test peer to the authenticated registry
application; this is not installed application code attestation.

The parent queries `GetProcessId` and `GetProcessTimes` on its original created
process handle. It never opens a process by a reported PID. Creation time is
checked with the retained handle and process liveness, not treated as a standalone
credential. The frozen typed observation is an exact issued local object; copied,
fabricated, mutated or dictionary observations cannot be adopted as trusted.
[Microsoft documents the handle-based process timing query](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
and [the lifetime limits of process IDs](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers).

Numeric descriptor or handle equality is insufficient. The parent retains two
private noninheritable `DuplicateHandle` references for each original pipe,
process and job object. `CompareObjectHandles` checks the underlying kernel
objects; pipe type, noninheritance, nonblocking mode, process/job membership and
exact original fields are also checked around observations and I/O. This detects
same-number descriptor reuse as well as substitution of a mutable field.
[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
and [CompareObjectHandles](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles)
are the applicable documented APIs; comparison is loaded from KernelBase.dll.
Missing native support fails closed. No named endpoint or peer-PID lookup fallback
is used.

## Bounded transcript and terminal cleanup

A distinct strict MAC domain carries only the full binding, witness digest and
one-use retirement messages. Key possession authenticates that transcript, not
human control, native identity or authority. Typed phases, the previous frame
digest, original key/session/role snapshots, exact recipient revision and bounded
canonical schema reject malformed, oversized, injected, cross-domain, substituted
or replayed input. No data, read or publication message exists.

Current registry/review/proposal/version/resource/effect and recipient ownership
are checked before and after external phases without holding registry locks
during I/O waits. The peer requires exact input EOF before returning its terminal
acknowledgement. Both private input references close with the original stdin
descriptor, so comparison ownership cannot prevent EOF. ACK remains private until
exact output EOF, zero exit and joined native process/job cleanup. No signed claim
substitutes for those observations.

Cleanup uses the original retained ownership. Substituted foreign descriptors,
processes or jobs are preserved, while matching original references permit
termination/join and disposal of the original child. Any ownership mismatch or
native uncertainty permanently rejects completion and poisons admission. Partial
startup cleanup and native callbacks that change ownership during cleanup are
tested. An uncertain close never reports confirmed cleanup.

The final metadata return occurs under the original owner locks and current
registry lease. It checks all cleanup tombstones, exact token/display/review/
recipient/native observation/proof/ACK snapshots, closed codec state and original
transcript, original deadlines, cancellation, zero-byte result fields and current
authority again after result validation. Cleanup-time state changes, superseding
review evidence, restored state or retired receipt replay cannot create a new
channel or preserve successful evidence.

The protocol/review budget is at most five seconds and cannot be extended by
mutating deadlines. Cancellation is terminal even if the event is cleared or
replaced. It requests worker shutdown; callers must join the worker before
accepting cleanup status. Native cleanup has a separate bounded one-second join;
the budget is enforced at polling points, not a hard wall-time guarantee for
synchronous OS calls. The child independently exits after ten seconds if
abandoned, including while waiting for bootstrap. These diagnostic lifetimes
are not a desktop human-wait policy.

## Evidence and remaining gates

Automated tests exercise a real fixed Windows child and real descriptor/handle
ownership. Scripted ALLOW/DENY records and synthetic resource observations in
source-model tests are test orchestration, not a human walkthrough or new native
file-resource proof. This profile never acquires or releases protected contents.

The 174 new adversarial tests comprise 35 strict protocol, 42 native ownership
and 97 channel lifecycle tests. They cover fabricated or substituted observations,
same-number descriptor reuse, original handle/process creation-time binding,
foreign ownership preservation, partial startup and native failures, missing
authority/human control, exact context and recipient ownership, one-use attempts,
replay and concurrent workers, revocation/rotation/stale drafts, malformed or
injected fields, crashes and trailing/nonzero/hung output, cancellation/expiry,
independent watchdog termination, cleanup uncertainty, cleared/replaced events,
timer faults and mutation during proof, cleanup and final metadata return.

The trusted coordinator/bootstrap, operator port distribution, registry/ledger,
runtime/OS, development checkout and fixed peer remain trusted. The same-account
child is not an OS security sandbox. Private MACs do not encrypt messages or prove
installed code identity; these checks do not resist hostile code inside either
trusted process or grant global Windows access protection.

The separate [inactive live-channel check](broker-live-channel-check.md) now keeps
the original peer live and owned across retained fixture quarantine and a final
discard-only check, under the same current authority/review/resource/effect.
This probe still deliberately retires its own channel and review: its result
cannot bridge that gap. Actual publication needs an explicit revocation/cancellation
linearization point, one bounded delivery, and a generated-fixture experiment
showing zero bytes for every denied, stale, expired, revoked, replayed or changed
request. The existing human-wait lifecycle needs deliberate alignment as well.
Integrating a real cooperating application also requires a trusted onboarding/
launch association rather than trusting an application name or self-reported PID.
No new protection or active authorization claim is made by this gate.
