# Inactive bounded-wait native fixture profile

This separate prerequisite retains the original generated-fixture handle during
a bounded wait, then permits one short private acquisition/retirement transcript.
It does not connect human review to acquisition. No existing source host, owner
walkthrough, protected reader, `/check` or v1 route imports or selects it. There
is no application delivery or authorization API.

## Fixed lifetimes and ownership

`_WaitAcquisitionPhases` captures one original worker and these absolute limits:

| Phase | Limit | What completing it means |
| --- | --- | --- |
| Waiting | 30 seconds from construction | The scheduling budget has not expired. |
| Acquisition and retirement | At most 5 seconds from the first transition, within the original 35-second total | Only that same scheduling attempt is still current. |
| Independent child watchdog | 40 seconds from child entry | A stuck or abandoned child is terminated. |

Phase checks, a deadline value or an authenticated frame are never human-review
evidence, permission, a grant extension or a verified cooperating-app identity.
The first acquisition attempt spends the transition even if its frame is bad.
There is no retry, renewal, heartbeat, caller clock or lifetime selector.

The exact `WaitNativeFixtureAdapter` accepts only trusted bootstrap key/session
bytes. It creates its own harmless fixture with a fresh fixed native lifetime;
it never extends an existing five-second resource. A small shared allocation
helper preserves the old native owner's five-second constructor and behavior.
The wait owner retains original Windows handle identity, metadata and API owners
separately from mutable fields. The displayed path is a label; the adapter never
reopens it or accepts a caller-selected path, handle, contents or executable.

The new opening and acquisition protocols have distinct authenticated domains
from each other and from the old metadata, desktop and publication profiles.
Opening obtains metadata without reading fixture contents. The acquisition codec
is constructed only for the one transition and retains its existing five-second
maximum, capped by the original phase deadline. Resource, application, proposal
and effect claims must match the original observation/request before the single
bounded read from that original handle. Logical recipient claims are wire-bound
and checked for the same application and fixed revision; independent recipient
ownership remains a future coordinator gate.

These signed claims are supplied by trusted test orchestration. This standalone
adapter cannot independently establish current registry authority or human
permission. It must remain unreachable from application inputs until a separate
coordinator deliberately enforces both. Retired evidence must never auto-answer
or populate the decision of a fresh existing `LiveBrokerReview`.

## Expiry, cancellation and disposal

Timers signal original cancellation state only. The fixed new child polls its
original nonblocking input descriptor and checks the phase around each bounded
read. Idle expiry therefore unwinds native cleanup on the original worker.
Bootstrap and protocol reads use the same raw descriptor, avoiding buffered
read-ahead ambiguity with pipelined input. Malformed lengths, truncated input,
extra input or a missing input half-close fail closed.

Thirty-five seconds bounds validity; it is not an unconditional physical cleanup
deadline for a blocked kernel operation. The independent watchdog covers stuck
I/O or cleanup. A future enclosing host must retain admission until original
process/handle cleanup is independently verified, and poison it on uncertainty.
Phase closure or a peer ACK alone cannot certify that cleanup.

Success requires native resource cleanup, exact authenticated retirement and the
original acknowledgment digest. Entry output waits for context cleanup and a
final original-archive/deadline check. Private staged bytes stay in the test
coordinator's quarantine and are discarded; no application bytes are released.
Mutation, copied owners, replay, cancellation, expired phases or uncertain
original disposal withhold retirement evidence. No timer, cleanup callback or
restored older state can renew the attempt.

## Verification and remaining composition gates

Tests use only newly generated fixtures and synthetic trusted coordination;
they are not an owner walkthrough or proof that an application cannot bypass a
broker. A genuine child test waits longer than the old five-second lifetime,
then stages one bounded read and discards it after verified retirement. Other
cases exercise expiry, cancellation, collisions, protocol separation, malformed
input, native ownership mutation, copied state, replay and failed cleanup.
Exact verified counts are recorded in [the development log](DEVELOPMENT_LOG.md).

The next composition must bind an exact observed-resource human display and
current registry/grant/draft/proposal state to these deliberately separate
lifetimes, while retaining original admission and native ownership through the
later peers. Neither old review evidence nor a matching displayed pathname can
substitute for that binding. The existing five-second source host and acquisition
contracts remain unchanged and reject the separate desktop review subclass.

Trusted cooperating-application association and actual payload publication,
including partial-write, crash, lost-receipt, revocation and restart outcomes,
remain later gates. The trusted bootstrap/coordinator, checkout/runtime, fixed
entries, native adapter and Windows remain trusted. There is no sandbox against
hostile trusted-process code, immutable-content guarantee, direct Windows access
prevention or durable/global exactly-once claim. The existing fixture protected
reader remains the only narrow protected-operation claim. SecurityBrightness
remains the authorization/human-control boundary, not an arbitrary executor or
antivirus.
