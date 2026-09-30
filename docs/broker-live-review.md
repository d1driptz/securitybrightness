# Inactive authenticated live-observation review mapping

`core/broker_live_review.py` binds one authenticated four-frame metadata session
to one current registry grant, draft revision, proposal, decision identity,
resource observation and exact operator display. It has no content-read,
delivery, service or desktop integration. `/check`, v1, the protected reader and
the existing child diagnostic are unchanged.

The trusted bootstrap creates a fresh key/session and distributes the coordinator
and operator ports separately. `begin` authenticates the application and captures
its current activation lease and full grant snapshot. Only the transcript-bound
authenticated observation frame can establish the review facts. Caller-supplied
dicts, retired receipts, wrong keys, different request transcripts, duplicate
observations and decision/resource identifier collisions are rejected terminally.
Requester file references and displayed paths never become resource identity.

The operator receives an exact issued display. Only exact `ALLOW ONCE` or `DENY`
records evidence. Copies, mutation, repeat display/answer and replay close the
mapping. This is trusted-local operator-port possession under decision 0001 A,
not independent human authentication. The MAC authenticates key possession; it
does not establish that an arbitrary peer tells the truth about a resource.

After an answer, `finish` emits only metadata `verify` or `cancel`. The existing
trusted child verifies its retained synthetic resource and closes ownership before
returning a signed retired-denial acknowledgement. `retire` checks current
authority again and returns immutable **retired metadata**, with no data field or
permission semantics. No ticket can authorize a downstream operation. Recording
an answer alone neither proves the child remains alive nor that the observation
is still current; final verification and the retirement exchange are required.

## Explicit lifetime and host obligations

The absolute mapping deadline is at most five seconds from `begin`, including
observation, review and retirement. No refresh, redisplay, resume or retry extends
it. A timer discards idle mapping state. This is an automated diagnostic budget,
deliberately shorter than the existing child's ten-second watchdog. **It is not
a usable human-review deadline and is not connected to the desktop.** Neither
existing timeout is increased by this milestone.

This mapping is a state/protocol primitive, not a process owner. Its `close` does
not kill a child. A future host must own the admission slot, trusted native launch,
readiness/PID handshake, nonblocking bounded I/O, cancellation, EOF, successful
exit and cleanup. It must terminate the child on any mapping failure, withhold
results until all transport checks pass, and never substitute a receipt for a
live observation. The existing diagnostic transport already tests these transport
properties but is not silently repurposed as this new host.

All transition checks fail closed on expiry, registry/grant/activation changes,
draft changes, current-object mutation and validation failures. No registry lock
is held across an operator wait. Final retirement serializes current checks with
registry/draft changes; same-thread changes during evidence cleanup are checked
again. Retired evidence does not promise freshness after return.

## Verification and next gate

Adversarial tests exercise fabricated/spliced/replayed frames, exact display and
proposal mutation, ownership, identifier collisions, scope removal, rotation,
revocation, persistent lock/re-unlock, corrupt/unavailable checks, draft changes,
expiry, cancellation, concurrent finish, cleanup failure and unsupported data or
allow acknowledgements. A real fixed Windows child integration test authenticates
startup, maps its generated fixture, supplies a scripted operator response,
verifies retirement, checks EOF/exit and fixture deletion. It performs no content
read and is not a human demonstration.

Next: build a dedicated process-owning review-session host with a deliberate
human-wait child profile, bounded cancellation and crash cleanup. Do not import
retired observations into it or merely lengthen the diagnostic watchdog. Before
any read/delivery activation, separately establish current grant/human-control,
exact operation/resource/effect, expiry/revocation, one-use and final publication
checks. A broker is not hostile-same-user isolation or a general executor.
