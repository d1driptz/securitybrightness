# Inactive process-owned metadata review host

`BrokerReviewHost` adds a process-owning host around the authenticated live review
mapping. It has no desktop or HTTP endpoint, no caller-selected file/executable,
and no content-read or delivery API. Existing `/check`, v1, protected-reader and
owner-demo behavior remain unchanged. This stage is exercised by automated tests;
it is not a new completed human demonstration.

Trusted bootstrap constructs the host with the registry and draft ledger, then
distributes `worker` and `operator` ports separately. One worker calls `run` with
authenticated application intent and a current draft. The operator can inspect
one pending display, queue exact `ALLOW ONCE` or `DENY`, or cancel. A queued answer
is not success or permission. The worker revalidates it against current registry,
grant activation, draft, proposal and exact authenticated resource observation.
The operator port exposes no application credential or launch controls.

## Explicit lifetime profile

- Host: fixed total budget of at most **30 seconds**, including startup, operator
  wait, metadata verification/retirement, EOF, exit and cleanup. Shorter budgets
  are supported; no heartbeat, renewal, retry or session restoration is supported.
- New fixed child: independent **35-second wall watchdog** from entry startup,
  retaining only its one generated fixture. Resource ownership still has its
  existing 60-second ceiling. These are scheduling bounds, not hard real-time
  guarantees.
- Existing five-second mapping and ten-second diagnostic child remain unchanged.
  The new profile uses a separate authenticated MAC domain, so old diagnostic
  frames cannot silently enter the longer review profile.

The new child uses the same trusted isolated Python launch, fixed entry path,
private inherited pipe handles, PID/session readiness proof and native Job Object
restrictions. No requester can select the command, environment, resource or key.
The child cannot create descendant processes under the existing job policy; it
still runs with the account's privileges, not a reduced security token.

## Completion, cancellation and failure

The worker owns all process I/O and cleanup. Operator cancellation sets a signal
and wakes the worker. The worker checks cancellation/deadline while reading,
writing, waiting for an answer and awaiting exit, then kills/reaps the child on
failure. **`close()` signals cancellation; the caller must join its worker to
confirm cleanup.** The independent child watchdog remains the fallback if the
host stops progressing. Native delete-on-close owns fixture removal on crash.

A valid response is insufficient: after the operator answer, the child must
verify/cancel and retire its fixture, send the exact authenticated retired-denial
acknowledgement, reach EOF without extra output and exit successfully. The host
must complete cleanup before the mapping accepts retirement and rechecks current
authority. A final cancellation/deadline fence precedes publication. Only then
can the worker return retired review metadata. The receipt has no data field,
cannot be treated as a boolean and never authorizes a downstream operation.

The shared one-child admission slot remains occupied throughout review. Cleanup
uncertainty poisons admission in this host process; no permissive recovery or
fallback read occurs. Bad startup, malformed/truncated output, crashes, hangs,
extra output, duplicate worker/answers, display mutation, stale state, expiry and
cancellation cannot produce a successful receipt. A pending display is historical
review evidence, not a guarantee the child is currently alive; completion must
pass all final checks.

## Trust boundary and next gate

This remains trusted-local operator bootstrap (decision 0001 A). The coordinator,
registry/ledger, packaged child, interpreter and eventual operator UI are trusted.
Private pipes and a MAC do not independently authenticate a human or isolate
hostile code already in the trusted process. This does not prevent direct Windows
file access or establish immutable file contents. Paths remain display text; the
trusted child reports the OS-derived identity of its retained generated fixture.

The separate fixture-only desktop adapter is described in
[broker-host-desktop.md](broker-host-desktop.md), including visible rejection,
cancellation and cleanup states and joined worker shutdown. The host's operator
port exposes a frozen cleanup-status snapshot only after cleanup finishes; it
never grants permission. The old evidence-only window remains separate. Before
later acquisition/delivery activation,
test exact current authority/human control, resource/effect binding, revocation,
expiry, one-use consumption and the final protected publication boundary.
