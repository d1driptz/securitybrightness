# Process-owned fixture review desktop demonstration

This is a separate, opt-in metadata-only demonstration. It starts a private
child that creates one harmless generated fixture; it accepts no personal file,
path or other command-line arguments. No protected content is read or delivered,
even after ALLOW ONCE. No HTTP service or active authorization endpoint starts.

From PowerShell:

```powershell
Set-Location -LiteralPath 'C:\Users\manue\.codex\.chatgpt-projects\g-p-6ab571deb5848191860fb7718942556e\securitybrightness-work'
python -m core.broker_host_desktop
```

The window shows the application, exact proposal/effects and the child's observed
resource identity in escaped, read-only JSON. Paths remain display labels. The
total session limit is 30 seconds, including startup, decision and cleanup; no
activity extends it. This is trusted local operator bootstrap, not independent
human authentication or protection against hostile same-user UI automation.

## Owner steps

Run a fresh session for each case:

1. Type exactly `ALLOW ONCE`, then click **Record ALLOW ONCE evidence**. Enter by
   itself does not approve. First expect “Response queued”; only after freshness
   checks, child retirement, clean exit and cleanup expect “Review evidence
   retired: allow_once. Worker joined; child cleanup confirmed.” The window also
   states that no operation was authorized and zero protected bytes were released.
2. Click **DENY**. Expect retired deny evidence, joined worker and confirmed child
   cleanup, with zero protected bytes released.
3. Click **Cancel session**. The window remains visible while cleanup runs, then
   reports rejection/cancellation and confirms cleanup only after the worker stops
   and its thread is joined. No successful review is reported.
4. Make no decision for the fixed deadline. Expect “Review cancelled, expired or
   rejected”, joined worker and confirmed cleanup, with zero protected bytes.
5. Close the window while awaiting a decision. It first requests cancellation and
   remains alive until the worker is finished and joined, then closes. PowerShell
   returns only after the bootstrap's final worker join as well.

If cleanup cannot be confirmed, the window explicitly says so and remains visible
instead of automatically closing or reporting success. A subsequent close can
dismiss that completed failure report. Worker completion by itself is not treated
as proof of successful cleanup. There is no fallback file read.

These cases have automated real-widget/private-child coverage. On 2026-10-04 the
owner reported verifying the expired/cancelled path with zero protected bytes,
and ALLOW ONCE with retired evidence, joined worker, confirmed child cleanup,
no operation authorized and zero protected bytes. This confirms those manual
metadata-only paths, not permission for broker acquisition or delivery. The earlier
`core.broker_review_desktop` evidence-only window and `core.controlled_read_demo`
protected-reader walkthrough remain unchanged and separate.

## Architecture and remaining gates

The UI receives only the operator port, completion future and worker-pool owner.
Credentials, registry and draft setup stay in the trusted generated-fixture
bootstrap. Responses disable the controls immediately; a successful receipt must
match both the displayed snapshot and the queued decision. The worker pool is
joined before any completed status, and failures cannot become allow evidence.
UI construction or event-loop failure also cancels and joins in bootstrap cleanup.

The host exposes a frozen shutdown-status snapshot only after its cleanup path
finishes. This reports process cleanup, not permission, resource truth, immutable
contents or continuing authority. Pre-admission cancellation confirms that no
process existed; uncertain native cleanup remains explicitly unconfirmed.

No broker reads or delivery are active. `/check`, v1 and the existing protected
reader are unchanged. Before the first broker-backed read experiment, design and
test a distinct one-use acquisition/delivery protocol: current authority and human
control, exact retained resource/effect binding, revocation/expiry/cancellation,
bounded buffered data and a final publication check that prevents bytes after
DENY or failed validation. Do not turn a metadata receipt into permission or add
an arbitrary path/read request to this demonstration.
