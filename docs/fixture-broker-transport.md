# Inactive private broker transport

The broker remains disconnected from the protected fixture reader, owner demo,
`/check` and v1. `core.broker_transport.probe` accepts one exact bounded binding
and returns authenticated **denial evidence only**. It rejects even correctly
signed buffered data. No file is acquired or read; no decision becomes authority.

## Trusted startup and bounded lifetime

The coordinator launches only the packaged `broker_child_entry.py` with its
current Python interpreter, isolated mode (`-I`) and no site initialization
(`-S`). It supplies only SystemRoot/WINDIR environment entries, an explicit
three-handle inheritance list, private anonymous stdin/stdout pipes and NUL
stderr. There is no requester-supplied executable, command, environment, path,
launch mode, key or session parameter. Packaged code, interpreter, installation
path and coordinator integrity are trusted prerequisites; this is not executable
attestation or protection against hostile code in the coordinator/account.

Each call generates a fresh 32-byte key and session. They travel only through
the private input pipe. A fixed-size readiness MAC binds the actual child PID
and session before the coordinator sends the request. This proves key possession
on that channel, not approval, application authentication or resource truth.
The child requires one bounded frame followed by EOF and always denies.

The Windows launcher uses an explicit handle list and atomic job assignment via
`PROC_THREAD_ATTRIBUTE_JOB_LIST`; unsupported startup fails without a fallback.
These process-creation attributes are documented by
[Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
The unnamed, noninherited Job Object has kill-on-close, one-process, 256 MiB
process-memory and ten CPU-second limits. Windows terminates its members when
the last job handle closes with kill-on-close enabled; see
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
A test kills the coordinator while its child waits for bootstrap and observes
that child's process handle become signaled. Another tests denial of child
process creation inside the one-process job.

The parent admits only one exchange at a time, with no queue/retry. Pipe I/O is
nonblocking; fixed readiness and four-byte frame headers bound buffering before
body reads (8,192-byte body plus 32-byte MAC). Cancellation and a finite wall
deadline (default five seconds, maximum ten) are checked throughout polling and
again after cleanup. Native process creation/cleanup calls are synchronous;
this is not a hard real-time cancellation guarantee. Cleanup has a bounded
one-second process wait. A valid reply alone is insufficient: EOF, successful
child exit, exact codec binding, denial-only result and successful cleanup are
required. Partial, extra, oversized, unauthenticated or crashed output fails.
Cleanup uncertainty poisons the admission slot until coordinator restart.

## Adversarial evidence and limits

Tests exercise fresh sessions, wrong readiness PID/session/key, truncated and
flooded output, tampered MACs, repeated frames, signed data delivery attempts,
startup crashes, post-reply crash/hang, deadlines, cancellation before launch,
during startup and after cleanup, request mutation, bad input/options, busy
admission, sanitized environment, native startup failure, cleanup uncertainty,
parent death and process-count limits. Actual Windows processes are used for
transport faults; test helper entry substitution is private test instrumentation,
not a public transport option. Existing codec tests cover replay and all exact
binding substitutions. Automated tests are separate from the owner walkthrough.

A Job Object is **not a reduced-privilege sandbox**. The child still runs with
the account's rights. This deny-only child reduces no existing reader trust yet.
The OS, Python, native launcher, packaged child and coordinator remain trusted.
Secrets are not promised to be securely erased from Python memory. Cancellation
is cooperative observation at polling/publication checks, not an atomic
revocation fence; no asynchronous cancellation can retroactively recall a return.

## Remaining gate before activation

A separate [inactive fixture owner](broker-resource-ownership.md) now tests
original-handle metadata ownership and local one-shot proposal binding. It is
not connected to the child. Next define authenticated observation issuance,
session/token lookup and staged-buffer ownership across the process boundary. Define one-use authority consumption, current registry and human
control, expiry/revocation/cancellation fencing at final delivery and crash
semantics without renewal or replay. Choose a restricted token/application
channel design deliberately before a real cooperating application. A resource
token is still only an opaque binding value, never file identity. Do not reopen
requester paths or interpret a successful transport handshake as permission.
The existing narrow protected fixture path remains the only enforcement claim.
