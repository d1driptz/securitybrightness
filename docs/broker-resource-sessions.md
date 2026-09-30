# Inactive generated-resource sessions and process-crash disposal

The resource owner now creates its fixed 37-byte synthetic file with one native
`CreateFileW` call: `CREATE_NEW`, no shared read/write/delete access, null security
attributes (noninherited handle), temporary/open-reparse-point flags and
`FILE_FLAG_DELETE_ON_CLOSE`. Requested rights allow fixture creation/write,
metadata and deletion, but not content reads. The handle becomes a write-only
CRT descriptor; no second handle or path reopen is used.

Windows documents create-new failure for existing names and deletion when the
last handle closes with delete-on-close enabled. Those are the properties used
here; no path-based unlink or Python finalizer is required. See
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
The native metadata validator remains unchanged: delete-pending, reparse,
nonregular, multiple-link and unsupported filesystem observations still fail.
On the tested Windows NTFS configuration, a newly created delete-on-close handle
passes these existing checks without an exception or relaxed policy.

There is no per-fixture directory to orphan. Random-name collisions fail without
retry, truncation, reopening or deletion of the preexisting object. Conversion
failure closes the native handle. Normal descriptor closure, abrupt process
exit, forced termination and Job Object shutdown remove the generated pathname
in actual Windows tests. A native content-read attempt through the creation
handle returns failure with zero bytes.

This is process-lifetime disposal, not secure erasure or a guarantee across power
loss, OS/filesystem failure, malicious same-account handle duplication or added
hard links. Normal trusted code never duplicates or exports the creation handle.
A foreign hard link is rejected during revalidation, but deleting the owned name
does not remove somebody else's link. Account/process integrity and temporary
root selection remain trusted. The existing protected reader is unchanged.

## Bounded live ownership, still inactive

`BrokerResourceSession` is used by the separate opt-in [live-metadata diagnostic](broker-live-metadata.md),
not authorization or the existing reader. A trusted host creates a session with capacity 1–8
(default 4). It owns only generated fixture owners and their exact issued local
bindings. It has a fixed sixty-second monotonic deadline; every owner also keeps
its own existing deadline. There is no restore, import, renewal or extension API.

Issuance returns a live-ownership observation with a session ID and resource
token. Neither is authority or a permission token. Token lookup selects only an
already owned handle; it never opens a pathname or imports requester metadata.
Owner-session and token collisions are rejected, including retired token IDs.
Capacity counts issued tokens forever within that session, so consumption cannot
be used to evade its bound. The registry is process-local, not durable.

Verification first retires the token, then checks the original exact application,
proposal, decision-ID and resource binding through its owner. It closes the
handle and returns metadata evidence only. It does not read contents, grant
scope, authenticate an application, approve a request or consume an authoritative
human decision. In particular, decision IDs are comparison data, not a permission
ledger. A later authority layer must enforce its own one-use decisions.

Any failed operation closes the entire session and all remaining handles. Close
is terminal cancellation; a lock serializes it with consume. An already completed
metadata receipt cannot be recalled. Expiry is checked on operations and again
after native/cleanup work; it prevents later use, but there is no background
expiry timer yet. An idle trusted host must close the context; when eventually
hosted in a child, its independent process deadline must enforce bounded idle
lifetime. Constructing unlimited sessions in hostile host code is not prevented.

## Tests and next gate

Tests cover actual process crash/job cleanup, handle-conversion failure,
preexisting-name preservation, denied native content reads, bounded ownership,
exact lookup, application/proposal/decision mismatch, cross-session substitution,
expiry during cleanup, cancellation, replay, tombstones, collision, concurrent
consumption and cleanup failure across multiple owners.

The retired-observation wire diagnostic remains retired and denial-only. Its
fixture disposal uses the native owner and exposes no live registry. A separate
two-round diagnostic now tests authenticated live observation and terminal
retirement without reading. Next bind coordinator-owned pending review to current
registry/grant/human-control authority and define acquisition/delivery revocation
fences. `/check`, v1 and the existing fixture-only enforcement path remain unchanged.
