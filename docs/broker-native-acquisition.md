# Inactive fixed native fixture acquisition

`core/broker_native_acquisition.py` supplies a separate trusted adapter for one
newly generated 37-byte fixture. It stages a bounded native read onto private
discard-only transport. Only the separate inactive acquisition/discard child and
host select it. Existing desktop, protected reader, `/check` and v1 paths do not.
It accepts no caller pathname, file contents,
handle, executable or resource selector. It has no application delivery API.

The adapter creates the fixed synthetic fixture atomically with CREATE_NEW,
DELETE_ON_CLOSE and OPEN_REPARSE_POINT using a noninherited read/write/delete
handle. Setup writes only the built-in fixture. Native metadata restricts the
resource to a local NTFS regular file with no reparse point and one hard link.
Generated identifiers are bounded and validated before constructing the filename.
Creation failure has no reopen, overwrite or permissive fallback.

The adapter emits an authenticated observation derived from that original handle.
The coordinator's existing live lifecycle supplies current application authority,
the exact proposal and explicit operator-review evidence separately. The adapter
checks the complete resource/application/proposal/decision/effect context against
its own issued observation and original opening. Grant/draft/review fields are
authenticated coordinator claims; the adapter cannot independently authenticate
a human or query current grant authority. The coordinator owns the original
display digest; this staging profile does not independently prove human review.

The first staging attempt is spent before decoding or native work. Native metadata
and exact typed description snapshots are checked, the original descriptor is
positioned at zero, and one read requests exactly the observed 37 bytes within
the approved limit. No pathname is reopened or normalized into identity. Native
metadata, proposal and description snapshots are checked after reading and after
frame generation. Exact typed descriptor/handle snapshots must still map to the
original native object before and after inspection; reads use the captured original
descriptor. Cleanup verifies native object identity before closing the original
descriptor and rejects uncertainty rather than closing a substituted resource.
Short, oversized, non-bytes or changed-content results fail:
the output must exactly match the built-in synthetic fixture. This preserves the
fixed test scope and is not a general promise of immutable contents.

The read/write handle uses share mode zero to exclude ordinary competing
read/write/delete opens. Metadata-only access and hostile code in the trusted
process remain outside that claim. Delete-on-close depends on all relevant handles
closing; this does not defeat hostile same-process handle duplication.
See Microsoft's [CreateFile sharing/cleanup contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
and [handle-derived file metadata](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex).

Staging frames contain the synthetic bytes and are for trusted adapter/coordinator
transport only. HMAC authenticates frames and does not encrypt them. Tests feed
these frames into the private quarantine, which returns only count/digest metadata.
Neither app credentials nor review evidence alone can create a valid coordinator
acquisition request. Changes to authority after native staging still invalidate
coordinator consumption and clear quarantine before any publication check.

Discard must match the exact staged transcript. The adapter validates the retained
resource again, closes its native ownership, and only then emits a zero-byte
discard acknowledgement. Closure uncertainty, expiry, cancellation or mutation
during cleanup prevents that acknowledgement. No retry, rebind or restoration
exists. Public cancellation is distinguished from successful internal retirement.

The adapter has a nonrenewable lifetime of at most five seconds and serializes
native access with cancellation so a timer cannot close/reuse the descriptor
during a read. Checks around native calls reject late results. A synchronous native
call may still block: local timers cannot provide process interruption. The
separate [inactive process composition](broker-acquisition-host.md) uses a fixed
child with independent watchdog/job cleanup and requires EOF, zero exit and joined
cleanup before its final authority check. No existing product route selects it.

The 47 adapter tests and 10 descriptor-binding tests use actual generated fixtures
and cover exact binding,
same-descriptor/bounded reads, noninheritance/deletion, replay/concurrency, malformed
or substituted input, type confusion, native/seek/read errors, changed/short/long
data, expiry/cancellation, mutation during native calls/frame generation/cleanup,
stale registry/draft authority and zero-byte discard/publication checks. Scripted
operator answers are test orchestration, not a human demonstration.

This proves native fixture acquisition into quarantine followed by discard in a
trusted discard-only composition. It does not establish a product broker protection path,
direct Windows access control, hostile-process isolation or real application
delivery. Existing protection claims remain unchanged. Retired acknowledgements
and publication-check metadata cannot become later read or delivery tokens.
