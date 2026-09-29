# Controlled fixture read enforcement experiment

Owner decision accepted on 2026-09-29: human approval covers a specific verified file object and one bounded read effect, **not an immutable byte snapshot**. Exact-byte approval remains a distinct future mode requiring explicitly authorized snapshot/content-stability handling.

`core.fixture_read_experiment` implements one opt-in integration. It is not imported by `/check`, the HTTP service, SDK authorization or ordinary file tools. The trusted bootstrap creates one synthetic fixture; neither the application proposal nor the read API accepts a filesystem path. Maximum fixture size is 4,096 bytes. No application-requested write, delete, execution or antivirus behavior exists.

## What is enforced

The protected operation is delivery of the whole bounded fixture read to the application-facing caller. A preflight denial prevents the native read call. A failure discovered after native buffering returns zero bytes to that caller. Internal staged bytes are not published incrementally. Repeated or concurrent attempts cannot reuse an approval.

1. The trusted bootstrap exclusively creates a temporary fixture, obtains the creation handle's OS identity and keeps it alive until the metadata collector retains that same object. It compares handle-derived volume/file identifiers, not pathname strings. The fixture's descriptive reference is the fixed `controlled-fixture` label.
2. The application-facing port proposes the strict file-read schema. The existing registry authenticates the application and supplies current `files.read` (or wildcard) scope. The experimental policy supports only this fixture/effect and always requires operator approval, including for trusted applications. Requester fields cannot supply permission.
3. A separate operator port displays the application, complete proposal JSON and identity, grant/draft/envelope versions, actual observed resource identity/lifetime, display path and byte ceiling. Displaying/reviewing is not approval. Only the exact display object issued to that operator channel can be approved. Copies, superseded displays and duplicate approvals fail. Redisplay removes prior approval without extending the deadline.
4. The first read attempt irreversibly retires its issued request, even on denial, wrong credentials, mismatch or adapter failure. There is no serialized allow token or restore/import path. Approval is bound to the exact internal envelope and current authority, not a caller-supplied flag.
5. Under the registry activation lease, the adapter validates the complete proposal, review/grant versions, resource and bounded effect. It uses `ReOpenFile` on the retained object to acquire read access; it never opens an application pathname. It checks the new handle's full metadata against the retained observation before reading.
6. A bounded synchronous `ReadFile` stages the whole observed file. Short/error/oversized results, identity/metadata failures, read-handle closure errors and final authority/freshness failures release nothing. The read handle closes before publication. The exact observation and review are checked again before returning the result.

The experiment is session-only: at most 32 issued requests, each with a fixed 60-second lifetime from proposal creation. Retired IDs continue consuming capacity. Duplicate IDs fail, and shutdown invalidates all requests. Adapter read failures poison the experiment instead of enabling a retry fallback. No requester can prolong the lifetime by redisplaying approval.

Microsoft documents [ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile) as reopening the existing filesystem object with selected access/sharing, and [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) as reading through a read-capable handle. Real Windows fixture tests validate this retained-object route with the collector's handles on this host. Unsupported operations fail; there is no pathname fallback.

## Revocation and race boundary

The experiment lock serializes its owned draft/review/approval/resource lifecycle. The registry lease serializes external registry changes with the bounded read and result publication. Locks are acquired in experiment-then-registry order; the coordinator/ledger/collector belong exclusively to this experiment. No application callback runs under these locks.

A registry revoke completed before consumption causes denial without a native read. A revoke arriving while an already-guarded read is in progress waits: the read may publish while authority is still current, then revocation completes and blocks subsequent attempts. It is not retroactive cancellation of already authorized delivery. Tests exercise both orders and same-thread injected authority changes, which the final lease check rejects before releasing staged bytes. Concurrent read attempts deliver at most once.

Native Windows calls are synchronous and have no hard cancellation deadline. The 60-second check rejects a completed result that has become stale; it does not interrupt a hung filesystem/filter call. Such a stall can delay registry revocation while the lease is held. This is a limitation of the isolated fixture experiment, and a reason not to expose it as a general service.

## Contents and Windows limitations

Metadata-only handles do not reliably exclude writers. The read-capable handle requests share-read only, and fixture tests confirm ordinary conflicting writers and deletion are rejected during its lifetime. Existing writers cause acquisition failure. These checks **do not establish immutable bytes**: pre-existing writable mappings, privileged actors and metadata restoration are outside a byte-stability guarantee. A real writable-mapping regression permits only a restrictive denial or a bounded result from the approved object; it does not require approval-time contents. Detected inconsistency fails closed, but unchanged metadata is not proof of unchanged content.

Reparse points, hard links, unsupported case behavior, remote/non-NTFS resources and ambiguous namespaces retain the collector's rejection rules. Parent/drive alias handling is documented in [Windows resource identity](windows-resource-identity.md). File IDs are scoped to the retained-handle session, not permanent identities after deletion/recreation.

## Human-channel and coverage limits

The trusted host must keep the operator port, registry, controller and adapter private. The application-facing port accepts untrusted request data; these Python objects are **not isolation against hostile Python executing in the same host process**. Private attributes are not a security boundary. There is no external authenticated application transport, secure desktop, durable approval ledger or cross-process broker in this experiment.

Automated tests simulate operator decisions through the separate trusted port. They do not claim a real person approved the automated fixture reads. The optional console demonstration requires an interactive local terminal, displays the full envelope and requires the exact typed phrase `ALLOW ONCE`. It accepts no path arguments, automatic approval flags or piped approval input. The local operator terminal is a deliberately limited trusted channel, not general human identity verification.

Run manually from the repository:

```powershell
python -m core.controlled_read_demo
```

The owner walkthrough now exercises explicit DENY, ALLOW ONCE, replay, revoked/stale/expired approval, and changed request/resource binding. It uses a real 65-second expiry wait and fresh typed approval for changed requests/resources. Only synthetic fixture data is shown. See [the dedicated security review and owner steps](fixture-security-review.md). Automated script checks simulate input/time only in tests; they are not human demonstration evidence.

This establishes real enforcement **only through this controlled integration path**. An application using Windows directly or bypassing the trusted host is not prevented from accessing files. SecurityBrightness remains the authorization/human-control boundary; the small adapter mediates this one effect. `/check` and v1 remain unchanged.

## Before any expansion

Stop at this single fixture path. Generalization needs a separately reviewed isolated broker/transport and authenticated human channel, trusted acquisition policy for real resources, cancellation/liveness and revocation semantics for slow I/O, durable decision/audit/recovery requirements where applicable, and a separately authorized snapshot mode if exact-byte consent is desired. No production Windows-wide protection claim follows from this experiment.

The dedicated review fixed expiry crossing the final freshness check: deadlines are now rechecked after inspection and at the publication decision, with terminal retirement on expiry. See the linked review for reproduced failures, regression evidence and broker trust analysis.
