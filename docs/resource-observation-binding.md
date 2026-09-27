# Adapter observations and downstream operation binding (inactive model)

This stage structurally separates requester intent from adapter-originated resource reports. `core.resource_binding` is a pure in-memory contract model with synthetic test reports. It performs no Windows calls, acquires no handles, verifies no resources, evaluates no authority and executes nothing. It is not consumed by `/check` or any file reader. The trusted resource identity gate remains OPEN.

## Separate data channels

| Channel | Source and meaning | Current handling |
| --- | --- | --- |
| Structured proposal | Application-authored reference, effects and context | Existing immutable intent snapshot and strict file-read schema |
| Windows file observation | Metadata a future trusted adapter must obtain from its retained handle | Separate typed object issued within an adapter observation session |
| Operation binding | Association between application, complete proposal identity, observation lifetime and byte limit | Exact locally issued binding; inspection only, not permission |
| Human/authority decision | SecurityBrightness-controlled policy and required human control | Not produced or consumed by this model; remains a separate gate |

Requester context is never deserialized into an observation. A caller-constructed or copied observation is not recognized by a session, even if its fields match. Application ID validation is syntax only, not authentication. The trusted Python adapter caller can still fabricate a report: process isolation and a genuine observation collector are not implemented. Constructing a typed object does not confer trust.

The observation stores volume serial, 128-bit file ID, size, change-time value, and a display path in a distinct session/observation lifetime. Only the explicit draft profile `local_ntfs`, `regular`, `excluded` reparse status is accepted. These labels are required reports, NOT facts established by this module. Unknown/network/nonregular/reparse profiles fail validation. Unknown metadata must not be replaced by fabricated zero/default values by a future collector.

The requester reference and observed display path may differ. Both are untrusted as identity and neither is normalized or compared to declare resource equivalence. Their roles must be visibly distinct in future human review. Binding requires the exact complete proposal snapshot and the exact issued live observation; the same display path with a different file ID cannot satisfy an old binding. A new observation with identical metadata or an alias path also requires new binding.

## Lifetime and failure invariants tested in the model

One binding is outstanding per observation. Rebinding supersedes the earlier object. Observed size cannot exceed the requested whole-file limit. Changed application, reference, effects or context invalidate the operation binding.

Release invalidates the observation and its binding. Replacement retires the old observation before validating the new report, so failed replacement stays invalid. IDs, including released tombstones, consume bounded session capacity and collisions are rejected. A session has no import/restore path. All state changes use one lock. These are model lifetimes, not actual OS handle retention or closure.

Inspection results reject boolean conversion. A match cannot prove authority, human approval, content immutability, or real-resource truth. Repeated matching does not consume an operation and does not implement execution replay prevention. A previously returned match can become stale immediately. A generic proposal-only decision binding does not cover the observation and must not be promoted into an operation authorization.

## Windows collection and race design requirements (not implemented)

Microsoft documents handle-derived volume/file identifiers for comparing open handles. The proposed collector should obtain `FILE_ID_INFO` from the retained handle; it must not manufacture identity from a path. See [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).

File IDs are not guaranteed unique for all time and their behavior depends on the filesystem. Our design therefore scopes observations to an adapter session and a specific retained-handle lifetime, with no reopen-by-path shortcut or cross-session replay. See [file identifier limits](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information).

The future first integration should support only a deliberately narrow local regular-file profile. The adapter must own the handle from observation through final validation and bounded operation. Closing/reopening, lost handles, incomplete queries or inconsistent observations must abort and require new observation/review. The current model does not hold any native handle; its lifetime IDs only test the contract.

Windows sharing modes constrain compatible opens, including write and delete/rename access, for the lifetime of a handle. A proposed adapter must choose and test read-only access with conservative sharing against conflicting opens; a sharing violation must fail closed, not trigger a permissive retry. Share flags are not a substitute for proving all supported mutation paths are controlled. Existing writable mappings, hard-link aliases, alternate streams, namespace/device paths, replacement and concurrent writes require explicit tests or exclusion. See [CreateFileW access and sharing semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

Reparse processing has special semantics. A future adapter must prove its supported traversal policy for every relevant component and the final object. A path precheck followed by ordinary opening is race-prone; `FILE_FLAG_OPEN_REPARSE_POINT` must not be treated as a blanket proof that the entire traversal was safe. Unsupported junctions, mount points, symlinks or other reparse behavior must fail closed until deliberately supported. See [reparse-point considerations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations).

Size and change time are inconsistency signals, not cryptographic content identity or proof that bytes cannot change. Before claiming exact-content approval, define whether approval covers the actual file object under a proven stability condition or a separately acquired immutable byte snapshot. Do not read protected content before authorization merely to compute its hash. Acquisition of metadata/handles itself needs a narrowly scoped, explicitly authorized adapter boundary; this model does not introduce one.

## Required authorization-to-operation sequence

1. The application submits immutable intent. No identity or authority is accepted from its context.
2. A separately trusted adapter establishes the supported real resource using its own retained handle and supplies authenticated provenance. This acquisition boundary and its race behavior need real Windows tests.
3. SecurityBrightness evaluates current authoritative grants and policy and obtains required human control over an envelope containing the exact proposal AND adapter observation/effects. Existing proposal-only bindings are insufficient.
4. Immediately before the operation, current authority, proposal/version, human-decision provenance, observation/handle lifetime and effect limits are revalidated together. Revocation, replay/use accounting and failure cleanup need explicit atomic semantics.
5. The adapter acts only on that retained exact resource, within the approved effects. It never reopens a path supplied by the requester and never delegates arbitrary commands.
6. A controlled integration must demonstrate denial/error/stale/replayed/mismatched requests prevent the real operation through the protected path, with no partial data release or fallback. Direct access outside that path must not be described as covered.

None of steps 2 through 6 is established by these primitives. SecurityBrightness remains the authorization boundary, not a general executor or antivirus. Active authorization and enforcement must wait for these gates and their tests.

Session closure irreversibly retires all model evidence. Display labels are bounded to 32,767 UTF-16 code units, not merely Python code points. Resource matching deliberately remains independent of registry state; it must never substitute for current authority validation.
