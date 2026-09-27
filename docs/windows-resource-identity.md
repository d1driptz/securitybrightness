# Windows retained-handle identity collector (inactive)

`core.windows_identity.WindowsIdentityCollector` is a trusted adapter primitive. It opens **metadata-only** handles on explicitly selected paths and returns observations issued by its own session. It is not called by `/check`, HTTP handlers, SDK authorization or a file reader. It cannot read file contents with its handles, grant permission or execute an action. Tests operate exclusively on synthetic fixtures.

## Narrow supported profile

- Windows, local NTFS, regular unnamed files, one hard link.
- Drive-absolute paths only; slash variants are accepted as syntax. Relative, drive-relative, UNC, device/extended namespaces, alternate streams, dot components, empty components, trailing dots/spaces and reserved DOS device names are rejected. Component and total UTF-16 lengths, depth and session capacity are bounded.
- Case-insensitive directory traversal only. Unknown case flags fail closed. Different case/slash spellings can reach the same OS file identity but create distinct observation lifetimes. No path spelling is proof of identity.
- Each component is opened relative to the retained parent handle, with reparse processing disabled for that component. Reparse directories and final objects are rejected by metadata checks. A concurrent parent rename/replacement cannot redirect the already-held parent to its replacement. There is no claim of confinement beneath an authorized pathname: the collector has no such authority policy.
- Actual volume serial and 128-bit file ID come from `FILE_ID_INFO`; a handle-derived final path is for display only. Parent identities and final metadata are rechecked during acquisition. Missing queries, remote filesystems, deletion pending, unexpected metadata or unsupported features abort without fallback.

The OS operations follow Microsoft's [NtCreateFile relative-root and open options](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile), [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info), [volume query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile) and [volume information by handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew) contracts.

## Lifetime, mutation and failures

The collector retains the actual handles until explicit release/close. Every binding requires the exact live issued observation; equal/copied reports, another collector's reports and requester dictionaries are rejected. Revalidation queries those same handles, never reopens the display path. Changes in final identity/size/timestamps/attributes/link count, parent identity, unsupported state or query failure retire evidence. IDs are session-scoped, bounded and not recycled after release. A file recreated at the same name requires fresh observation and binding even if an OS identifier is eventually reused.

Cleanup attempts every acquired handle. Any reported close failure poisons the collector's evidence and blocks new acquisition; OS cleanup success cannot be promised after a failed native close. Use a context manager or explicit close. There is no destructor-based safety guarantee. Unsupported platforms and native errors fail closed with fixed public errors.

**Metadata identity is not content stability.** Real Windows tests demonstrated that attributes-only handles do not reliably exclude writers through sharing flags. Existing writers and changed contents are possible; metadata revalidation detects tested inconsistencies but cannot prove absence of intervening changes, malicious timestamp restoration, writable mappings or mutation immediately after validation. Share flags and timestamps must never be promoted into an immutable-content claim. See [Windows access/sharing semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

## Deliberately open gates

The collector is trusted in-process Python, not a boundary against hostile code in the same process. It accepts no serialized observations or permission fields. Its explicit path argument must come from a trusted adapter selection policy before any future exposure to applications. Metadata acquisition itself must be authorized and contained; it is not currently an application endpoint. Synchronous native calls have no hard timeout or broker isolation.

Exact human review must cover the application, full proposal, current grant/draft versions, observation lifetime and effects. Neither the model binding nor a collector match checks registry authority. Neither proves human approval, scope permission, expiry or use accounting. Matches are repeatable point-in-time evidence, not execution tokens.

Before a real controlled experiment: define trusted acquisition/selection, authenticated human control of the combined envelope, authoritative grant/freshness checks at consumption, replay/revocation ordering, and a bounded read strategy with explicit content-stability semantics. A metadata-only handle cannot simply be upgraded into an approved reader. No fallback may reopen the requester path. A denial experiment must measure zero protected content delivered on denial/error/staleness/replay and the exact permitted effect on allow. This collector does not demonstrate enforcement.
