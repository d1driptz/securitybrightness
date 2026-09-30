# Inactive broker-owned fixture binding

`core.broker_resource.BrokerFixtureOwner` is a separate metadata-only prerequisite.
It is used only by the opt-in [retired-observation child](broker-retired-observations.md),
not the existing protected reader, owner walkthrough, `/check` or v1. No existing
protection claim changes.

## Ownership and exact binding

Construction accepts no arguments. It creates one uniquely named temporary
synthetic file containing the fixed 37-byte test text with native atomic
create-new/delete-on-close, retains the original noninherited write-only descriptor, and obtains Windows metadata from that same
handle. It never reopens the generated pathname. Only local NTFS regular files
with one link and no reparse attribute pass the existing native metadata checks.
A generated filename or normalized path never serves as resource identity.
The creation handle, volume/file ID and complete metadata snapshot do.

The description carries separate fresh session/resource identifiers, native
volume/file ID, size and a display-only path. An owner can bind exactly one
application ID, structured file-read proposal digest, resource token, decision
ID and byte bound. The digest covers the complete proposal, including reference,
effects and requester context. References stay unverified descriptive text.
The whole synthetic file must fit the bound: 37 through 4,096 bytes in this
primitive. A decision ID is merely an exact comparison field, not a grant or
proof of review. There is no approve, grant, read, arbitrary-file or deliver API.

`verify_once` compares the original locally issued binding object and its saved
immutable values, revalidates the retained handle, closes ownership, then returns
a metadata-match receipt with no content field. Failure also closes ownership.
Copies, forged or foreign binding objects are rejected even if their values
match. This is local object provenance, not a serialized capability: it must not
be replaced by dictionary deserialization at a future IPC boundary.

A fixed 60-second monotonic lifetime cannot be refreshed. Deadline checks after
native validation and cleanup prevent those operations from extending validity.
A lock serializes consume/close/rebind attempts; concurrent verification yields
at most one receipt. Duplicate binding attempts, malformed requests, mutation,
expiry, metadata or cleanup errors are terminal. Context-manager cleanup is the
trusted caller's responsibility; Windows delete-on-close additionally removes the generated pathname on process
exit; no per-fixture directory or Python finalizer is needed. See
[resource sessions and disposal](broker-resource-sessions.md) for the limits.

## Windows and trust limits

The retained creator handle prevents ordinary deletion/replacement in the tested
Windows configuration. Identity is still checked from the handle, never by
re-resolving an old name. Added hard links and changes to identity, size, change
or write timestamps, creation metadata, attributes or link count invalidate the
snapshot. This is not a promise of immutable contents. Displayed paths may be
stale labels and are never interpreted as capabilities. This primitive avoids
requester path aliases/case/relative-path issues by accepting no path at all;
it does not establish that arbitrary Windows paths are safe.

The interpreter, host process, temporary-directory configuration, native metadata
adapter and module integrity remain trusted. The creator descriptor retains its
creation access rights and must stay private; it is not a reduced-privilege
sandbox. Hostile same-process Python can bypass private fields. Repeated owner
construction is available only to trusted bootstrap/test code, not an exposed
application endpoint. Random identifier collisions cannot transfer a local
binding because exact issued-object provenance is also required. No durable or
cross-process token registry is claimed.

## Next gate

The original denial-only child remains unchanged. A separate diagnostic child
now returns authenticated observations only after resource retirement. A separate inactive local session registry now tests bounded lookup, collision
rejection, lifetime and terminal cancellation. Before using it across IPC, define
a bounded multi-step session protocol and explicit peer/resource binding. Broker-owned
handles must stay alive across review while stale sessions and cancellations
retire them. Define staged-buffer ownership and authority-controlled acquisition;
there must be no speculative content read based on matching metadata alone.
Then test final current registry/grant/human-control checks, one-use decision
consumption, expiry/revocation/cancellation fencing and crash behavior before any
bytes leave trusted staging. Neither a fresh observation nor a match receipt
can substitute for these gates. Application/AI intent does not equal permission.
