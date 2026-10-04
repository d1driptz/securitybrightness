# Inactive acquisition-binding wire draft

`core/broker_binding_protocol.py` defines a separate authenticated four-message
profile. It is a codec only: no process is launched, resource is acquired, authority
is issued or bytes are read. No existing broker, host, desktop, `/check`, v1 or
protected-reader path imports it.

The allowed sequence is:

1. Coordinator sends the bounded exact reservation context and reviewed-display digest.
2. Broker acknowledges the digest of that complete binding with `bound`.
3. Coordinator sends `retire` or `cancel`, bound to the same digest.
4. Broker acknowledges `denied`, `retired`, and exactly zero released bytes.

`bound` means only that the peer accepted a transcript. It does not establish
current registry authority, human permission, resource ownership, native identity
freshness or successful cleanup. These claims cannot be inferred from a message
signed by a peer, even when its key came from trusted bootstrap.

Each frame authenticates the session, direction, step, previous-frame hash and
canonical content, under a distinct protocol domain. The first context includes
application/proposal, grant/draft/version, review and decision identifiers,
resource session/owner/token, volume/file identity, size, byte limit, operation and
recipient. The display digest additionally binds the human-facing presentation.
Path, handle, authority flags, peer-selected expiry and unsupported fields are
rejected. Requester strings are not converted into native identity.

The existing 8192-byte frame-body bound applies. Only `files.read` descriptive
contexts with byte limits up to 4096 are representable; **no read command exists**.
The codec snapshots validated scalar context rather than retaining caller-owned
dictionaries. Received dictionaries remain metadata, never permission objects.

Each endpoint has a local trusted monotonic lifetime of at most five seconds.
Messages cannot extend it. Both before and after a codec call, expiry/cancellation
withholds the result. Idle expiry clears endpoint state and its key. Invalid
messages, duplicates, wrong order, unsupported operations and closure are terminal.
Cancellation serializes under the endpoint lock; a completed message cannot be
retroactively recalled and therefore must never independently authorize work.

Lost messages produce no successful receiver transition. A lost final reply cannot
be retransmitted from a spent endpoint. A new exchange needs fresh bootstrap,
current authority and fresh review; the old reservation/receipt must not be revived.
This codec has no reconnect, retry, resume or recovery path.

## Verification and remaining integration

The 28 tests cover exact binding, mutation, malformed/oversized input, unsupported
effects and authority injection, identifiers, replay, wrong key/session/domain,
transcript substitution, truncation, data injection, message loss, idle expiry,
concurrency, timer failure and cancellation/expiry during encoding or decoding.
Peer disappearance is simulated at the codec boundary. These tests do not claim
new child-crash cleanup behavior; the existing private-child suites run separately.

Before this profile may participate in a broker experiment, a separate fixed
metadata-only child/host integration must tie acknowledgement to exact retained
resource validation and verified cleanup, hold results until EOF/exit/join, and
recheck current coordinator authority. Cancellation, revocation, expiry and crashes
must be tested across those boundaries. The native-retirement receipt cannot serve
as a later acquisition token: its resource has already been retired.

Actual acquisition still needs a deliberate one-use transition that keeps the
resource live for a bounded operation, plus quarantine and an independent final
publication check. This draft does not activate or claim that enforcement.
