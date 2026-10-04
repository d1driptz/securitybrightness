# Inactive native retirement composition

`core/broker_native_retirement.py` joins the inactive acquisition reservation model
to an exact locally owned `BrokerResourceSession` and its exact issued observation.
It performs native **metadata validation and retirement only**, never a read.
No existing child, host, desktop, protected reader, `/check` or v1 path imports it.

Trusted bootstrap transfers ownership of the reservation model and resource
session. Requester dictionaries, verifier callbacks, paths, handles and deserialized
observations are not accepted as owners. This is a local composition experiment,
not a new wire command or independently authenticated broker boundary. Bootstrap,
the Python process, registry/ledger, metadata collector and native owner remain
trusted. Private model invariants are intentionally coupled and require joint review.

The first attempt is terminal. Under the acquisition/review/registry/ledger locks,
it checks the exact reservation, current review and authority, application
credentials and exact proposal. It then asks the session to inspect the original
issued observation against its retained native handle. Session/owner/token,
volume/file ID and observed size must match the saved reservation. The displayed
path must also match the reviewed label; path equality never establishes identity.

Native `verify_once` retires the resource slot before validation and closes the
fixture owner. The whole transferred session is then closed before consumption
rechecks authority, freshness and review state. Any failure retires both owners;
cleanup uncertainty returns no receipt. A concurrent attempt cannot obtain a
second receipt. Cancellation serializes with retirement; it cannot retroactively
recall a completed metadata receipt, which carries no executable permission.

The inherited native policy still restricts fixtures to local NTFS regular files,
rejects reparse points and multiple hard links, and compares retained-handle
metadata. This module introduces no path reopening, normalization-as-identity,
arbitrary file selection or promise of immutable contents. Fixtures are generated
by the existing owner and removed on closure.

The return value is the existing inactive consumption evidence, with no bytes,
read command or delivery permission. It describes checks completed before
retirement, not a resource that remains available afterward. It must never be
converted into a bearer token for later acquisition.

## Verification and remaining gate

The 26 new tests use actual generated native fixtures and cover exact ownership,
substituted sessions/resources, copied tokens/observations, changed requests and
effects, wrong/oversized credentials, rotation, permission/draft changes, expiry,
native metadata/error rejection, mutation/revocation during retirement, cleanup
failure, cancellation, replay and concurrent attempts.

The next gate remains a deliberate one-use **cross-process** transition tying
current coordinator authority to a broker-retained resource. It must address
lost/duplicate messages, crashes, cancellation and expiry without reusing this
retired receipt as authority. Bounded quarantine and a separate final publication
check remain necessary before any new broker-backed controlled read experiment.
The existing fixture protected-reader claim is unchanged.
