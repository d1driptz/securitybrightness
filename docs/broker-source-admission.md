# Inactive logical-source admission custody

`core/broker_source_admission.py` adds a private prerequisite for a future fixed
host. Trusted bootstrap can acquire the existing shared admission slot before
constructing an exact NEW logical publication source, retain it throughout
synthetic observation/review/acquisition, and hand it to a fixed private
two-worker rendezvous. The handoff never frees and reacquires admission.

This is **logical custody with two genuine Windows metadata peers**, not complete
native fixture acquisition custody. No source fixture child is created, owned or
joined here. Synthetic adapter frames remain trusted test orchestration, not
proof of a file observation or an actual read. No existing host, desktop/owner
walkthrough, protected reader, `/check` or v1 route selects this component.

## Fixed ownership and transitions

The private `_SourceAdmissionCustody` accepts only a bounded lifetime, at most
five seconds. It captures its original instance, bootstrap thread, deadline,
cancellation signal and original shared semaphore/condition/primitive guard,
waiter deque and notification function. It acquires that guard nonblocking and
changes the original slot from 1 to 0 once. Busy admission spends that attempt;
there is no replacement pool, `already_admitted` flag or reset operation.

Trusted bootstrap supplies an exact NEW `LivePublicationDraft`, exact acquisition,
review, registry, ledger and logical recipient owners. Subclasses, requester
mappings, foreign managers, preexisting review/claims/quarantine and malformed
initial state are rejected. The original graph, locks, descriptor and recipient
timer are archived before review. Model construction and port distribution
remain trusted-bootstrap responsibilities; NEW objects do not attest their own
creation chronology or human identity.

The custody-owned begin transitions capture the original review ticket, proposal,
application snapshots, registry lease, timer and deadline, then the original
quarantine wire, buffer, timer and deadline as those resources are created.
Creation failures are uncertain and poison admission. Starting those resources
through unrelated model ports cannot be certified as custody-owned cleanup.
Separate existing operator and adapter ports still handle synthetic observation,
human-control evidence and staging. Review evidence never becomes authority.

Original monotonic signals retain source, review, quarantine, handoff and completed
release history independently of mutable status snapshots. Erasing archives or
restoring an earlier status cannot make a created resource disappear, restart a
handoff or free admission belonging to a later session. Shallow copies are bound
to the original instance and cannot acquire, cancel, finish or abort its custody.

Only the original bootstrap thread can perform the custody transitions. Separate
cancellation signals the original owner without releasing admission; the worker
must finish or abort. All source/registry guards are released before rendezvous
I/O and thread joins. Original authority guards remain nonblocking. There is no
human wait, retry, renewal or deadline extension. The private rendezvous caps its
absolute deadline at the unchanged original custody deadline.

## Retained handoff and final release

The exact private `_CustodiedRendezvous` uses the existing fixed worker logic,
authority checks, consume/discard point and original native cleanup. The public
standalone rendezvous keeps its own admission behavior. The private profile
accepts only a reciprocal original custody/source/gate binding; its one-use
claim leaves the shared slot at 0.

After both workers join and original native/local cleanup is independently
verified, its distinct `joined_retained` or `failed_retained` seal explicitly
records `released=False`. No worker result, receipt, cleanup boolean or arbitrary
callback releases admission. Outer custody checks that original seal and source
graph, including empty original buffers, retired keys, absent original review
records and the original timer cancellation signals. Timer threads themselves
are not claimed joined.

Only outer custody can change 0 to 1. It holds the original condition guard
through cleanup, final current authority, terminal sealing, notification and
post-notification validation. Failure inside that guard rolls back to 0 before
another owner can enter. Confirmed cleanup after an authority rejection can free
admission but returns no successful association fact. Unknown cleanup poisons
the slot irreversibly within this process; no restoration, timer or new wrapper
clears it. A bootstrap-stage abort also requires independent original cleanup.

Forced termination before protocol input retirement may still prove original
process/job/pipe handles closed. Cleanup compares the exact typed archived
`(exit, input_closed)` facts. Successful association **separately** still requires
input retirement and zero exit. A forced-close fact never substitutes for the
successful protocol receipt.

A final return fence rechecks cleanup and current authority after genuine outer
release. Late corruption withholds historical evidence and wipes the captured
original buffer; it never reclaims, releases or cancels a later owner's slot.
The release marker cannot be rolled back by replaying old status snapshots.
These checks do not claim resistance to hostile code rewriting the trusted
Python runtime or secure erasure of interpreter/kernel copies.

## Verification and remaining gates

The added adversarial tests cover exact NEW graph validation, malformed lifetimes,
copy/thread ownership, separate authority/review requirements, replay, original
ticket/timer/lease/wire mutation, archive/history rollback, startup uncertainty,
denial and cancellation, credential rotation/revocation during genuine native
proof, original worker/native cleanup, guarded outer-release rollback, and late
failure after a newer custody has acquired admission. Existing rendezvous tests
also cover bounded/malformed proposals, effect/resource substitution, expiry,
peer crashes, extra output and protocol binding. Test decisions/observations are
automated orchestration, not an owner walkthrough or application identity proof.

The focused combined suite passed **176 tests** in 97.342 seconds, with no skips.
Full-suite verification is recorded in `DEVELOPMENT_LOG.md`. Workspace-only
Windows temporary-directory ACL support is not shipped. Runtime
`security_events.json` is excluded.

The complete workspace suite passed **2,491 Python tests** in 603.376 seconds
and all **8 scanner tests** in 1409.8201 ms, with no skips.

The next composition must own and archive creation of the **first native fixture
child** under the same admission, before observation/review/acquisition, and
verify its original handles and cleanup before this retained rendezvous. A
separate fixed guarded launcher can reuse the existing publication entry without
changing current hosts. Its original native archive must remain inside the
outer admission release fence through both later workers; closing it and passing
an outer cleanup boolean to this logical custody is insufficient. Launch
uncertainty and late archive mutation must retain admission.

A deliberate bounded human-wait acquisition profile remains a separate gate: the
30-second desktop-review subclass is intentionally rejected by the current exact
five-second acquisition contract. Neither deadlines nor accepted types are
widened here.

Trusted cooperating-application association and exact original-source/native-peer
payload publication remain separate gates, including partial-write, crash,
lost-receipt, expiry/revocation and restart semantics. No historical discard fact
activates them. The only current protected-operation claim remains delivery
through the existing fixture protected-reader path. This milestone proves no
native file acquisition, payload delivery, installed-app identity, immutable
contents, global durable at-most-once behavior or prevention of direct Windows
access. Application/AI intent does not equal human permission. SecurityBrightness
remains the authorization/human-control boundary, not an arbitrary executor or
antivirus.
