# Inactive one-use dry publication commit

`PublicationCommitExchange` and `PublicationCommitDraft` define a separate
metadata-only commit contract. They have no transport, file access or byte delivery
operation. The only supported mode is `dry_run_discard_only`, revision 1. Existing
protected-reader, broker hosts, owner/desktop walkthroughs, `/check` and v1 behavior
are unchanged; no product route imports or selects this draft.

## Exact binding and one use

Trusted bootstrap supplies the exact original `LiveChannelPublicationCheck`
separately from requester proposal data. It must be in its witnessed phase, with
the original guarded Windows peer still live and owned and the original fixture
bytes retained. The draft captures original source/recipient/acquisition/review,
native child/observation, quarantine and envelope identities. It generates its own
commit ID; no requester-provided channel observation, endpoint, callback, PID,
nonce, authority flag or recipient owner is accepted by the draft.

The bounded strict envelope includes the complete original action/recipient
binding, exact staged count/digest and original channel PID, creation time and
witness session. The count must equal the observed whole-file size and remain
within the original byte ceiling. Empty data requires the empty-data digest.
Unknown fields, additional effects, unsupported modes/revisions, partial-read
claims, identity collisions, malformed values and type confusion are rejected.
The pure codec validates these as claims; it cannot independently establish any
file/process identity or authority. Path strings do not appear as resource identity.

A distinct MAC domain and four bounded canonical frames cover prepare, prepared,
dry commit and receipt. Direction, session, phase and previous-frame digest bind
the transcript. Rejected input, wrong phase/role, mutation or replay permanently
closes that endpoint. Inherited witness/data operations are disabled. Frames and
receipt metadata contain no protected bytes and cannot become permission by
being truth-tested.

The draft validates the same original source, issued proof, native observation,
both codecs and current review/registry/draft/proposal/resource/effect/recipient
state around every phase. Native queries are followed by renewed checks of the
original proof, bindings and fresh authority so reentrant mutation cannot hide
behind an earlier successful check. Deadlines remain bounded by the original
helper/source/recipient/quarantine lifetimes and at most five seconds; they cannot
renew human review or restore retired state.

## Explicit dry boundary and failure ordering

The first `commit` attempt burns the draft before credential, proposal or recipient
validation. Under original owner locks, a current registry/ledger lease and native
ownership lock, it authenticates the exact application/request/recipient and
constructs private commit metadata. It then calls the existing one-use source
final check, which irreversibly consumes that source and **discards all bytes**.
This locked consume-and-discard is the dry boundary. Metadata escapes only after
current authority, original native liveness/ownership, binding, empty-buffer and
exact zero-release result checks succeed afterward.

Revocation or cancellation completed before that boundary prevents completion.
A different thread attempting revocation during it waits for the registry lease;
once the boundary releases its locks, that revocation invalidates later receipt
inspection. The source stays consumed and its bytes stay discarded. There is no
rollback, renewal, retry or reusable commit token. A second draft over the same
source cannot consume it again and cannot preserve the first draft's evidence
after interfering with its ownership.

Receipt inspection independently requires the still-original live witness and
current authority, exact closed commit transcript and original zero-release final
result. Failure, cancellation, expiry or stale state closes the draft, wipes its
original buffer and signals the original worker. It never closes an unrelated
substituted helper, native child or timer. The original host/worker still owns
native cleanup and shared admission; callers must join it before accepting native
shutdown status. Codec/timer failure cannot skip buffer disposal or expose a
successful receipt.

## Tested scope and remaining gate

The 78 new tests comprise 27 protocol and 51 draft cases, with parameterized
malformed/oversized/injected input and boundary values. They cover exact binding,
untrusted constructor data, wrong credentials/application/recipient/effects,
revocation/rotation/scope/draft/review changes, replay/duplicate commit attempts,
copy/mutation/state rollback, cancelled/expired/extended lifetimes, foreign owner
and timer preservation, buffer reinsertion, native death, false result metadata
and proof substitution during post-consumption native checks.

Tests use a real original guarded Windows witness but an **in-process synthetic
commit peer**. No commit frame goes to the native peer, and its synthetic receipt
is not proof of actual peer receipt, OS identity, process cleanup or delivery.
Resource reports and operator decisions in draft tests remain model orchestration.
Additional tests pause the original witness worker after genuine proof outside
all authority locks, then exercise the draft on another thread under its own
leases. They verify completed pre-commit revocation/cancellation, actual concurrent
revocation waiting for the dry boundary, stale post-boundary receipts and failed
registry guards. The old worker subsequently rejects the already-consumed source
and joins cleanup; this is test orchestration rather than a new host profile.

The next prerequisite is a fixed native commit-peer/host composition that verifies
these exact metadata phases over the original guarded private channel, including
EOF/crash/cleanup/cancellation handling. It must remain inactive and discard-only
until separately tested. Actual one-use delivery still needs an explicitly tested
publication boundary: bytes already delivered cannot be retracted by later
revocation, and retries cannot reproduce a lost delivery. Human-wait lifetime,
trusted real-application onboarding and a controlled generated-fixture delivery
experiment remain separate gates. Retired dry metadata cannot authorize any of
them.

The coordinator/bootstrap, registry/ledger, operator port distribution, development
checkout, runtime/OS and fixed peer/adapter remain trusted. No hostile trusted-
process isolation, installed-code attestation, immutable contents, secure erasure
of interpreter copies or global/direct Windows access protection is claimed.
Application/AI intent does not equal human permission; neither review evidence nor
application authority alone becomes permission through this contract.
