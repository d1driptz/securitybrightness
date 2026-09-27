# Resource-bound review envelopes (inactive)

`core.resource_review` pairs the exact issued registry/draft review ticket with the exact collector-owned observation and operation binding. Its envelope names the application and complete proposal identity. It never accepts an approval flag, creates an authority grant, checks policy permission or executes a read. The collector's OS metadata and the requester's proposal remain separate objects; neither a requester dictionary nor a copied observation can be imported as trusted evidence.

Capture checks current review evidence before and after native binding. Inspection checks review state, then resource state, then review state again. Tests inject registry rotation and draft revocation during the resource check; the final review check rejects the envelope. Registry errors, stale versions, superseded reviews/bindings, changed resources and closed collectors retire it. Retired IDs consume capacity and cannot be reused. Copied, changed-schema, transferred or cross-coordinator envelopes are rejected. Concurrent captures serialize and leave only the newest binding current. Closing the coordinator is terminal and does not implicitly close its separately owned collector/registry.

**This sequence is sampling, not atomic authorization.** A positive result describes the checks performed and can become stale immediately. The result refuses implicit boolean conversion. Repeated inspection is intentionally allowed: it is not one-use execution or replay accounting. A previously returned positive sample cannot authorize later consumption. A test deliberately obtains a current envelope for an application with no scopes: freshness is evidence, never permission.

No human approval is recorded here. Existing proposal-only decisions cannot be attached and promoted into authority for the combined envelope. A future authenticated human-control interface must display the observed resource separately from the requester label, explain the precise effects and bind its decision to the whole envelope. The current grant/draft/resource lifetimes must still be checked at the actual operation boundary. These checks are not yet implemented as an atomic downstream operation guard.

## Owner decision needed before a reader

The collector tests establish that metadata-only handles do not prove immutable contents. The product must define what a human approval means:

1. **Approve a file object and bounded read effect (recommended for the first fixture-only experiment).** The prompt identifies the adapter-selected object and maximum returned bytes. It must explicitly avoid promising approval of exact pre-inspected bytes. The experimental reader must retain its resource handle, refuse unsupported mutation situations, abort on detected inconsistency and never silently switch objects.
2. **Approve exact immutable bytes.** This needs an explicitly authorized snapshot/stability protocol, including permission to acquire protected contents for review. Metadata, file IDs and timestamps alone cannot support this meaning. No pre-authorization content hashing or reading may be added implicitly.

This is an approval-semantics decision, not a request to publish already verified inactive code. The first option is a deliberately narrower proof; it does not close the second option's content-consent requirements.

## Proposed first controlled experiment (not implemented or run)

Use only a runner-created synthetic fixture and an explicitly selected adapter-owned handle. No arbitrary path endpoint, normal `/check` integration or access to user documents. The human-control channel must be distinct from application input. SecurityBrightness must evaluate current scope/policy and required human control; a fresh review record cannot substitute for either.

The experimental operation must consume a one-use, exact envelope-bound decision under a defined order for registry/lifecycle revocation and resource validation. Acquire read access only within the deliberately authorized fixture boundary; do not reopen a requester path. Keep output buffered and bounded, with no partial content release on error. A concurrent revoke either linearizes before consumption and denies, or after the explicitly defined completed consumption point; tests must exercise both orders.

Instrument the protected reader and application-visible bytes. Deny, absent human control, wrong application/resource/effect, stale proposal/draft/grant, rotated credentials, failed lookup, changed resource, expired/consumed decision and replay must yield zero delivered bytes with no fallback. An authorized matching case must deliver only the intended bounded fixture bytes. This proves denial prevents the operation through that specific protected path; it does not prove protection against direct OS access outside it, hostile code in the trusted process, arbitrary Windows files or antivirus threats.

Still required before that experiment: the owner-selected approval semantics, trusted acquisition/human-channel provenance, appropriate handle rights/stability strategy, authoritative grant/decision lifecycle, final atomic consumption/revocation ordering and one-use replay accounting. The inactive envelope does not solve those gates merely by existing.
