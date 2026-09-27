# Structured proposal and constrained authority - design gate

Status: PROPOSED. This decision records the contract that must be settled before changing authorization semantics. It does not grant new authority, change the HTTP schema, or add execution.

## Why this gate exists

SecurityBrightness currently authorizes an `action`, `target` and ordinary requester details. Application identity and granted scopes are server-derived. That is deliberately safer than allowing callers to assert authority, but broad scopes such as `files.read` do not express which resource, recipient, amount, visibility or other material effect was reviewed.

A future enforcement point must be able to prove that the operation it is about to permit is the same operation SecurityBrightness evaluated. Adding resource syntax to scope strings before defining that proposal identity would create ambiguous authority and replay/binding risks.

## Required invariants

- Application/AI intent is a proposal, never human permission.
- Authenticated identity, grants, policy state and human decisions remain outside requester-controlled proposal data.
- Missing or unverified material context cannot make a request less restrictive.
- Human approval applies to one immutable proposal unless a separately defined grant explicitly says otherwise.
- Changing a material effect creates a different proposal. An approval for one target, recipient, amount or operation must not silently authorize another.
- SecurityBrightness remains authorization-only. This contract must not introduce arbitrary shell, file, payment, communication or system execution.
- Existing v1 `action + target + details` requests remain supported until an explicit migration decision is accepted.

## Proposed v2 proposal model

A v2 proposal should have a versioned canonical representation with these conceptual fields:

- `operation`: normalized action vocabulary controlled by the integration contract.
- `resources`: one or more typed affected resources. Examples may include a file object, account object or service object; a display string alone is not proof of resource identity.
- `effects`: operation-specific material consequences such as destination/recipient, amount and currency, external visibility, destructive/reversible state, or requested privilege.
- `requester_context`: optional application-authored purpose/explanation. It is untrusted context and cannot lower safeguards.
- `provenance`: context supplied by a trusted adapter/enforcement point, kept distinguishable from requester claims.
- `proposal_id`: derived from a canonical immutable proposal snapshot or otherwise bound to that exact snapshot. The algorithm and cryptographic requirements require a later implementation decision.

Not every operation uses every effect. Operation-specific schemas should reject unknown material fields rather than interpreting them loosely.

## Authority must be separate from proposals

A durable or temporary grant is not a proposal and not an application credential. A future constrained grant needs, at minimum:

- application/delegation identity;
- permitted operation(s);
- resource constraint(s);
- effect constraints where applicable;
- lifetime semantics;
- use-count semantics where applicable;
- grant/version identity for revocation and final revalidation.

Unsupported expiry, one-shot or resource constraint modes must fail closed rather than degrade to a broad scope.

## Enforcement binding requirement

A decision response alone is not an enforcement capability. Before SecurityBrightness claims control of a real operation, a controlled enforcement point must verify that:

1. the application/delegation identity is applicable;
2. the exact proposal/effect identity matches what was authorized;
3. the relevant grant/policy version is still valid;
4. expiry/use-count/revocation conditions still hold;
5. authorization has not been replayed for an incompatible operation.

The enforcement point, not requester prose, must own or reliably observe the authority needed to refuse the real effect.

## Compatibility sequence

1. Keep the current v1 HTTP/SDK behavior unchanged.
2. Introduce a validated v2 proposal type without changing permission results.
3. Add canonical proposal identity and adversarial tests for mutation, ambiguity and serialization.
4. Define operation-specific resource/effect schemas starting with one narrow integration.
5. Define constrained grants and their persistence/revocation semantics.
6. Bind decisions to proposal identity.
7. Build one controlled enforcement-point prototype and test bypass/replay/failure behavior.
8. Only then make protection claims for that mediated path.

## First integration candidate

File access is the preferred first candidate because it can be kept narrow and local. The design must distinguish a user-facing path from the resource identity actually opened by the enforcement point and account for path normalization, links/reparse points, replacement/race behavior and platform-specific identity. The existing File Security analyzer remains independent analysis and must not be mistaken for file-access enforcement.

## Explicitly deferred

The isolated snapshot prototype uses SHA-256 for content identity, not signatures or capabilities. This proposal does not choose a signature algorithm, Windows broker architecture, OS credential store, asynchronous approval API, payment schema, human identity mechanism, policy language, or general-purpose executor. Those require separate decisions and evidence.

## Acceptance evidence for implementation

Tests for the eventual v2 contract must cover deterministic canonicalization, nested mutation isolation, unknown/duplicate fields, type confusion, Unicode/normalization ambiguity, oversized/deep data, material-effect changes, replay attempts and v1 compatibility. Enforcement tests must demonstrate that a denied or mismatched proposal cannot complete through the protected path.

## Review gate before an enforcement prototype

The isolated draft now preserves exact resource-reference text and rejects unsupported material effects during constraint applicability checks. A content hash plus a caller-constructible allow binding remains insufficient for execution. Keep v1 unchanged until a narrow operation-specific schema, authenticated decision issuer, application binding, revocation/final revalidation and replay policy are implemented and reviewed. File-path identity and replacement/link races remain unresolved; no protected file-access path is claimed by these primitives.

## Step 4 draft implementation

The first operation-specific schema is [file_read.v1](../file-read-proposals.md), implemented as pure construction/inspection helpers. Its explicit whole-file byte limit and requesting-application recipient are proposal data, not authority. Effect-aware constrained grants and real resource provenance remain subsequent work; the generic constraint evaluator continues to reject these effects. This advances the schema milestone without activating v2 in the service or changing human authority.

## Step 5 preparatory implementation

The separate [effect-aware file-read constraint draft](../file-read-constraints.md) adds pure owner/reference/byte-ceiling applicability checks. It does not complete step 5: authoritative grant issuance, persistence, activation, revocation, version and lifetime semantics remain unimplemented for these structured constraints. No live authorization or enforcement path consumes this draft.

## Step 5 draft-review versioning prototype

The isolated [draft review ledger](../file-read-review-lifecycle.md) tests expected-revision updates, terminal draft revocation and stale exact-proposal review detection. This deliberately stops before active grants: no reviewer authentication, human decision, activation, persistence, expiration, authority replay consumption or protected operation exists. A current review is only point-in-time inspection evidence, not an execution lease.

## Registry lifecycle binding prerequisite

[Registry-bound review evidence](../registry-bound-review.md) composes the existing authenticated application snapshot/activation lease with the inactive draft ledger. This tests invalidation on registry changes without activating structured authorization. Trusted human decisions, approved constrained-grant issuance, resource identity, final operation binding and enforcement replay handling remain explicit gates.

## Resource observation and operation-binding contract draft

The [separate adapter observation model](../resource-observation-binding.md) tests structural provenance separation, observation lifetime invalidation and exact operation binding using supplied synthetic metadata. It does not close the trusted resource identity gate. A real retained-handle collector, supported Windows traversal/stability policy, combined human/authority decision envelope, final revalidation/replay semantics and controlled denial-prevents-operation integration remain unimplemented.
