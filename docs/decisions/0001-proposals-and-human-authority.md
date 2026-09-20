# Proposal lifecycle and human authority

Status: PROPOSED; no approval endpoint, schema, identity mechanism or workflow described here is implemented by this document. The product owner's threat-model choice below is pending.

## Context and implemented baseline

The [architecture](../ARCHITECTURE.md) requires structured proposal identity before durable/asynchronous review, and separate human authority before an approval API. Today the SDK snapshots existing action/target/details JSON; the service generates a request ID, derives application identity, evaluates policy/scopes, waits for a trusted terminal provider, writes the decision audit and responds. That snapshot is not a persistent proposal, an approval token or a downstream capability.

Default terminal review now shows the engine's policy and review explanations. Application credentials cannot answer terminal prompts or invoke administrative endpoints. However, trusted in-process Python providers can return decisions, and SecurityBrightness does not isolate itself from hostile code with the same OS privileges. The registry remains in memory. These are boundaries, not guarantees of human-presence authentication.

## Intended next workflow

1. An authenticated application submits a versioned structured proposal. Separate action/resource/parameter/context fields from service-derived identity and authority. Caller explanations and risk claims retain their provenance; they cannot grant approval or lower mandatory review.
2. The service validates the entire proposal, snapshots the accepted content and assigns an identity. A materially changed target, recipient, amount or effect creates a new proposal requiring reevaluation. A content digest, if later used, is correlation/integrity metadata rather than a permission grant.
3. Policy and scopes may deny immediately. Otherwise the service either decides automatically under existing rules or makes the fixed proposal available for human review.
4. A separately authorized human channel shows the exact proposal, application, policy explanation, constraints and consequences. It submits an explicit decision for that proposal only. Strong confirmation remains distinct from ordinary approval.
5. The service checks that the review is still applicable, records the transition, and exposes the result to the originating application. Approval is not execution and does not grant ongoing authority.

This is a behavioral design, not a wire-schema commitment. Exact field types, normalization, protocol version negotiation and legacy coexistence will be specified and tested before release. Do not silently reinterpret legacy /check requests as durable grants or remove their supported behavior.

## Lifecycle requirements to settle during implementation design

- Explicit pending, approved, denied, cancelled and expired states; only one terminal transition wins.
- Stable immutable proposal content throughout review and audit, with caller data separate from service authority.
- Application ownership checks for status/cancellation; an application can never approve its own request using its application credential.
- Explicit concurrency rules for credential rotation, revocation, scope changes and human decisions. Existing authentication snapshots are insufficient for durable approval.
- Deadlines and disconnect recovery that fail closed. Polling is not a resubmission. Duplicate submission handling must be specified; current SDK checks are not idempotent.
- Audit persistence before returning an authoritative success, with no invented execution outcome.
- Human review transport independent of application and administrative credentials. Do not reuse the service/admin token as proof of human consent or merely add an application-accessible approved flag.
- No executor, general command runner, unrestricted resource access or claim of OS interception.

Persistent authority, retention and restart behavior need their own design before implementing durable grants. A first asynchronous workflow could remain explicitly ephemeral, but must clearly report expiry/loss rather than silently restoring authority.

## Product-owner decision required: first graphical approval threat model

### A. Trusted local operator environment first (recommended scope)

Treat the local operator's OS session and the trusted review component as trusted, as the terminal deployment does today. Build a separately authenticated review channel for that operator; isolate its authority from application credentials and protect against hostile API clients, browser-origin attacks if applicable, replay and proposal substitution. Keep access local. Select the concrete reviewer bootstrap/session mechanism in a subsequent design; do not expose approval routes before it is defined.

This enables a smaller first user-facing application without promising protection from arbitrary malicious processes with the operator's OS privileges. A stolen reviewer credential, code injection into the trusted reviewer, or OS-session compromise can defeat this model. The UI must state that limit. This choice does not authorize weaker scopes, automatic AI approval, remote access or arbitrary execution.

### B. Same-account hostile applications in scope from the first graphical approval release

Require a meaningful boundary even when a requesting application has the same OS account privileges as the human-facing component. A second bearer token alone cannot establish that boundary. First design and validate stronger process/credential isolation and a trustworthy human-presence channel on the selected platform. The UI/approval release must wait for evidence that requesting applications cannot impersonate or tamper with the approver.

This is substantially broader security work and could require platform-specific architecture. It does not authorize deep OS integration or any executor by itself; those still require explicit designs. Do not claim this guarantee based on loopback binding, an approval button, browser origin checks, or a separate secret alone.

## Recommendation and decision gate

Choose A for the first graphical approval release while keeping B as an explicit future assurance target, unless protection from malicious same-account applications is required for the first usable product. Both choices preserve application intent != human permission at the supported boundary; they differ in which attacker can compromise the trusted approval channel.

The owner must choose this scope before implementation of a new human approval channel. This follows the architecture's requirement for product-owner input on material changes to human authority. No option is selected by publishing this proposal. Ordinary improvements within the existing trusted terminal and application API remain authorized.

## Required acceptance evidence after a decision

Test application credentials attempting approval, admin credentials attempting to stand in for human consent, cross-application access, changed proposals, replay, race conditions with revocation/cancellation/expiry, denied strong confirmation, audit failure, disconnect/restart behavior, and preservation of the legacy contract. For B, also demonstrate resistance to the selected same-account attacker; protocol tests alone cannot establish that claim.
