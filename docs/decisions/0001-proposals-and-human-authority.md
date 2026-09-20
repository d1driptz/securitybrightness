# Proposal lifecycle and human authority

Status: A ACCEPTED by the product owner; B is a required hardening milestone before claiming strong local enforcement against hostile same-user applications. The lifecycle and versioned schema below remain design direction, not existing application API features.

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

## Accepted decision: A first, with migration to B

### A. Trusted local operator environment first (accepted)

Treat the local operator's OS session and the trusted review component as trusted, as the terminal deployment does today. Build a separately authorized review channel for that operator; isolate its authority from application credentials and protect against hostile API clients, browser-origin attacks if applicable, replay and proposal substitution. Keep access local. Select the concrete reviewer bootstrap/session mechanism in a subsequent design; do not expose approval routes before it is defined.

This enables a smaller first user-facing application without promising protection from arbitrary malicious processes with the operator's OS privileges. A stolen reviewer credential, code injection into the trusted reviewer, or OS-session compromise can defeat this model. The UI must state that limit. This choice does not authorize weaker scopes, automatic AI approval, remote access or arbitrary execution.

### B. Hostile same-account applications (required future hardening milestone)

Require a meaningful boundary even when a requesting application has the same OS account privileges as the human-facing component. A second bearer token alone cannot establish that boundary. First design and validate stronger process/credential isolation and a trustworthy human-presence channel on the selected platform. The UI/approval release must wait for evidence that requesting applications cannot impersonate or tamper with the approver.

This is substantially broader security work and could require platform-specific architecture. It does not authorize deep OS integration or any executor by itself; those still require explicit designs. Do not claim this guarantee based on loopback binding, an approval button, browser origin checks, or a separate secret alone.

## Prototype boundary and migration to B

The owner selected A and requires an explicit migration path to B. The first graphical reviewer runs as a trusted desktop component in the local operator's session. The service passes a credential-free immutable review message across an approval-provider boundary; the reviewer returns only a decision bound to that pending review. Application HTTP requests, application credentials and administrative tokens have no operation for submitting human decisions. Launching the local reviewer is the operator bootstrap; this prototype does not invent a second bearer token as proof of human presence.

Implement the first transport in process, with bounded pending reviews and expiry, while retaining the current synchronous application /check API. Keep GUI dependencies out of the policy and permission engine. Do not expose an HTTP approval endpoint or change application response schemas just to support the GUI. Reviewer failure must never fall back to automatic approval or a hidden terminal prompt.

For B, replace the in-process review transport with an authenticated, isolated Windows component. Preserve the core provider contract and application-facing API. The isolated transport must authenticate both peers, bind decisions to immutable request content and a fresh review identifier, resist replay/substitution, and fail closed on disconnect. Review messages carry display facts, not application credentials, admin tokens, grants or caller-supplied authorization context. Exact IPC, OS identity, secret custody and human-presence mechanisms require a separate threat model and evidence before implementation.

B is a release/claims gate: SecurityBrightness must not claim strong local enforcement against hostile same-user applications until that isolation and human-authority boundary is implemented and tested. A does not protect against same-user process injection, tampering or impersonation. This migration must not add executors or broaden authority; any execution/capability boundary remains a separate architectural decision.

## Required acceptance evidence after a decision

Test application credentials attempting approval, admin credentials attempting to stand in for human consent, cross-application access, changed proposals, replay, race conditions with revocation/cancellation/expiry, denied strong confirmation, audit failure, disconnect/restart behavior, and preservation of the legacy contract. For B, also demonstrate resistance to the selected same-account attacker; protocol tests alone cannot establish that claim.
