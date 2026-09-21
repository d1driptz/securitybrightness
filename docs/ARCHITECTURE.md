# SecurityBrightness architecture

**Application/AI intent does not equal human permission.**

This document separates the current implementation from the planned architecture and optional future extensions. [Product vision](PRODUCT_VISION.md) explains the purpose; [Current behavior](CURRENT_BEHAVIOR.md) specifies today's service contract; [Application integration](application-integration.md) shows how to use it.

## Current implementation and evidence

The initial inventory below was reviewed against commit `e1144ba42ec1642e96c8d88517a3d8512916f62a`. Keep current-state claims synchronized when code changes; this baseline reference is evidence provenance, not a freeze on development. Tests exercise the stated behavior but do not prove complete security or OS-level enforcement.

| Implemented capability | Code | Evidence and qualification |
| --- | --- | --- |
| Action/target/details events with generated request IDs and UTC timestamps | [events.py](../core/events.py) | [test_events.py](../core/test_events.py). Strings and details types are checked; this is not a rich resource/effect schema. |
| Shared action categories, required scopes, baseline review and reported risk | [actions.py](../core/actions.py), [policy.py](../core/policy.py), [human_control.py](../core/human_control.py), [scopes.py](../core/scopes.py) | [test_actions.py](../core/test_actions.py), [test_policy.py](../core/test_policy.py), [test_scopes.py](../core/test_scopes.py). Sensitivity uses labels/target markers; risk describes review level rather than independently verified impact. |
| Session-only or optional persistent registrations, hashed credentials and lifecycle operations | [registry.py](../core/registry.py), [authority_store.py](../core/authority_store.py) | [test_registry.py](../core/test_registry.py), [test_registry_security.py](../core/test_registry_security.py), [test_persistence.py](../core/test_persistence.py). Immutable snapshots, locked persistent startup, exact-version human unlock and final revalidation. No timestamp expiry or resource constraints. |
| Server-derived application identity and internal authorization context | [service.py](../core/service.py), [authorization.py](../core/authorization.py), [identity.py](../core/identity.py) | [test_service.py](../core/test_service.py), [test_authorization.py](../core/test_authorization.py), [test_identity.py](../core/test_identity.py). HTTP rejects caller-authored identity fields; direct Python APIs still trust in-process callers. |
| Policy denial, missing-scope denial before prompting, approval and strong confirmation | [permissions.py](../core/permissions.py), [approval.py](../core/approval.py) | [test_permissions.py](../core/test_permissions.py), [test_approval.py](../core/test_approval.py), [test_approval_security.py](../core/test_approval_security.py). Terminal review shows proposal context, the permission engine's policy/review explanations, and an unverified requester explanation in both approval modes. Review is synchronous; providers are trusted code, not verified human identity. |
| Optional trusted-operator desktop review | [desktop.py](../core/desktop.py), [review_channel.py](../core/review_channel.py) | [test_review_channel.py](../core/test_review_channel.py), [test_desktop.py](../core/test_desktop.py), [test_sdk.py](../core/test_sdk.py). Credential-free immutable review messages and registration summaries, bounded ephemeral channel, strong confirmation and fail-closed expiry/closure. Trusted local OS session only; no HTTP approval route or isolated Windows broker. |
| Loopback HTTP checks and admin-protected lifecycle endpoints | [service.py](../core/service.py), [json_input.py](../core/json_input.py) | [test_http_security.py](../core/test_http_security.py), [test_service.py](../core/test_service.py). Strict JSON/framing and bounded request reads; still a single-threaded service. |
| Decision audit with redaction, synchronized temporary writes and fail-closed persistence | [logger.py](../core/logger.py), [security.py](../core/security.py) | [test_logger.py](../core/test_logger.py), [test_audit_security.py](../core/test_audit_security.py). Not tamper-proof, not cross-process coordinated, not a full lifecycle audit. |
| Registered-application SDK, prepared proposal snapshots, explicit decisions and authorization-only example | [sdk.py](../core/sdk.py), [proposal.py](../core/proposal.py), [api.py](../core/api.py), [example](../examples/authorize.py) | [test_sdk.py](../core/test_sdk.py), [test_proposal.py](../core/test_proposal.py), [test_api.py](../core/test_api.py). No executor, automatic retry, remote endpoint support, signed capability or separately published SDK package. |

### Current request flow

```text
Application / AI adapter proposes an action and target
    -> application credential + app ID over local HTTP
    -> service verifies registry credential and derives identity/scopes
    -> internal AuthorizationContext + caller's ordinary details
    -> policy and Human Control classification
    -> policy denial / scope denial / trusted terminal/desktop approval as applicable
    -> final decision
    -> successful audit persistence
    -> structured response to application
    -> END of SecurityBrightness responsibility today; no action is executed
```

`GET /health` is minimal health information. `POST /check` is the decision endpoint. `/register`, `/rotate`, `/revoke` and `/permissions` require the service/admin token and reject application-mode headers. No HTTP endpoint accepts a human approval or provides pending-review state.

The registered SDK sends an application credential, not administrative authority. Default session-only mode retains the privileged admin-token/no-application compatibility path without registered scopes. Opt-in persistent mode rejects that path so it cannot bypass inactive grants. It is not the model for untrusted applications.

### Current trust boundaries

| Input or component | What may be trusted today | What must not be inferred |
| --- | --- | --- |
| Caller action/target/details | A proposal to classify and review | That labels describe the actual downstream effect, or that an `approved` flag is human permission |
| Verified application credential | Possession of the registered application's bearer secret and its current registry snapshot | OS process identity, code integrity, human identity, or permission outside granted scopes |
| Service/admin token | Privileged local lifecycle administration and legacy checks | A separate authenticated human session or an auditable human consent record |
| Internal AuthorizationContext | Context supplied by trusted integration code; constructed by HTTP after credential verification | A cryptographic credential or protection from hostile code in the same Python process |
| Approval provider / service terminal or desktop | Trusted in-process approval channel with a boolean contract; strong requests require provider support | Proof that an arbitrary custom provider actually obtained informed human consent |
| Audit file | Locally persisted decision history with some corruption/failure handling | Tamper resistance, comprehensive secret detection, multi-process safety or complete administrative history |
| SDK result | A validated decision response from the configured local service | An unforgeable capability, permission for a different action, or evidence that an operation ran |

Service/API calls carrying an `AuthorizationContext` now keep it on `SecurityEvent.authorization_context`, separate from caller details. Identity, scopes and identity participation use that context exclusively when present. Mixed context and legacy identity details are rejected at construction. `AuthorizationContext.apply` remains an explicit legacy trusted-Python adapter; no-context Python calls still support legacy detail fields. This is data separation, not protection from hostile code in the same process.

Registered HTTP requests capture registry and activation identity. After review, final revalidation and audit persistence serialize with registry changes; stale, rotated, revoked or locked authority cannot return authorization. Lock-and-reunlock does not revive the old request. Previously committed decisions are not retroactively withdrawn or bound to downstream effects. Trusted embedded Python callers must explicitly pass a registry authorization lease guard rather than infer validity from a manually constructed context.

The `notify` level is classification metadata only; there is no separate notification delivery mechanism. The standalone [browser scanner](../index.html) and the bundled SoulScript ZIP are separate artifacts, not the human-control application or an enforcement layer. Core tests do not validate them as such.

## Planned architecture: intended responsibilities, not implemented modules

The independent [File Security contract](file-security.md) in `file_security/text_analysis.py` now analyzes supplied bounded immutable bytes with three literal private-key-header rules. It imports no core authority components and returns no authorization decision. It has no acquisition, desktop/HTTP integration or OS isolation; tests live in `core/test_file_security.py`. This is an analysis foundation, not the planned installed security capability.

```text
Integrated application / AI tool adapter
    -> structured proposal contract and authenticated application/delegation identity
    -> policy, contextual risk and constrained-grant evaluation
          <-> persistent protected policy/credential/grant store
          <-> human-control workflow and user-facing SecurityBrightness application
    -> decision tied to the reviewed proposal and current authority
    -> controlled enforcement point verifies applicability before any external effect

Audit and explanations span proposal, grant, review, revocation and outcome transitions.
Any future execution broker sits beyond the authorization service in a separate boundary.
```

The diagram describes responsibilities and data flow, not deployment choices, existing endpoints or a promise to add an executor. A user interface is not automatically an approval authority just because it can call an API.

### Structured proposal and contextual classification

Define a versioned action contract separating the intended operation, affected resources, parameters/effects, explanation and provenance from authenticated identity, granted authority and human decisions. Useful context may include sensitivity, recipients, amount/currency, reversibility, external visibility and cumulative effects. Obtain trustworthy context from adapters or controlled resource boundaries where possible; caller claims can inform review but cannot lower mandatory safeguards by assertion.

Unknown or missing material context should be surfaced as uncertainty and handled conservatively. Request identity and immutable proposal snapshots should allow the same content to be shown to the human, audited, and checked at the enforcement point. An updated target, recipient or amount must not silently reuse old approval. The precise schema and compatibility/migration rules remain to be designed.

### Scoped authority and persistent state

Separate a durable grant from a request-specific decision and from a credential. Planned grants identify who may do what, on which resources, under what constraints, and for how long. Expiry, single-use limits, explicit revocation and revalidation must have well-defined clocks and concurrency behavior. A broad natural-language task is not a wildcard grant.

Storage should protect credentials and policy integrity, support migrations/recovery, and avoid exposing administrative or human authority to requesting applications. OS-backed secret storage is a planned requirement to evaluate, not a current implementation or a selected backend. Persistent grants, expiry semantics and human identities require an explicit design decision before release.

### Human-control workflow and application

Retain a proportionate spectrum: automatic decisions within legitimate delegated authority, useful notifications, explicit approval, strong confirmation, and policy denial. A review should identify the requesting application, proposed effects, applicable limits, why review is needed, and what approval would permit. Display requester-authored explanations as untrusted context. Never silently expand permission to avoid repeated prompts.

The desktop implements proposal review, credential-free authority inspection, exact-version unlock and confirmed revocation. Broader management/history remains planned. A future asynchronous workflow needs explicit states, ownership, duplicate handling and disconnect recovery. There are no application-facing lifecycle endpoints for reviews now; the desktop channel is ephemeral inside the trusted process. Establish separate authenticated human authority before adding an approval API. A client timeout never counts as consent or triggers automatic resubmission.

### SDK/API and enforceable integrations

Keep the SDK simple for integrators while making decisions, denial, uncertainty and compatibility explicit. An adapter must map the actual operation to the proposal rather than relay an AI-selected harmless label. Tests should cover useful end-to-end workflows and attempts to bypass their boundaries.

An enforcement point is the component that controls access to the real operation/resource and can refuse it. To govern an action, the application must integrate with a point SecurityBrightness controls or with a trusted adapter that enforces its authority decisions. Mere installation, a preflight check, a displayed badge, or an ignored SDK result is not enforcement. If a third-party application can bypass the gate and access the resource directly, SecurityBrightness does not control that path.

Planned integration contracts must define which effects are mediated, who owns the resource authority, how proposal/decision applicability is checked, and what happens on expiry, revocation, replay or failure. Start with explicit narrow integrations and honest coverage claims; do not claim control over arbitrary applications.

### Audit and explanations

Record relevant proposal, policy/grant version, review, human decision, revocation and enforcement transitions without leaking unnecessary sensitive contents. Integrity, retention, access control and error recovery must be designed alongside persistent storage and workflows. Explanations should describe evidence and limits, not imply that an AI risk label or passing tests proves safety. Current audit records are only decision records, not evidence of execution.

## Boundary for a possible future capability/execution layer

Authorization-only remains the current architectural constraint. Introducing execution requires a separate approved architecture decision and threat model. If considered, require a separately isolated broker, a narrow allowlisted capability interface, explicit operations and resource limits, authenticated requesters, expiry/revocation/replay rules, and audit linkage to the exact reviewed proposal. Avoid ambient administrative authority.

No unrestricted shell, OS command runner, general file operator, payment or communication executor may be inferred from this roadmap. Arbitrary application/AI intent must never become unrestricted OS/shell execution. Existing action names such as `execute` or `transfer_money` are labels evaluated for permission, not implementations of those effects.

## Longer-term possibilities, not commitments

Platform/OS mediation, sandboxes, service-specific brokers, additional SDK languages, cross-device authority and organization policies may be investigated later. Deeper OS integration is not implemented and no particular mechanism is selected. Each extension needs its own enforceability analysis: which applications/resources are covered, what bypass remains possible, and what trust is added. A universal OS security boundary cannot be claimed on the strength of the current local HTTP service.

## Development sequence and decision gates

1. Improve the existing human-review experience and proposal/explanation contract without granting new authority. Validate it through the SDK and current terminal provider.
2. Define structured proposal identity and compatibility before introducing durable/asynchronous review. Bind human review to the actual content and define safe retry/cancellation behavior.
3. Design granular grants and persistent secure state, including revocation/expiry consistency and recovery. Choose storage and human identity mechanisms explicitly.
4. Build the user-facing application on those authority boundaries, then demonstrate controlled narrow integrations with honest enforcement coverage.
5. Consider any isolated execution/capability broker or deeper platform integration only through its own architectural decision.

These are dependency-based priorities, not dates or claims of implementation. Evolve the sequence when evidence warrants it. Material changes to human authority, delegation, persistent grants, network exposure or execution require a recorded design and product-owner input; normal implementation within agreed boundaries can proceed autonomously.

Every substantial batch should identify the capability advanced, preserve compatible behavior unless security requires a documented change, test meaningful regressions and workflows, run the complete suite, review the diff, update implementation/evidence documentation, and verify the published branch. See [current service behavior](CURRENT_BEHAVIOR.md) for current limitations rather than interpreting the plan as a security guarantee.

## Architecture decisions

[Proposal lifecycle and human authority](decisions/0001-proposals-and-human-authority.md) records the accepted A prototype threat model and required migration milestone B. Trust the local operator environment for the first desktop reviewer; do not claim protection against hostile same-user processes. The versioned/asynchronous application contract remains future design.

[Persistent registration and authority lifecycle](decisions/0002-persistent-authority-lifecycle.md) records the accepted explicit-unlock rule. The implemented opt-in [persistent authority](persistent-authority.md) store restores all grants inactive. Desktop controls inspect scope/lifetime/state, confirm exact-version unlock, lock all and revoke inactive grants. [authority_store.py](../core/authority_store.py) and [test_persistence.py](../core/test_persistence.py) provide storage and regression evidence. Default registries remain session-only; OS-protected storage custody and recovery are not implemented.

## Expanded platform responsibilities (planned, not current enforcement)

Trust does not imply authority, including for SecurityBrightness itself. Keep these responsibilities separate:

| Component | Intended authority | Authority it must not inherit |
| --- | --- | --- |
| Policy/authorization core | Evaluate authenticated proposals and grants | Arbitrary execution or human impersonation |
| Human Review/authentication | Obtain bounded human decisions through a trusted channel | Application credentials as human proof |
| Integrated enforcement adapter | Mediate its explicitly controlled resource boundary | Unrestricted OS authority or universal third-party control |
| Device Security | Observe/assess specifically authorized signals | Automatic control over observed applications or execution |
| File Security | Analyze explicitly supplied files within a defined analysis boundary | Grant editing, human approval, unsafe execution of samples |
| Security Assistant | Read permitted evidence, explain, navigate and propose | Approve, silently change policy, possess universal admin authority |
| Management | Explicit lifecycle operations in its own authority boundary | Substitute administrative access for human consent/unlock |
| Audit/history | Persist/expose authorized security evidence | Treat unverified assertions as proof or leak credentials |
| Update/recovery | Future narrowly scoped authenticated maintenance | Unsigned updates, authority rollback or unrestricted shell access |

These are design responsibilities, not a claim that the current Python process already isolates them. Prototype A relies on trusted in-process components. Future isolation should limit compromise propagation; B, privileged monitoring, OS enforcement, human authentication and security-sensitive model integrations require explicit owner-approved designs.

Integrated application protection and Device Security are distinct. Represent observed, integrated and genuinely enforced coverage honestly. The current scanner must be inspected before reuse, and no detection claim is justified merely by its UI. Ordinary and AI applications share the same intent/authority separation. Existing application protections should remain complementary.

Persistent grants must start inactive, show stored versus active state and applicable lifetime, and be revocable while inactive. Unlock is a trusted human action, never a restart/admin/application/caller flag. Before final authorization, revalidate current authority after review so rotation, revocation, changes, expiry or locking cannot resurrect stale grants. No grant record or approval permits execution by this core.
