# Persistent registration and authority lifecycle

Status: PROPOSED. Persistence and startup unlocking are not implemented. Product-owner input is required on the lifetime/activation of saved authority.

## Current behavior and motivation

Today the registry lives in memory. Stopping the service discards registrations, credential hashes, scope grants and trust settings. Applications must be provisioned again. The new desktop can review proposals and inspect credential-free registration summaries, but cannot restore them. This makes repeated use inconvenient and prevents the planned persistent-policy product experience.

Persisting the registry would extend the lifetime of application credentials and delegated authority beyond a service session. Restoring a scope such as files.read could allow automatic checks after restart without a fresh human interaction. That is a change to human-authority lifetime, even though consequential actions would still require their existing approval/strong-confirmation rules. It must be explicit rather than an incidental file-storage implementation detail.

## Constraints already accepted

- Preserve application/AI intent != human permission and authorization-only behavior.
- Use prototype A: trusted local Windows operator environment. Do not claim resistance to hostile same-account processes. B's stronger isolated authority component remains a required milestone before strong local enforcement claims.
- Keep application credentials, trusted authorization context and human approval authority separate. Store only credential hashes for application authentication; never recover or expose the originally issued application credential from the store.
- Keep existing in-memory construction available for tests/embedded users. Treat persistent desktop/service mode as a documented opt-in initially, without changing the application /check or SDK decision contract.
- Persistence must fail closed on corruption, unsupported schema, unavailable storage or failed writes. Do not silently create an empty replacement that revives revoked credentials or drops policy restrictions.
- Persist a lifecycle change before reporting success. Atomic storage updates, single-writer ownership, recovery and migration must be tested. Keep audit/registry consistency limits explicit; do not claim a transaction spanning independent files without implementing one.
- Do not import untrusted files as authority, provide a network restore API, embed secrets in audit messages, or turn an application credential into a human unlock mechanism.

## Decision required: when does saved authority become active?

### A. Operator unlock after every restart (recommended first persistent release)

Restore registrations into a locked state. Existing application credentials and saved grants do not yield usable authorization until the trusted local operator explicitly enables the saved authority for the current service session. The desktop must show what is being enabled and its limitations; automatic launch alone is not unlocking. No application/admin HTTP token substitutes for that human action. A locked service must fail closed with a documented unavailable response, without prompting the application or silently retrying.

Unlocking activates the saved grants; it does not approve individual consequential requests. Existing policy, scope and strong-confirmation checks still apply to every proposal. Revocation remains durable. Under prototype A, this is an explicit trusted-operator action, not OS-backed human-presence proof or protection against malicious same-user processes. The future B implementation must move that authority to the isolated human channel.

Benefit: saving registrations does not silently make a service restart a renewal of unattended authority. Cost: unattended startup waits for the operator, and unlocking a saved broad grant is itself a consequential delegation that must be presented clearly.

### B. Automatically restore previously granted authority

Saved registrations/scopes/trust become active when the opted-in service starts. The original grant persists until explicit durable revocation or a future defined expiry mechanism. The operator must understand this lifetime when granting authority or enabling persistence. Automatic read-like proposals may then be allowed without a new interaction after restart; consequential actions retain the existing approval requirements.

Benefit: continuity for unattended work within existing grants. Cost: restarting does not suspend that delegation; compromised retained credentials can continue requesting checks. This choice is not permission to add executors or extend any scope.

## Storage design after the activation decision

Use a versioned store interface below ApplicationRegistry so the policy core, credential-free desktop summaries and application API do not depend on the backend. Select and validate the Windows file/access-control and OS-protection mechanisms explicitly before enabling persistence. Credential hashes do not need to be recoverable secrets, but policy/grant integrity and access control still matter. Prototype A cannot promise same-user tamper resistance.

The first implementation must define single-writer behavior, registration/update/revoke/rotate commit ordering, startup validation and corruption recovery. Recovery must never silently undo revocation. Backups/restores need an explicit authority rollback policy; they should not be added as a convenience shortcut. B can replace storage custody and unlock attestation behind these interfaces without redefining application permission checks.

Temporary/resource-specific grants, clock/expiry semantics, cross-device recovery and automatic restoration of pending approvals remain separate future work. Do not infer any of them from approval to persist the current registry.

## Acceptance evidence

Test restart behavior in the chosen activation mode, durable revocation and credential rotation, invalid/corrupt/future-version stores, write failure before success, simultaneous writers, unchanged application API behavior, locked/unavailable failure handling if selected, and separation of application/admin credentials from human activation. Verify no raw application credential is stored or sent to the GUI. Document residual filesystem and power-loss limits.

No option is selected by publishing this proposal. The product owner must choose the activation/lifetime behavior before implementation changes the current service-session authority boundary.
