# SecurityBrightness

SecurityBrightness is a conservative authorization and human-control layer for application and AI actions.

It separates an application's proposed intent from the human authority required for consequential actions. SecurityBrightness currently makes authorization decisions only; it does **not** execute requested file, process, payment, communication, or system operations.

## Current pipeline

```text
Application / AI
        |
Application credential
        |
SecurityBrightness application registry
        |
Server-derived identity + permission scopes
        |
Security policy
        |
Human Control
        |
Human approval / strong confirmation when required
        |
Final authorization
        |
Audit record + structured response
```

Every event receives a unique request ID and UTC timestamp. Decisions record their source, policy rule, human-control level, application identity/trust context, required scope, and whether that scope was granted.

## Application identity and credentials

Applications can be registered with `ApplicationRegistry`. Registration issues a random credential and stores only its SHA-256 hash in the current in-memory registry. A registration also owns its granted scopes and trust setting.

Credentials can be rotated and applications can be revoked. Scopes and trust can be changed by the registry. The local service exposes admin-token-protected application lifecycle endpoints: `POST /register` issues a credential, `POST /rotate` replaces it, `POST /revoke` removes an application, and `POST /permissions` changes its scopes/trust. External HTTP callers cannot self-assert protected fields such as `application_id`, `authenticated`, `trust`, or `granted_scopes`.

Registry inputs are validated before mutation: application IDs must be nonempty strings, trust must be a real boolean, and scopes must contain nonempty strings (a mapping or single string is rejected). Scope names retain case/whitespace normalization, custom names, and the explicit `*` wildcard. `None` clears scopes; an omitted scopes field leaves them unchanged.

`ApplicationRegistry.update_permissions(application_id, scopes=..., trusted=...)` validates the whole update and atomically replaces the registration under a process-local lock. The HTTP `/permissions` endpoint uses this operation. Registration, credential rotation, revocation, and reads share the lock. Returned registrations are immutable snapshots with frozen scope sets; use registry methods to change them. A previously authenticated snapshot is not retroactively revoked, so consumers must authenticate each new request.

Security-related compatibility changes: values such as `trusted="false"`, numeric application IDs, non-string/blank scope entries, and mutation of returned registration objects are now rejected. Valid existing credentials and normal lifecycle requests retain their behavior. `AuthorizationContext` validates direct construction as well as its authenticated factory, and rejects non-dictionary caller details.

The registry is currently **in memory**. Registrations therefore do not survive a service restart. Persistent OS-backed credential storage is future work.

## Python API

```python
from core.api import check_action

result = check_action("read", "example.txt")
print(result)
```

Responses include `request_id`, `timestamp`, `decision`, `decision_source`, `policy_rule`, `human_control`, `application_id`, `application_trust`, `authenticated`, `required_scope`, `scope_granted`, and `reason`.

## Local service

Run from the repository root:

```bash
python -m core.service
```

The service binds to `127.0.0.1:8765` and refuses non-loopback binding. A service session token is generated unless `SECURITYBRIGHTNESS_TOKEN` is set.

`GET /health` provides the minimal health endpoint. `POST /check` is authenticated, size-limited, JSON-only, and rejects unknown fields. `POST /register`, `/rotate`, `/revoke`, and `/permissions` require the service session/admin token. Application credentials cannot use these administrative endpoints.

Registered applications authenticate with a Bearer credential plus the `X-SecurityBrightness-App` header. Their identity, trust, scopes, and request source are derived by the service rather than accepted from application JSON. Supplying an application ID with an invalid credential fails authentication instead of falling back to the service session token.

The standard-library client in `core.client` supports both registered-application credentials and the legacy service session token.

## Permission scopes

Actions map to explicit scopes such as `files.read`, `files.write`, `files.delete`, `process.execute`, `communications.send`, `payments.purchase`, and account-management scopes. Identified applications lacking the required scope are denied before human approval is requested.

## Human control

Human-control classifications are `automatic`, `notify`, `approval`, `strong_confirm`, and `blocked`. High-impact actions such as sending messages, publishing, sharing, purchases, payments, money transfers, and account changes require stronger human confirmation. The requesting application cannot approve its own request.

## Policy baseline

- ordinary read/open/view requests can be automatically allowed when authorization requirements are satisfied;
- sensitive targets require explicit approval;
- write/delete/execute-style requests require explicit approval;
- explicitly blocked security-bypass actions are denied;
- unknown actions require explicit approval.

## Security boundaries and current limitations

SecurityBrightness does not yet execute authorized actions. The audit file is useful for traceability but is not tamper-proof. Sensitive detail keys such as credentials, passwords, secrets, tokens, authorization values, and private keys are recursively redacted before audit records are written. The application registry is not persistent and does not yet use the operating system credential store. The direct Python API remains available for trusted/in-process callers. Authenticated identity and scopes can now be passed separately through an internal `AuthorizationContext`, rather than requiring transport authentication data to be authored directly in caller event details. The HTTP service constructs this context from the registry after credential verification.

Known remaining weaknesses requiring further batches:

- The trusted Python API still accepts legacy identity fields in event details; it must never be exposed directly to untrusted callers. `AuthorizationContext` is a trusted internal object, not a proof of authentication.
- HTTP parsing is duplicated and lacks strict duplicate-header/JSON-key handling, finite-number enforcement, and bounded read timeouts. This single-threaded service can be stalled by a client or a pending terminal approval. Early rejection without reading a request body can cause a connection reset on Windows instead of a readable error response.
- Approval-provider return values are interpreted by truthiness, and legacy providers need not support strong confirmation. The approval display needs protection against caller-supplied terminal control characters.
- Audit redaction recognizes only listed exact keys; free-text secrets and key variants may leak. Malformed audit history is replaced, and concurrent writers are not coordinated. Lifecycle changes are not audited.
- Policies infer sensitivity from action/target labels, scopes are not resource-specific, and authorization is not bound to a later execution. Registry locking does not make an entire authorization/approval flow atomic with revocation.
- The standalone `index.html` scanner and the bundled SoulScript ZIP are separate artifacts, not authorization enforcement components. The core unittest suite does not test their behavior.

## Tests

Run the complete automated suite from the repository root:

```bash
python -m unittest discover -s core -p "test_*.py" -v
```
