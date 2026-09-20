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

## Registered application SDK

New application/AI integrations can use `core.sdk.ApplicationClient` with an application credential. It returns an immutable `AuthorizationResult` with explicit `allowed`/`require_allowed()` handling, request IDs, scope information, action category, effective risk level, and human-review explanation. The SDK never executes, approves, or automatically retries proposals; it uses the local service without redirects or environment proxies.

```python
from core.sdk import ApplicationClient

client = ApplicationClient("notes-assistant", application_credential)
result = client.check("read", "notes.txt", details={"purpose": "summarize notes"})
print(result.allowed, result.reason, result.request_id)
```

The service and SDK share a discoverable catalog in `core.actions`: `describe_action(name)` and `list_actions()`. It preserves existing action scopes and approval requirements. Effective risk (`low`, `elevated`, `high`, `prohibited`) reflects the actual human-control classification, not a permission grant or an independent harm score. The API and audit records now include the additive fields `action_category`, `risk_level`, and `review_reason`.

See [Application and AI integration](docs/application-integration.md) for provisioning, human approval, timeout handling, tool-adapter boundaries, and the authorization-only `python -m examples.authorize` example. Legacy APIs remain available. A separate distributable SDK package and asynchronous human-review workflow are not implemented yet.

## Local service

Run from the repository root:

```bash
python -m core.service
```

The service binds to `127.0.0.1:8765` and refuses non-loopback binding. A service session token is generated unless `SECURITYBRIGHTNESS_TOKEN` is set.

`GET /health` provides the minimal health endpoint. `POST /check` is authenticated, size-limited, JSON-only, and rejects unknown fields. All POST routes use the same strict UTF-8 JSON decoder: duplicate object keys (at any depth), non-finite numbers, invalid Unicode, and nesting beyond 32 levels are rejected before authorization or registry mutation. Requests require one decimal `Content-Length` of 1 to 65,536 bytes. Duplicate security/framing headers, folded or malformed headers, transfer/content encodings, and `Expect` are rejected. Only UTF-8 JSON is supported.

A five-second absolute read deadline covers the request line, headers, and body, including trickled uploads. Expired or incomplete requests cannot reach authorization. Expiry may return HTTP 408 or close/reset the connection before a response is possible. Responses close the connection; early rejections use a size/time-bounded drain to improve delivery on Windows. The deadline ends when the full body is received, so it does not set a human-approval deadline.

`POST /register`, `/rotate`, `/revoke`, and `/permissions` require the service session/admin token. Application credentials cannot use these administrative endpoints. Administrative requests must omit `X-SecurityBrightness-App`; even an empty application header selects application mode for `/check` and never falls back to the admin token. Configured session tokens must be nonempty printable ASCII without spaces; malformed/non-ASCII supplied credentials fail authentication.

Registered applications authenticate with a Bearer credential plus the `X-SecurityBrightness-App` header. Their identity, trust, scopes, and request source are derived by the service rather than accepted from application JSON. Supplying an application ID with an invalid credential fails authentication instead of falling back to the service session token.

The standard-library client in `core.client` supports both registered-application credentials and the legacy service session token.

## Permission scopes

Actions map to explicit scopes such as `files.read`, `files.write`, `files.delete`, `process.execute`, `communications.send`, `payments.purchase`, and account-management scopes. Identified applications lacking the required scope are denied before human approval is requested.

## Human control

Human-control classifications are `automatic`, `notify`, `approval`, `strong_confirm`, and `blocked`. High-impact actions such as sending messages, publishing, sharing, purchases, payments, money transfers, and account changes require stronger human confirmation. The requesting application cannot approve its own request. Approval providers must return an actual boolean; truthy strings/numbers are errors. Providers handling strong confirmation must accept the `strong` keyword. Legacy one-argument providers remain supported for ordinary approval only. Invalid provider contracts raise `ApprovalProviderError` rather than grant permission; HTTP maps that error to 503. EOF from the approval channel denies the action, provider implementation exceptions are not retried, and terminal labels escape caller-controlled control characters.

## Policy baseline

- ordinary read/open/view requests can be automatically allowed when authorization requirements are satisfied;
- sensitive targets require explicit approval;
- write/delete/execute-style requests require explicit approval;
- explicitly blocked security-bypass actions are denied;
- unknown actions require explicit approval.

## Security boundaries and current limitations

SecurityBrightness does not yet execute authorized actions. The audit file is useful for traceability but is not tamper-proof. Sensitive detail keys containing normalized credential/password/secret/token/authorization/private-key/API-key/cookie/session-ID markers are recursively redacted, including camelCase and punctuation variants. This conservative matching can also redact benign fields such as token counts; it cannot detect secrets embedded in free text or unrelated fields.

Audit updates are serialized between threads in the same process. Each write uses a unique temporary file, flushes and synchronizes it, then atomically replaces the log. Malformed, ambiguous, unreadable, or non-array audit history is preserved and raises `AuditLogError`; it is never silently reset. A persistence failure prevents a successful authorization response (HTTP 503 `audit_unavailable`). An operator must repair or archive a damaged log deliberately before checks can resume. This is a security-related compatibility change from replacing corrupt history.

The application registry is not persistent and does not yet use the operating system credential store. The direct Python API remains available for trusted/in-process callers. Authenticated identity and scopes can now be passed separately through an internal `AuthorizationContext`, rather than requiring transport authentication data to be authored directly in caller event details. The HTTP service constructs this context from the registry after credential verification.

Known remaining weaknesses requiring further batches:

- The trusted Python API still accepts legacy identity fields in event details; it must never be exposed directly to untrusted callers. `AuthorizationContext` is a trusted internal object, not a proof of authentication.
- The service remains single-threaded. The read deadline bounds one slow request, but repeated connections, queued connections, and pending terminal approval can still delay others. There is no rate limiting or independent approval UI. Extremely large/rejected uploads may still end in a connection reset.
- Approval providers are trusted in-process code. Accepting `strong=True` cannot prove that a provider actually obtained human confirmation; the service does not sandbox providers or bind an approval cryptographically to later execution.
- Audit logs are not tamper-proof, have no rotation/size cap, and rewrite the entire history on each event. The lock does not coordinate multiple processes; use a single writer. Atomic replacement and file synchronization do not guarantee directory durability across every power-loss scenario. Free-text secrets can leak, and lifecycle changes are not audited.
- Policies infer sensitivity from action/target labels, scopes are not resource-specific, and authorization is not bound to a later execution. Registry locking does not make an entire authorization/approval flow atomic with revocation.
- The standalone `index.html` scanner and the bundled SoulScript ZIP are separate artifacts, not authorization enforcement components. The core unittest suite does not test their behavior.

## Tests

Run the complete automated suite from the repository root:

```bash
python -m unittest discover -s core -p "test_*.py" -v
```
