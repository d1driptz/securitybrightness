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

Credentials can be rotated and applications can be revoked. Scopes and trust can be changed by the registry. External HTTP callers cannot self-assert protected fields such as `application_id`, `authenticated`, `trust`, or `granted_scopes`.

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

`GET /health` provides the minimal health endpoint. `POST /check` is authenticated, size-limited, JSON-only, and rejects unknown fields.

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

SecurityBrightness does not yet execute authorized actions. The audit file is useful for traceability but is not tamper-proof. The application registry is not persistent and does not yet use the operating system credential store. The direct Python API remains available for trusted/in-process callers; the HTTP service is the stronger boundary for external applications because it derives registered identity and scopes server-side.

## Tests

Run the complete automated suite from the repository root:

```bash
python -m unittest discover -s core -p "test_*.py" -v
```
