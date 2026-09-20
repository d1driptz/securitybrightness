# Application and AI integration

This guide covers implemented integration behavior. See [Product vision](PRODUCT_VISION.md) and [Architecture](ARCHITECTURE.md) for the planned product and trust boundaries.

SecurityBrightness receives a proposal and returns an authorization decision. It never runs the requested action. The application's intent, generated text, `approved` flags, and local catalog metadata cannot grant human permission.

## Provision a registered application

Run `python -m core.service` in a trusted terminal, or `python -m core.desktop` for the optional [desktop reviewer](desktop-review.md). An administrator uses `POST /register` with the service token (no application header):

```http
POST /register
Authorization: Bearer <service-admin-token>
Content-Type: application/json

{"application_id":"notes-assistant","scopes":["files.read","communications.send"],"trusted":false}
```

Give the returned application credential and ID to the application. Keep the admin token out of the application/AI process and prompts. Registration, scope changes, rotation, and revocation remain administrator operations. The SDK intentionally exposes no administrative methods. The current registry is in memory, so re-provision after restarting the service.

## Submit a proposal

Use this repository on the Python import path (there is no separately published package yet). Both service and SDK must include the action metadata introduced with this SDK.

```python
import os
from core.sdk import ApplicationClient, SDKError

client = ApplicationClient(
    "notes-assistant",
    os.environ["SECURITYBRIGHTNESS_APP_CREDENTIAL"],
    timeout=60,
)

try:
    result = client.check("read", "notes.txt", details={"purpose": "summarize my notes"})
except SDKError as error:
    print(error.code, error.status, error.outcome_unknown)
else:
    print(result.request_id, result.action_category, result.risk_level)
    print(result.reason)
    if result.allowed:
        print("Authorized proposal; no action has been performed.")
    else:
        print("Denied proposal; stop this request.")
```

`result.require_allowed()` returns the result or raises `ActionDenied` with the denied result attached. Use `result.allowed`, not `if result`: implicit truthiness deliberately raises an error. A denied decision is a normal result, distinct from authentication/transport/service failures. Result objects are records, not signed or transferable capabilities.

`ApplicationClient` uses only `127.0.0.1`, disables environment proxies and redirects, validates responses, and never retries checks automatically. Set `port` for a non-default local service port. IDs/credentials must be printable ASCII without spaces. Ordinary request details are JSON data; identity, trust, and granted scopes cannot be supplied there. The old `core.client.check` function remains available for compatibility; new application integrations should use the registered SDK.

## Prepare and inspect a proposal

`ActionProposal` snapshots the existing action/target/details contract before sending anything:

```python
from core.proposal import ActionProposal

proposal = ActionProposal("read", "bills", details={"purpose": "summarize due dates"})
preview = proposal.to_payload()  # independent copy; does not grant permission
result = client.check_proposal(proposal)
print(result.allowed, result.request_id)
```

Nested changes to the original details or the preview do not change the prepared request. Construction validates the same JSON, size, text and reserved-authority constraints as `client.check`, which now delegates to this path. Existing `client.check(action, target, details=...)` calls retain their wire format and behavior. A proposal has no credential, approval, server request ID or executor. Each explicit submission is a fresh check against current credentials and scopes; there is no permission cache, automatic retry or idempotency guarantee. A timeout still requires reconciliation before resubmission.

This is a local SDK snapshot, not the planned versioned structured-effects protocol, a signed capability, or a guarantee that the application later performs the reviewed operation. Python code within the same process remains trusted. Do not place secrets in free-text explanations or print sensitive proposal contents indiscriminately.

## Human-control workflow

1. The adapter maps the proposed operation to an action and target, then calls `client.check`.
2. The service authenticates the application and derives its identity/scopes. A missing scope denies immediately, without asking the human.
3. Policy and Human Control classify the proposal. Ordinary reads may be automatic; sensitive reads and modifications require approval; communication/payment/account actions require strong confirmation.
4. The service's trusted terminal (or optional desktop reviewer) requests any required approval, showing the request ID, source, action/target, category, required scope, policy assessment, why human review is required, and any unverified requester explanation. The application's response or an AI-produced `approved=true` value cannot answer it.
5. Only after a final decision and successful audit write does the SDK return a result. This is still authorization only.

For example, with `communications.send` granted, `client.check("send_message", "recipient", details={"purpose":"reply to a question"})` waits for service-side strong confirmation in the selected reviewer. Without that scope it returns a denial without prompting. Do not build a caller-supplied approval endpoint around the SDK.

The SDK's `timeout` is a socket timeout (60 seconds by default), not a human-approval deadline. Invalid responses also leave the outcome unknown. If a transport failure reports `outcome_unknown=True`, the service may still be reviewing or may already have recorded a decision. Treat that as no usable permission, do not perform the proposed action, and do not automatically resubmit it. Inspect the service terminal and audit file to reconcile first; there is no audit-view application yet. There is no asynchronous review queue, cancellation, polling, or idempotency protocol yet.

## Discover actions and interpret risk

```python
from core.actions import describe_action, list_actions

print(describe_action("send_message"))
for item in list_actions():
    print(item.action, item.category, item.required_scope, item.baseline_control)
```

Descriptors are immutable integration metadata, not authorization. Categories are `files`, `process`, `communications`, `data`, `payments`, `account`, `security`, and `unknown`. Aliases preserve existing scope mappings. Unknown actions have their own `action.<name>` scope and require approval; they never inherit automatic access.

Actual results include `action_category`, `risk_level`, and `review_reason` in addition to the existing decision fields. Risk describes the effective human-control classification: `low` for automatic/notify, `elevated` for approval, `high` for strong confirmation, and `prohibited` for policy-blocked actions. Sensitive targets or declared high impact can raise review requirements. Low impact does not lower an action's existing requirements. This is a deterministic review taxonomy, not an independent assessment of real-world harm. A low-risk request can still be denied for missing scopes; only the final `decision` determines authorization.

For AI/tool adapters, the adapter must independently map the actual tool operation to the action and target; do not trust an AI's claim that a consequential operation is merely `read`. Retain the returned request ID with application telemetry. Never cache an allow result as permission for another proposal. Scopes are not resource-specific and decisions are not bound to execution, so this library alone cannot enforce what an application does afterward.

## Runnable example

Set `SECURITYBRIGHTNESS_APP_ID` and `SECURITYBRIGHTNESS_APP_CREDENTIAL` in the application environment, then run:

```bash
python -m examples.authorize read notes.txt --purpose "summarize notes"
```

Exit status is 0 for allow, 2 for deny, and 3 for an input/service error. The example prints the decision and never reads the target file or executes any requested operation.
