# SecurityBrightness

SecurityBrightness is a conservative permission and audit layer for application actions.

## Current pipeline

1. An application submits an action and target.
2. A validated `SecurityEvent` is created with a unique request ID and UTC timestamp.
3. The policy engine returns `allow`, `deny`, or `ask`.
4. `ask` decisions require an approval provider.
5. The final decision is written to the audit log with its policy rule, source, reason, and request ID.
6. The application receives a structured response.

SecurityBrightness makes decisions only. It does **not** execute requested file or system operations.

## Python API

```python
from core.api import check_action

result = check_action("read", "example.txt")
print(result)
```

Responses contain `request_id`, `timestamp`, `decision`, `decision_source`, `policy_rule`, `human_control`, and `reason`.

## Local service

Run from the repository root:

```bash
python -m core.service
```

The service binds to `127.0.0.1:8765` only and refuses non-loopback binding. On startup it creates a session token unless `SECURITYBRIGHTNESS_TOKEN` is already set. Keep that token private; `/check` requires it as a Bearer token.

Health check:

```text
GET /health
```

Decision request:

```text
POST /check
Authorization: Bearer <session-token>
Content-Type: application/json

{"action":"read","target":"example.txt","source":"my_app"}
```

Requests are authenticated, size-limited, JSON-only, and reject unknown fields. Actions requiring approval use the configured approval provider. The default provider asks in the service terminal. The server processes requests serially so terminal approval prompts cannot overlap.

A standard-library client is available in `core.client`; pass it the session token printed by the service.

## Policy baseline

- ordinary read/open/view requests can be automatically allowed;
- sensitive targets require explicit approval;
- write/delete/execute-style requests require explicit approval;
- explicitly blocked security-bypass actions are denied;
- unknown actions require explicit approval.

## Tests

Run the complete automated suite from the repository root:

```bash
python -m unittest discover -s core -p "test_*.py" -v
```

Tests cover policy decisions, approval/denial, event validation, the Python API, local HTTP service, and audit logging.


## Human control

SecurityBrightness separates an application's proposed intent from the human's authority to approve it. Human-control classifications are `automatic`, `notify`, `approval`, `strong_confirm`, and `blocked`. High-impact actions such as sending messages, publishing, sharing, purchases, payments, money transfers, and account changes require stronger human confirmation. The requesting application cannot approve its own request.
