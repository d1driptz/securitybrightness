# SecurityBrightness

SecurityBrightness is a conservative permission and audit layer for application actions.

## Current pipeline

1. An application submits an action and target.
2. A validated `SecurityEvent` is created with a unique request ID and UTC timestamp.
3. The policy engine returns `allow`, `deny`, or `ask`.
4. `ask` decisions require an approval provider.
5. The final decision is written to the audit log with its policy rule, source, reason, and request ID.
6. The application API returns a structured response.

SecurityBrightness currently makes decisions only. It does **not** execute requested file or system operations.

## Example

```python
from core.api import check_action

result = check_action("read", "example.txt")
print(result)
```

A response contains:

- `request_id`
- `timestamp`
- `decision`
- `decision_source`
- `policy_rule`
- `reason`

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

The tests cover policy decisions, permission approval/denial, event validation, application API responses, and audit logging.
