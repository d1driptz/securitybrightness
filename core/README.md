# SecurityBrightness Core

The core authorizes proposed actions; it does not execute them. Application/AI intent does not equal human permission.

The HTTP service authenticates credentials through `ApplicationRegistry`, constructs an internal `AuthorizationContext`, then calls the Python API. Events pass through policy, identity/scope checks, Human Control, optional terminal approval, and audit logging. The core remains independent of the standalone browser scanner.

Registry records are immutable snapshots. Use `register`, `rotate_credential`, `revoke`, `set_scopes`, `set_trusted`, or `update_permissions` to change state. Combined permission updates validate every supplied field before publishing one replacement under a process-local lock. Authenticate again for each new request; older snapshots are not revocation handles.

Application IDs must be nonempty strings, trust/authentication flags must be booleans, and scope collections must contain nonempty strings. String coercion and mapping-based scope grants are rejected. `AuthorizationContext` is for trusted code only. Legacy in-process event details can still contain authorization fields and are not an external authentication boundary.

See the root README for the HTTP contract, compatibility changes, and remaining security limitations.

Run from the repository root:

```bash
python -m unittest discover -s core -p "test_*.py" -v
```
