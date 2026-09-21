# SecurityBrightness

**Application/AI intent does not equal human permission.**

SecurityBrightness is building a human-controlled authorization layer for increasingly autonomous applications and AI agents. The aim is useful autonomy with meaningful human authority over consequential actions, not automation restricted for its own sake.

Today it is an **authorization-only Python core, local HTTP service, and application SDK**. It checks proposed actions against policy and application scopes, requests terminal or desktop approval or strong confirmation when required, and records decisions. It does not execute actions or control arbitrary third-party applications.

## Start here

- [Product vision](docs/PRODUCT_VISION.md): implemented capabilities, planned product direction, and longer-term possibilities.
- [Architecture](docs/ARCHITECTURE.md): trust boundaries, implementation evidence, dependencies, and architectural decision gates.
- [Platform development sequence](docs/PLATFORM_DEVELOPMENT.md): scanner/desktop assessment and dependencies for File Security, Device Security and the Security Assistant.
- [Application and AI integration](docs/application-integration.md): provisioning, SDK usage, human review, and a runnable example.
- [Current behavior and service reference](docs/CURRENT_BEHAVIOR.md): HTTP contract, compatibility notes, and known limitations.

- [Development batches](docs/DEVELOPMENT_LOG.md): reviewed changes, full-suite results, and remaining limits.

## Run the local service

From the repository root:

```bash
python -m core.service
```

The default address is `127.0.0.1:8765`. Keep the generated service/admin token private. Provision an application with its own credential and scopes using the [integration guide](docs/application-integration.md); do not give the application your admin token.

```python
from core.sdk import ApplicationClient

client = ApplicationClient("notes-assistant", application_credential)
result = client.check("read", "notes.txt", details={"purpose": "summarize notes"})
print(result.allowed, result.reason, result.request_id)
```

This proposes a read and reports its decision; it does not read the file. Inspecting bills must not automatically grant permission to transfer money. The existing action catalog distinguishes those operations, but resource-specific financial limits and actual banking integrations are not implemented.

For graphical human review, run `python -m core.desktop` instead of the terminal service. See the [desktop guide](docs/desktop-review.md) for setup, limitations, and the required migration toward stronger Windows isolation.

The desktop also has a narrow [File Security prototype](docs/file-security.md): explicitly choose one file to review three private-key header patterns. It shows redacted evidence, not a malware or safety verdict, and grants no authority.

## Boundaries

The default registry is in memory; [opt-in persistence](docs/persistent-authority.md) restores grants locked until explicit operator unlock. Desktop review, authority inspection, unlock and confirmed revocation are available. Review remains synchronous, audit history is not tamper-proof, and the direct Python API is for trusted callers. Expiring/resource-specific grants, OS interception and execution brokers are not implemented.

An application must integrate with an enforcement point SecurityBrightness controls for actions at that point to be governed. Merely installing this project does not stop another application from bypassing a decision. Deeper OS integration is a longer-term possibility, not an existing feature. Any future execution layer requires a separate decision and isolation; arbitrary AI intent must never become unrestricted shell/OS execution.

## Test

```bash
python -m unittest discover -s core -p "test_*.py" -v
node tests/test_web_scanner.js
```

Tests support specific behavior claims, not complete security. Development should follow the [product vision](docs/PRODUCT_VISION.md) and [architecture](docs/ARCHITECTURE.md), keeping current claims synchronized with code and evidence.
