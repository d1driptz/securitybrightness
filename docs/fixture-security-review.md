# Dedicated fixture-path security review and owner walkthrough

Reviewed from `d62e4e40edec5ca27f17d6b9b7889b22622937f6` on 2026-09-29. Scope: the opt-in generated-fixture read path only. `/check`, v1 and the normal SDK/service remain unchanged.

## Confirmed defect and correction

**Expiry could pass during validation.** `_current` checked the deadline before registry/resource inspection. If that inspection crossed the deadline, the final read check could still release a buffered result. Two regression tests reproduced an expired release and an expired review display before the fix.

Deadline validation now runs both before and after freshness inspection, before publishing a display, and at the final result-publication decision after evidence retirement. Expiry permanently retires the request. Additional tests cover expiry during operator approval and during final evidence retirement. The publication decision is the linearization point: expiry after it cannot retract an already returned result. This is not a real-time delivery or synchronous-I/O cancellation guarantee.

## Adversarial coverage and outcome

| Attempt | Expected and tested boundary |
| --- | --- |
| Current application authority without operator approval; displayed review without approval | Denied before native read |
| Copied approval/display/request; duplicate IDs; cross-session token | Rejected; no authority created |
| Replay, concurrent consumption, retired ID/capacity reuse | At most one delivery; tombstones retained |
| Wrong application/credential, proposal/context/resource/effect substitution | Zero delivered bytes |
| Grant rotation/revocation, persistent lock/re-unlock, stale draft/review | Old approval cannot be restored |
| Expiry before/during read, final validation, approval or publication | Request retired; zero delivered bytes |
| Post-buffer draft/authority change, short/error read, metadata/close failure | Buffered data withheld |
| Read adapter opens another resource or fails acquisition | No native read of the substituted resource |
| Registry revocation racing a guarded read | Pre-consumption revocation denies; an in-flight guarded attempt precedes a waiting revoke |
| Existing writer/mapping and fixture mutation | Ordinary conflicting writers are rejected; detected inconsistency denies; immutable bytes are not promised |

No additional protected-byte bypass was observed within the tested trusted-host model. These tests are evidence for their covered cases, not a proof against every possible vulnerability. Wrong credentials can burn a request if a caller already possesses its exact live in-process object; the experiment prioritizes fail-closed delivery, not denial-of-service resistance.

## Reader trust boundary

Currently trusted together: the host/bootstrap and fixture directory acquisition; Python interpreter and imported code; registry and lifecycle state/locks; proposal validation and envelope coordination; operator terminal/port; collector/native ctypes declarations; read adapter and buffering/publication logic; Windows kernel/filesystem. The adapter can read its retained fixture without consulting policy if called directly by trusted host code. Only the controller mediates the protected application-facing route. Private Python attributes do not isolate hostile code running in that host.

Application input cannot select a path, handle, reader callback, grant or approval. The operator channel must never be handed to application code. Automated tests simulate that trusted channel; they do not authenticate a person. The manual local terminal is a narrow operator assumption, not a secure desktop or externally authenticated human identity system.

A **small isolated read broker** would reduce native code and handle authority inside the coordinator and contain more failures, but would not make the broker untrusted. Keep its protocol to one selected, retained regular-file handle and one bounded read verb; no commands, plugins, arbitrary path reopening, writes or process execution. Keep policy/grants and human control in SecurityBrightness. The broker must not manufacture permission from a received observation or an application assertion.

Before one real cooperating application: design authenticated application/coordinator/broker channels with Windows endpoint ACLs and peer/session binding; an operator-selected acquisition boundary; unforgeable session-scoped resource/decision capabilities; exact proposal/effect/grant/approval binding; one-use consumption; and crash, timeout and revocation fencing. Broker output should remain staged until the authoritative delivery gate accepts it. Moving I/O to another process must not introduce a gap between decision validation and byte release. Avoid holding a global authority lock indefinitely while waiting for a broker: cancellation, acknowledgments and the delivery linearization point need explicit failure/race tests first. An isolated broker alone does not block direct OS access by the cooperating application.

## Owner walkthrough

Run in a normal interactive PowerShell terminal on this laptop:

```powershell
Set-Location -LiteralPath 'C:\Users\manue\.codex\.chatgpt-projects\g-p-6ab571deb5848191860fb7718942556e\securitybrightness-work'
python -m core.controlled_read_demo
```

No personal files, path arguments, automatic-approval flags or piped answers are accepted. The program creates and cleans up harmless synthetic fixtures. Allow approximately 2–4 minutes. Each review expires 60 seconds after its proposal, so answer each prompt within that interval; the explicit expiry stage deliberately waits longer. Any unexpected answer stops safely; Ctrl+C also stops. Rerun for fresh requests after interruption or expiry while reviewing.

There are **nine decision prompts**: type `DENY` at the first, then `ALLOW ONCE` at each remaining prompt after inspecting its application/action/resource/effect display.

| Stage | What the owner sees |
| --- | --- |
| 1 | Application `controlled-demo-app`, action `files.read`, complete request and observed identity; typed DENY yields zero bytes |
| 2–3 | ALLOW ONCE yields one bounded synthetic read; immediate replay yields zero bytes |
| 4a | Approval is explicitly revoked by the walkthrough before consumption; zero bytes |
| 4b | Registry grant version changes with the same scopes; stale approval yields zero bytes |
| 4c | After approval, a visible **65-second real wait**, without clock/deadline mutation; expired approval yields zero bytes |
| 5a–5b | A changed byte effect cannot inherit approval; a fresh displayed request needs a new ALLOW ONCE |
| 6a–6b | A second generated resource/session rejects the original approval; its separately displayed identity needs fresh approval |

The three expected successful reads are the original one, the newly approved changed request, and the newly approved second resource. All intervening negative cases must report `DENY: 0 protected bytes released`. Success ends with `All owner demonstration stages completed`. An incomplete/stopped walkthrough must not be reported as a completed human demonstration.

Automated script tests mock terminal input and advance a test clock to verify control flow quickly. Those mocks exist only in tests. The owner command runs the real interactive program and real deadline wait; it is intentionally separate from automated test evidence.

## Claim and remaining limits

SecurityBrightness has demonstrated denying a native fixture read on preflight failure and withholding all buffered bytes on later failure through this specific integration path. Direct Windows access, hostile in-process code, immutable content, durable distributed approval/audit, hard I/O cancellation and general application/broker isolation remain unproven or unsupported. No write/delete/process/payment/communication enforcement is introduced.
