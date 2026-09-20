# SecurityBrightness product vision

**Application/AI intent does not equal human permission.**

SecurityBrightness is intended to become a human-controlled authorization layer for increasingly autonomous applications and AI agents. Its purpose is to enable useful autonomy while preserving meaningful human authority over consequential actions. A person should be able to delegate routine work, understand the limits of that delegation, review important decisions, and withdraw authority without having to supervise every harmless step.

This is the product direction, not a claim that every component exists. [Architecture](ARCHITECTURE.md) defines boundaries and dependencies; [Current behavior](CURRENT_BEHAVIOR.md) and the linked code/tests establish what works today. When they diverge, investigate and correct the documentation rather than treating a roadmap as proof of implementation.

## 1. Implemented today

The repository currently provides an authorization-only Python core, a local HTTP service, and a registered-application Python SDK. It classifies proposed action names, checks application scopes, requests terminal approval when required, and records final decisions in a local audit file. Applications can be registered, have credentials rotated, have scopes/trust updated, and be revoked by the administrator.

A shared action catalog distinguishes categories such as files, communications, payments, accounts, and process actions. Its reported risk level is a deterministic description of the effective human-review classification, not an independent model of real-world harm. The SDK returns explicit decisions and does not execute actions. The example submits proposals and prints decisions only.

Important limits: scopes are broad action scopes, not resource/recipient/amount limits; grants do not expire automatically; registration is in memory; approval is synchronous terminal input; there is no integrated graphical authorization application, review queue, signed capability, OS interception, or execution broker. The standalone browser scanner is not the planned SecurityBrightness authorization UI. See the implementation evidence table in [Architecture](ARCHITECTURE.md#current-implementation-and-evidence).

## 2. Planned product architecture

The following are intended product capabilities, not existing features or delivery dates. Build them in cohesive increments with explicit security decisions where needed.

| Product capability | Intended outcome | Gap from today |
| --- | --- | --- |
| Structured actions and contextual risk/impact | Review the actual operation, affected resources, recipient, amount, sensitivity, reversibility, external effects, and relevant context; preserve evidence provenance and explain uncertainty. | Today uses action/target strings and caller details with deterministic rules. |
| Granular, temporary, revocable authority | Delegate only specified actions on specified resources, within limits and a defined duration; support one-request permission and bounded ongoing delegation. | Broad scopes, rotation and revocation exist; resource constraints, expiry and bounded grants do not. |
| Meaningful human control | Allow routine work within legitimate authority; notify appropriately; obtain approval or strong confirmation for consequential steps; make denial, cancellation and revocation understandable. | Terminal approval/strong confirmation exist; notify is a classification, not a delivered notification workflow. |
| Application/AI identity and scoped authority | Distinguish the requesting application, agent/delegation context, administrative authority, and the human granting permission. Credential possession must not imply unlimited authority. | Bearer-credential application identity exists; no OS attestation, separate human account/session model or agent-delegation protocol. |
| SDK/API and developer integration | Give adapters stable contracts, structured decisions, actionable errors, correlation and compatibility/versioning; make it practical to enforce a decision at the actual operation boundary. | Python SDK and local HTTP checks exist; broader packaging, versioned proposal contracts and mature adapters remain planned. |
| User-facing SecurityBrightness application | A usable place to see connected applications, granted authority, proposed effects, pending review, explanations, recent decisions and revocation controls. | No integrated authorization UI or asynchronous review backend exists. |
| Auditability and explanations | Explain who requested what, which policy/permission applied, what the human reviewed, and the result; protect secrets and history appropriately. | Local decision logs and explanations exist; lifecycle audit, durable review history and tamper evidence remain gaps. |
| Persistent secure policy/credential storage | Preserve policy and authority across restarts with access control, integrity, schema migrations, backup/recovery and appropriate OS-backed credential protection. | Registry is ephemeral, policy is code-defined, and only the audit JSON file persists. |
| Governed integration points | Place a trusted enforcement gate between intent and the affected resource, with checks tied to the actual operation and current authority. | The core returns decisions; a cooperating application can honor them but can also bypass them. No built-in non-bypassable resource gate exists. |

### Useful autonomy without unlimited authority

A mature system should distinguish low-consequence and high-consequence operations instead of treating a broad instruction as an unlimited grant. For example, **permission to inspect bills must not automatically imply permission to transfer money**.

The intended flow could allow an assistant to inspect specifically permitted bills, summarize due dates, and prepare a proposed payment. A transfer would be a separate proposal with an identified payee, amount, currency and funding source, evaluated against independently granted payment authority and any required strong confirmation. Changing those effects would require reevaluation, not reuse of an unrelated approval.

This is an illustrative future workflow, not an implemented bill or banking integration. Today `read` and `transfer_money` already map to different scopes and review requirements; the core neither opens a bill nor transfers money, and it cannot enforce financial limits or bind a decision to a bank transaction.

Low consequence does not mean unrestricted access: even a read may expose private information. High consequence is not synonymous with permanent prohibition: a user may deliberately authorize a specific consequential action through the appropriate workflow. Uncertain or unknown actions must not silently gain the authority of a known safe action. Natural-language intent and caller-supplied risk labels are evidence to evaluate, never permission by themselves.

### Product success criteria

- A user can understand what an application may do, why a particular action needs review, and how to revoke its authority.
- Routine permitted work proceeds with proportionate friction; approval fatigue does not become the mechanism for granting broad authority.
- Approvals refer to specific effects and scope, and changed proposals cannot quietly reuse them.
- An adapter can explain where enforcement occurs and what remains outside its control.
- Failure, expiry, cancellation or ambiguous outcomes never silently become permission.
- Tests demonstrate security boundaries and useful workflows; a larger test count is not the product goal or proof of complete security.

## 3. Longer-term possibilities, not commitments

Deeper platform or OS integration could eventually provide stronger mediation of application/resource access. Other possibilities include separately isolated capability brokers, additional platform/language SDKs, richer organizational or multi-device delegation, and supported third-party adapters. These need feasibility work, a threat model and explicit decisions before implementation. No specific OS hook, kernel component, sandbox, banking connector or universal application-control mechanism is promised here.

**SecurityBrightness cannot control arbitrary third-party applications merely by existing.** An application must integrate with an enforcement point SecurityBrightness controls for actions at that point to be governed. A caller that can directly access a resource and ignore a decision remains outside effective enforcement. Deeper OS/platform integration might change that boundary in the future; it is not implemented now and must not be assumed in product claims.

## Authorization and possible execution

The present boundary remains authorization only. A future execution/capability layer is a separate architectural decision, not an implicit consequence of this vision. If introduced, it must be separately isolated and narrowly capability-based, with explicit resource/operation limits and well-defined expiry, revocation, replay and audit behavior. It must never translate arbitrary AI intent into unrestricted OS or shell execution. A process-execution action name in the catalog does not supply an executor.

## Development alignment

Prefer the next useful vertical slice over unrelated feature accumulation: improve the proposal/review contract, demonstrate it through an SDK and controlled integration point, and document its actual limits. Strengthen the foundation when a real dependency or security flaw requires it; do not substitute endless hardening for product progress.

For each batch, state which planned capability it advances, preserve existing human-authority guarantees, add meaningful regression/workflow tests, run the full suite, review the diff, update the current-state documents, and publish/verify the requested branch. Record material changes to execution boundaries, human identity, delegation, persistent authority or enforcement in an architecture decision before implementation and obtain the product owner's input. Routine implementation within an already established boundary should proceed autonomously.
