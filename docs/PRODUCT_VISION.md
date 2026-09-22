# SecurityBrightness product vision

**Application/AI intent does not equal human permission.**

SecurityBrightness is security software intended to protect the human, device, applications, data and security boundaries. Human-controlled action authorization is a fundamental protection mechanism, not the entire long-term product. It supports ordinary applications as well as AI applications, agents and increasingly autonomous software. Its purpose is to enable useful autonomy while preserving meaningful human authority over consequential actions. A person should be able to delegate routine work, understand the limits of that delegation, review important decisions, and withdraw authority without having to supervise every harmless step.

This is the product direction, not a claim that every component exists. [Architecture](ARCHITECTURE.md) defines boundaries and dependencies; [Current behavior](CURRENT_BEHAVIOR.md) and the linked code/tests establish what works today. When they diverge, investigate and correct the documentation rather than treating a roadmap as proof of implementation.

## 1. Implemented today

The repository currently provides an authorization-only Python core, a local HTTP service, and a registered-application Python SDK. It classifies proposed action names, checks application scopes, requests terminal or optional desktop approval when required, and records final decisions in a local audit file. Applications can be registered, have credentials rotated, have scopes/trust updated, and be revoked by the administrator.

A shared action catalog distinguishes categories such as files, communications, payments, accounts, and process actions. Its reported risk level is a deterministic description of the effective human-review classification, not an independent model of real-world harm. The SDK returns explicit decisions and does not execute actions. The example submits proposals and prints decisions only.

Important limits: scopes are broad action scopes, not resource/recipient/amount limits; grants do not expire automatically. Registration is session-only by default; optional persistence restores grants inactive until operator unlock. Approval remains synchronous, with no application-facing asynchronous review API, durable review queue, signed capability, OS interception or execution broker. The standalone browser scanner is separate. See the implementation evidence in [Architecture](ARCHITECTURE.md#current-implementation-and-evidence).

A separate [File Security prototype](file-security.md) now reviews an explicitly operator-selected regular UTF-8 file for three private-key header shapes, using bounded acquisition, a fixed analysis worker and versioned redacted evidence. It has no malware verdict, remediation or authority access. This narrow implemented workflow does not establish the planned broader File Security protection capability.

The desktop also offers [read-only decision history](decision-history.md), a bounded view of existing local audit summaries. It is not comprehensive security history, current authority state, tamper-proof evidence or proof of execution.

## 2. Planned product architecture

The following are intended product capabilities, not existing features or delivery dates. Build them in cohesive increments with explicit security decisions where needed.

| Product capability | Intended outcome | Gap from today |
| --- | --- | --- |
| Structured actions and contextual risk/impact | Review the actual operation, affected resources, recipient, amount, sensitivity, reversibility, external effects, and relevant context; preserve evidence provenance and explain uncertainty. | Today uses action/target strings and caller details with deterministic rules. |
| Granular, temporary, revocable authority | Delegate only specified actions on specified resources, within limits and a defined duration; support one-request permission and bounded ongoing delegation. | Broad scopes, rotation and revocation exist; resource constraints, expiry and bounded grants do not. |
| Meaningful human control | Allow routine work within legitimate authority; notify appropriately; obtain approval or strong confirmation for consequential steps; make denial, cancellation and revocation understandable. | Terminal and optional desktop approval/strong confirmation exist; notify is a classification, not a delivered notification workflow. |
| Application/AI identity and scoped authority | Distinguish the requesting application, agent/delegation context, administrative authority, and the human granting permission. Credential possession must not imply unlimited authority. | Bearer-credential application identity exists; no OS attestation, separate human account/session model or agent-delegation protocol. |
| SDK/API and developer integration | Give adapters stable contracts, structured decisions, actionable errors, correlation and compatibility/versioning; make it practical to enforce a decision at the actual operation boundary. | Python SDK and local HTTP checks exist; broader packaging, versioned proposal contracts and mature adapters remain planned. |
| User-facing SecurityBrightness application | Inspect connected applications, authority, proposals, review, explanations, history and revocation. | Desktop review, stored/active authority inspection, confirmed revocation, exact-version unlock and a read-only decision-history view exist; broader management, comprehensive security history and asynchronous review remain planned. |
| Auditability and explanations | Explain who requested what, which policy/permission applied, what the human reviewed, and the result; protect secrets and history appropriately. | Local decision logs and explanations exist; lifecycle audit, durable review history and tamper evidence remain gaps. |
| Persistent secure policy/credential storage | Preserve policy and authority with access control, integrity, migration, recovery and appropriate OS-backed protection. | An opt-in versioned registry store restores authority locked. Policy remains code-defined; OS-isolated storage custody, backup/recovery and rollback protection remain gaps. |
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

The first desktop reviewer follows accepted threat model A: the local Windows operator environment is trusted. It is not protection against hostile processes under the same Windows account. [Decision 0001](decisions/0001-proposals-and-human-authority.md) makes migration to an isolated human-authority component (B) a required milestone before strong local enforcement claims.

## Expanded protection mission and component principles

**Protect. Prevent. Detect. Withstand. Explain. Prove.** Protect people/devices/data; prevent unauthorized actions where genuine enforcement exists; detect defensible security problems; withstand bypass/impersonation/compromise; explain decisions; and support justified claims with trustworthy evidence. These are objectives, not implemented endpoint-protection claims.

**Trusting an application does not mean trusting every action it can perform. Trust establishes who or what something is; authority establishes what it may do. Trust is not authority.** This also applies to SecurityBrightness components. A legitimate scanner, assistant, updater or monitor must not automatically receive permission-management, human-approval or execution authority. Monitoring does not imply execution; admin credentials do not substitute for human authority.

The planned platform adds distinct Device Security, File Security, Security Assistant, application management, human authentication, audit/history and update/recovery responsibilities around the authorization foundation. Keep existing application authentication/encryption/sandbox protections; integration adds controls rather than requiring wholesale replacement. An SDK or badge is not enforceable protection: relevant actions must pass through a genuine enforcement point.

**Observed does not mean controlled.** Future device assessments may cover installed applications with no integration, but must distinguish observation from action enforcement. Candidate capabilities include file analysis, vulnerability/version awareness, posture assessment, suspicious-activity detection and alerts. None is an implemented device-monitoring or antivirus guarantee today. Privileged monitoring and OS enforcement require separate owner-approved threat models.

File Security is an intended installed-application capability. Inspect the existing browser scanner before migration, distinguish demonstration/browser functionality from substantive analysis, and require evidence for every detection/protection claim. The website may evolve into discovery, documentation and downloads. Do not bolt a cosmetic Scan button onto the trusted core or claim antivirus protection without supporting analysis and evaluation.

The planned conversational Security Assistant should explain events, access, warnings and protection coverage; investigate available evidence; navigate the application; and propose changes. It is not a generic chatbot or a security authority. The intended path is conversation -> understanding/structured proposal -> policy -> required human authority -> final revalidation -> authorized change. It must never approve its own proposals, inherit an admin token, or use natural language to bypass controls. External model dependencies with security implications require owner input.

Application identity, exact proposed effects and authorized-human identity are separate questions. Prototype A trusts the local Windows operator environment and does not prove strong human identity or resist hostile same-user processes. B remains a required isolated/OS-backed human-authority hardening milestone before stronger local enforcement claims. Introducing its mechanism requires owner input.

Quality claims should follow: claim -> threat model -> architecture -> implementation -> automated and adversarial tests -> independent assessment -> evidence -> justified claim. High assurance and competitive quality are ambitions, not claims of superiority over established products. Favor fewer defensible capabilities over feature counts. Secure update/recovery, tamper resistance, isolation, least privilege and eventual independent review belong in the development plan.

Candidate/core identity statements (not finalized marketing): SecurityBrightness - security software built to protect; Trust is not authority; Application intent is not human permission. Candidate concise expression: SecurityBrightness - Trust the app. Authorize the action.
