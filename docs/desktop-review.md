# Desktop human review (prototype A)

Run `python -m core.desktop` from the repository root, instead of `python -m core.service`. Python must include Tkinter. The desktop owns the existing loopback service at 127.0.0.1:8765, so stop an already running instance first. The console prints a generated administrator token unless SECURITYBRIGHTNESS_TOKEN is configured. Keep it private. Provision applications through the existing [integration guide](application-integration.md); the desktop does not yet manage registrations or persistent permissions.

Application/AI intent does not equal human permission. This prototype trusts the local Windows operator environment. **It does not protect against malicious processes running under the same Windows account.** [Decision 0001](decisions/0001-proposals-and-human-authority.md) records A and makes B a required hardening milestone before strong local enforcement claims.

## Review a request

Use the existing ApplicationClient.check or check_proposal APIs. Requests still wait for a final decision; automatic and denied requests do not open a review. When review is required, the window shows the application identity, whether the credential was verified, request ID, action/target, required scope, policy assessment and unverified requester explanation. Control characters are displayed as escaped text to reduce spoofing. This display is not an independent verification of the requested effects.

Choose Deny or Approve this proposal. Strong confirmation also requires typing ALLOW. Typing alone does not submit approval. There is no default Enter-to-approve binding. Approval applies only to the proposal; it never grants continuing authority or executes an action. The service must persist its audit after the human answer before returning a successful authorization result.

A reviewer has 120 seconds by default. Expiry, unavailable review capacity or closing the window fails outstanding unanswered review with HTTP 503, without a final authorization decision. Closing also stops the desktop-owned service. No terminal fallback occurs. Internal pending reviews disappear on shutdown; they are not durable grants or recoverable review records. A response accepted before closure is already a human decision and may complete its audit/response.

The SDK's default 60-second socket timeout can occur before review expires. Timeout never means consent. An application that loses its response must not execute or automatically resubmit. Adjust the SDK timeout deliberately if a longer human wait is needed, and reconcile ambiguous outcomes through the service audit. The desktop shows a submitted human answer, not proof that audit persistence succeeded or that the application received it.

## Boundary and replacement path

The trusted desktop main thread owns the review interface; the existing HTTP service runs on a worker. OperatorReviewChannel implements the existing approval-provider contract and carries immutable credential-free ReviewRequest messages. Each response names a fresh pending review ID; wrong, expired or already answered IDs cannot approve another request. Strong confirmation is checked in the channel as well as requested by the UI.

Application and administrator credentials are not reviewer credentials and there is no HTTP approval route. The desktop is launched by the local operator; this in-process bootstrap is not OS-backed human-presence authentication. Only the trusted reviewer holds the channel object. Python code in that trusted process can still bypass these conventions; same-user hostile processes are outside A's protection.

A future B implementation replaces this in-process transport with an authenticated isolated Windows review component while keeping the core authorization/provider model and application-facing API. It must independently establish human authority, protect IPC and credential custody, bind decisions to reviewed content, prevent replay, and fail closed on channel failure. It must be validated against the selected same-user attacker before making strong local enforcement claims. No executor or OS interception is implied.

## Remaining limitations

The service remains single-threaded: waiting for human review also delays other HTTP requests, including administration. Revocation is not atomic with an in-progress authorization. There is no application-facing polling/cancellation API, persistent review queue, notification delivery, application-management UI, authenticated human account model or isolated process boundary. Scope checks still use broad action scopes. Audit failures remain fail-closed, but audit history is not tamper-proof and failed review-channel attempts have no final decision record.
