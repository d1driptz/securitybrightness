# Desktop human review (prototype A)

Run `python -m core.desktop` instead of `python -m core.service`. Python must include Tkinter. The desktop owns the loopback service at 127.0.0.1:8765; stop any previous instance first. Keep the generated console admin token private. Provision through the [integration guide](application-integration.md). Optional [--store persistence](persistent-authority.md) restores grants locked, with operator unlock and inactive revocation in the desktop.

Application/AI intent does not equal human permission. This prototype trusts the local Windows operator environment. **It does not protect against malicious processes running under the same Windows account.** [Decision 0001](decisions/0001-proposals-and-human-authority.md) records A and makes B a required hardening milestone before strong local enforcement claims.

## Review a request

Use the existing ApplicationClient.check or check_proposal APIs. Requests still wait for a final decision; automatic and denied requests do not open a review. When review is required, the window shows the application identity, whether the credential was verified, request ID, action/target, required scope, policy assessment and unverified requester explanation. Control characters are displayed as escaped text to reduce spoofing. This display is not an independent verification of the requested effects.

Choose Deny or Approve this proposal. Strong confirmation also requires typing ALLOW. Typing alone does not submit approval. There is no default Enter-to-approve binding. Approval applies only to the proposal; it never grants continuing authority or executes an action. The service must persist its audit after the human answer before returning a successful authorization result.

A reviewer has 120 seconds by default. Expiry, unavailable review capacity or closing the window fails outstanding unanswered review with HTTP 503, without a final authorization decision. Closing also stops the desktop-owned service. No terminal fallback occurs. Internal pending reviews disappear on shutdown; they are not durable grants or recoverable review records. A response accepted before closure is already a human decision and may complete its audit/response.

The SDK's default 60-second socket timeout can occur before review expires. Timeout never means consent. An application that loses its response must not execute or automatically resubmit. Adjust the SDK timeout deliberately if a longer human wait is needed, and reconcile ambiguous outcomes through the service audit. The desktop shows a submitted human answer, not proof that audit persistence succeeded or that the application received it.

## Inspect current application authority

Applications shows identity, trust, stored scopes and active/locked state, refreshed about once per second. Select a row for complete scope/lifetime/creation/change information. Neither credentials nor hashes are displayed. Persistent mode supports exact-version confirmed unlock and Lock all; confirmed Revoke works while inactive. Registration, rotation and scope changes remain administrative operations. Empty scopes grant no access; trust never bypasses scopes or strong confirmation. An arriving review selects the Human review tab without answering it.

The registry supplies immutable credential-free summaries. The UI receives specific read/operator callbacks, not a credential-bearing registry object. A failed refresh marks the view stale. Unlock/revoke revalidate the selected grant version instead of trusting stale display data. This is not a list of OS processes or arbitrary third-party permissions.

## Boundary and replacement path

Decision history provides [read-only local audit summaries](decision-history.md) through an explicit Refresh button. Missing/unavailable history is distinguished from an empty valid log. Free-form targets/details/reasons are withheld; records are not proof of execution, current authority or strong human identity. The tab has no permission or approval controls.

The File Security prototype tab provides a separate [private-key-header review](file-security.md) for one explicitly selected regular UTF-8 file up to 1 MiB. It is not a malware scan or permission decision. Reading and analysis run in fixed helpers with separate timeout/cancellation handling; an arriving authorization review still takes priority. Results show redacted locations, a snapshot digest and limitations. Neither helper receives application/admin credentials, registry or approval channel. No scan happens automatically and no file is modified. Closing cancels processing; OS startup/kill limitations and the absence of strong sandboxing remain explicit in the guide.

The trusted desktop main thread owns the review interface; the existing HTTP service runs on a worker. OperatorReviewChannel implements the existing approval-provider contract and carries immutable credential-free ReviewRequest messages. Each response names a fresh pending review ID; wrong, expired or already answered IDs cannot approve another request. Strong confirmation is checked in the channel as well as requested by the UI.

Application and administrator credentials are not reviewer credentials and there is no HTTP approval route. The desktop is launched by the local operator; this in-process bootstrap is not OS-backed human-presence authentication. Only the trusted reviewer holds the channel object. Python code in that trusted process can still bypass these conventions; same-user hostile processes are outside A's protection.

A future B implementation replaces this in-process transport with an authenticated isolated Windows review component while keeping the core authorization/provider model and application-facing API. It must independently establish human authority, protect IPC and credential custody, bind decisions to reviewed content, prevent replay, and fail closed on channel failure. It must be validated against the selected same-user attacker before making strong local enforcement claims. No executor or OS interception is implied.

## Remaining limitations

The single HTTP worker waits during review. Trusted desktop lifecycle changes can still occur; registered requests revalidate after review so old approval cannot revive changed/locked/revoked authority. There is no application-facing polling/cancellation API, durable review queue, notification delivery, full management UI, authenticated human account or isolated process boundary. Scopes remain broad. Audit failure is fail-closed, but history is not tamper-proof and failed reviews/revalidation have no final decision record.
