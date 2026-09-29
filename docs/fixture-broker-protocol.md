# Inactive fixture-broker exchange contract

The owner reported `ALL COMPLETED` for the interactive walkthrough at `acf518ed9b4f1e101257536cfef42d288e6f1643`. This is owner-reported completion of the generated-fixture cases, separate from automated test evidence. The next prerequisite is a narrow coordinator/broker message boundary, not broader file access.

`core.broker_protocol` implements a pure, inactive single-exchange wire contract. It performs no process launch, IPC, file acquisition, read, authorization or delivery. It is not imported by the current fixture reader, demo, `/check` or v1. The already demonstrated protected path remains unchanged.

## Contract

A trusted bootstrap supplies a fresh 32-byte secret key and fresh 32-byte session identifier to exactly one coordinator endpoint and one broker endpoint. A request binds canonical application ID, complete proposal digest, opaque resource token, decision ID and a 1–4096 byte limit. The resource token must eventually refer to a broker-owned retained handle; it is not a pathname, file ID or proof of identity by itself. No path, callback, approval flag or arbitrary operation is accepted.

Frames carry a four-byte bounded length, canonical JSON body and a 32-byte HMAC-SHA256 tag. Distinct direction keys bind request/reply roles. Session/version/direction are authenticated. Body size is capped at 8,192 bytes; receivers reject partial, concatenated, oversized, malformed, noncanonical, unknown-field and invalid-MAC messages. The decoder takes one complete frame; a future transport must enforce the length bound before allocating/reading it. HMAC authenticates bytes; it does not encrypt them or establish OS peer identity.

The broker can reply only to its accepted binding, with `buffered` or `denied`. A denial has no payload. Buffered data uses strict canonical base64, cannot exceed the bound, and remains staged evidence. The coordinator compares every binding field before exposing that staged reply to trusted code. Result types refuse implicit boolean conversion. Signed-but-invalid schema or content is rejected too: key possession is not enough to bypass validation.

Each endpoint can complete exactly one request/reply exchange. A second operation, role/order violation, malformed frame, failed authentication or explicit close irreversibly retires that endpoint. There is no retry/import/reset API. Locks serialize concurrent consumption. A lost sent frame does not restore the sender's ability to send again. Failures expose fixed errors, not keys, paths or protected bytes.

## Limits that must not be promoted into security claims

- The bootstrap is not implemented. An application must never supply the key, session, resource mapping or channel role. A valid MAC means possession of that key, not human approval, correct resource observation or current authority.
- Replay resistance is endpoint/session-local. Reconstructing endpoints with reused key/session values defeats lifetime replay accounting. The future bootstrap must generate fresh cryptographic randomness on every exchange/restart, and the authoritative coordinator must independently burn each decision. A decision ID is only an exact binding field here, never authority.
- A `buffered` reply is not an allow result. It must remain inside trusted staging until current registry, approval, expiry, revocation, resource and one-use checks pass at the final delivery boundary. This codec neither performs nor substitutes for those checks.
- There is no process isolation, restricted token, peer authentication, pipe ACL, cancellation, timeout, crash recovery or persistent revocation mechanism here. HMAC is not a replacement for them. Closing drops key references but does not promise secure memory erasure.
- Unauthenticated invalid traffic can close an endpoint. Availability and hostile same-process code are outside this primitive's guarantee. It accepts no external traffic today.

## Transport gate status

The separate [inactive denial-only transport](fixture-broker-transport.md) now implements private child startup, bounds, cancellation and crash handling. The codec itself remains pure and inactive; the limitations above describe the codec alone. No file-reading broker is active. Bootstrap secrets must not appear in arguments, environment variables, logs or requester input. Independently test wrong-peer/session injection, partial frames, flooding, child startup failure, hangs, cancellation, parent/child death and endpoint reuse. Use only broker-created synthetic fixtures initially.

Before connecting the protected path, define where staged bytes live, who owns the retained handle and how cancellation/revocation invalidates a pending result. Authenticate application/coordinator/broker channels and scope capabilities to the exact peer/session/resource/decision. Keep final authority and human control in SecurityBrightness; never add arbitrary commands or reopen requester paths. A smaller broker reduces native code in the coordinator but remains trusted for resource acquisition and read correctness.
