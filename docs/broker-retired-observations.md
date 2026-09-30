# Inactive authenticated retired observations

The new `observe_fixture` diagnostic is opt-in and remains disconnected from the
protected reader, owner walkthrough, `/check` and v1. It returns a retired
metadata receipt with `outcome='denied'` and empty data. It does not grant
permission, issue a live resource capability, perform a content read or deliver
protected bytes. The existing denial-only `probe` retains its contract.

## Fixed child and exchange

A second fixed packaged entry runs under the existing Windows Job Object,
isolated interpreter, explicit inherited-pipe handles and sanitized environment.
Both profiles share the same one-exchange admission slot, timeout/cancellation
checks and cleanup poisoning. No public entry-path or executable selector exists.
Fresh bootstrap randomness and PID/session readiness still precede each request.

The request contains only application ID, decision ID and a canonical structured
file-read proposal (maximum 4,096 ASCII characters). Neither ID authenticates an
application or grants authority. The proposal must preserve exactly version 2,
operation, resources, effects and requester context. Its whole-file bound must
fit the fixed 37-byte synthetic fixture and cannot exceed 4,096 bytes. Extra
resource/observation/path/key/authority fields are rejected before launching.
The reference within the proposal remains descriptive requester text.

The child validates the complete authenticated request before creating a fixture.
It creates its own fixture and retains its creation handle, uses the existing
owner to bind and verify that exact request once, and closes/deletes the fixture
before serializing a reply. It accepts no caller resource selection and never
opens the requester's reference. A new MAC domain prevents interchange with the
original broker codec, even under the same key/session. The existing 8,192-byte
body framing, canonical JSON, direction/session/version checks and terminal
single-exchange state machine remain in force.

The reply echoes the exact canonical request and contains only strict bounded
metadata: owner session, resource token, volume ID, file ID, fixed fixture size
and display-only path. Unknown fields, live lifecycle, allow/buffered outcomes,
data fields, malformed metadata or request substitution are rejected even with
a valid MAC. The returned object has immutable byte snapshots, detached metadata
inspection, no implicit boolean permission, and an explicit retired lifecycle.

## What the evidence means

The receipt reports metadata observed by trusted child code before that child
closed the resource. It is historical evidence, not current freshness or a
resource that can later be consumed. A MAC proves channel-key possession; the
native observation still depends on child/OS/interpreter integrity. No persistent
session/token lookup exists and no caller can redeem the receipt. Future live
sessions must reject collisions and bind their own token registry explicitly;
this diagnostic must not be repurposed by changing `retired` to `live`.

Normal successful publication requires fixture cleanup, valid exact response,
EOF, successful child exit, successful process cleanup and a final cancellation/
deadline check. Crashes, cancellation or filesystem cleanup errors return no
receipt. The [native delete-on-close owner](broker-resource-sessions.md) now removes
the generated pathname on process termination without Python cleanup. No
per-fixture directory is created. The documented OS/account trust limits apply. No personal files are involved. The child has normal account rights;
Windows jobs are not a restricted-token sandbox.

## Verification and remaining gates

Tests cover real child creation and deletion, separate random observations,
request/metadata mutation, schema/version/type/boundary errors, signed data/live
claims, wrong keys/sessions/domains, replay, extra/partial/tampered frames,
request substitution, startup failure, post-reply crash/hang, cancellation,
shared admission and cleanup failure before reply publication.

The earlier directory-based owner required normal Windows permissions for its
child tests because of sandbox temporary-directory ACLs. The native owner creates
no such directory; the current complete suite runs in the workspace sandbox.
No permission bypass/fallback was introduced. Test files are generated
fixtures only; the owner demonstration is separate.

A separate inactive local registry now tests bounded live ownership, token
collisions, expiry and terminal cancellation. Next connect a deliberately designed
multi-step authenticated session protocol with explicit retirement across review. Only then add authority-controlled
content acquisition and trusted staged-buffer ownership, followed by final
registry/grant/human-control and exact one-use delivery checks. Intent and review
evidence alone must never trigger a read. No broker activation is included here.
