# Bounded file-read proposal schema (inactive draft)

This implements step 4 of the structured-proposal roadmap: one operation-specific resource/effect schema. It defines requester intent, not human permission. No service endpoint, SDK migration, file access, grant or enforcement point is added.

## Contract: file_read.v1

The operation is exactly `files.read`. There is exactly one `file` resource containing only `type` and `reference`; even an empty `attributes` object is outside this schema. The reference is preserved exactly, must be nonblank, and cannot contain ASCII control characters. It is still a descriptive string: validation neither resolves a path nor proves that a file exists or is safe to open.

Effects must contain exactly these three fields, with no defaults:

| Field | Accepted value | Meaning of the requested operation |
| --- | --- | --- |
| `schema` | `file_read.v1` | Version of this whole-file read contract |
| `max_bytes` | Integer from 1 through 1,048,576 inclusive | Maximum size of the entire requested file; bool, float and string are rejected |
| `recipient` | `requesting_application` | Return bytes only to the application whose identity a future adapter authenticates |

The intended operation would return the entire file only when it fits the byte limit. Oversized files would be refused, never silently truncated. Empty files could fit any valid limit. Offset/range reads, directories, multiple resources, alternative recipients, extra effects and resource attributes are unsupported. The 1 MiB ceiling bounds this draft's intended operation; it does not establish a current runtime enforcement limit.

The generic snapshot constructor retains its existing normalization for operation/resource-type labels. Schema and recipient values are exact and are not normalized. `requester_context` is detached untrusted explanation: fields placed there cannot override the byte limit or recipient. The shared recursive authority-field rejection still applies.

## Trusted Python inspection only

```python
from core.file_read_schema import make_file_read_proposal, inspect_file_read_proposal

proposal = make_file_read_proposal(
    "notes/report.txt",
    max_bytes=4096,
    requester_context={"purpose": "summarize the report"},
)
intent = inspect_file_read_proposal(proposal)
# intent.reference, intent.max_bytes and intent.proposal_id are inspection data.
# No file has been opened and no authorization decision has been obtained.
```

`inspect_file_read_proposal` also validates a generic `StructuredActionProposal` against this exact schema. It rejects v1 `ActionProposal` objects rather than silently migrating them. Its frozen result rejects boolean conversion and omits the reference from its representation. Neither that object nor a caller-constructed decision binding is an authenticated capability.

The complete structured snapshot determines proposal identity. Changing the byte limit, reference, effects or requester context invalidates an existing exact decision binding. That detects content changes, not human approval, revocation, expiry or replay.

## Authority and compatibility boundaries

The existing inert constraint evaluator deliberately continues to reject these proposals with `unsupported_effects`: its constraint model cannot represent the byte limit or recipient yet. Successful schema inspection must never bypass that rejection. The v1 HTTP service, SDK, policy, registry and File Security analyzer remain unchanged.

Before any protected operation, later milestones must define effect-aware constraints, authenticated application/decision provenance, grant version/lifetime/revocation checks and replay semantics. A separately designed adapter must establish real resource identity and handle links/reparse points, device paths, replacements and concurrent mutation without treating requester references as verified provenance. No executor or file-access adapter is implemented by this milestone.

Tests cover strict bounds and types, unknown/missing fields, schema/recipient versions, resource cardinality, snapshot mutation, context/authority injection, changed decision bindings, lack of filesystem access, continued constraint rejection and rejection of implicit v1 migration.

### Adversarial review limits

Reference spellings such as relative paths, `..`, drive-relative paths, device names, alternate-stream notation, network paths, case differences and Unicode normalization variants are preserved as distinct intent text. Accepting such text is not a declaration that it is a usable or permitted path. No platform-specific path sanitizer is implemented; a later adapter must reject unsupported paths and establish the actual object identity. Tests assert exact identity differences, not filesystem equivalence.

The shared structured snapshot contract enforces its complete-message byte bound, finite JSON, UTF-8 validity, string object keys, depth limit and recursive rejection of reserved authority fields. The file-read schema inherits those checks rather than introducing a second serializer. Other context text remains untrusted; Python construction and frozen dataclasses are not isolation against hostile code inside the trusted process.
