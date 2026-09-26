# Effect-aware file-read constraints (inactive draft)

This is preparatory work for roadmap step 5, not completion of grant lifecycle or active authorization. `FileReadConstraint` stores one application owner, an exact descriptive reference, a byte ceiling and the currently supported `session` / `unlimited` lifetime labels. Its effect schema is fixed to `file_read.v1` with recipient `requesting_application`. Construction cannot register, activate, unlock, issue or persist a grant.

## Tested applicability invariants

- The supplied application ID must equal the constraint owner. The evaluator validates syntax but does not authenticate either identity.
- The proposal must pass the complete strict file-read schema: operation, one file resource without attributes, exact schema and recipient, and an explicit integer limit. Unsupported material effects produce an inapplicable result.
- Reference text must be exactly equal, without path resolution, case folding, trimming, Unicode normalization or alias handling. This comparison establishes no actual filesystem identity.
- The proposed byte ceiling must be less than or equal to the constraint ceiling, both within 1 through 1,048,576 bytes. A lower ceiling can fit the constraint but still changes the exact proposal identity and invalidates a previous decision binding.
- Requester context and mutable inspection copies cannot override the owner, reference or byte ceiling. Constraints and evaluation results reject implicit boolean conversion.
- Persistent, expiring and one-shot lifetime modes are rejected. The accepted labels are only draft metadata: no session clock, use counter, activation state, revocation or grant-version semantics are implemented.
- The complete serialized constraint obeys the shared message-size bound. Inspection copies are detached and references are omitted from the object's representation.

## Explicit API separation

```python
from core.file_read_constraint import FileReadConstraint, evaluate_file_read_constraint
from core.file_read_schema import make_file_read_proposal

constraint = FileReadConstraint("notes-app", "notes/report.txt", max_bytes=4096)
proposal = make_file_read_proposal("notes/report.txt", max_bytes=1024)
result = evaluate_file_read_constraint("notes-app", proposal, constraint)
# result.applicable describes constraint fit only. It is not permission.
```

Malformed generic structured proposals return `unsupported_file_read_proposal`; incompatible Python argument types raise errors. There is no fallback to broader constraints. The existing generic constraint evaluator does not accept this new type and still rejects file-read proposal effects. The v1 service, SDK, policy, registry and existing structured contracts are unchanged.

These are trusted in-process helpers, not a boundary against hostile Python code. Anyone able to construct these objects can construct a matching constraint; that says nothing about human approval or authority issuance. A future integration must obtain authoritative constraints from authenticated, activated, versioned state and must not use this result as an allow decision.

## Remaining gates

Before activating any authorization path, define and test authenticated decision/application provenance, grant identity/version, final revalidation, revocation, lifetime and replay behavior. Before file access, separately establish verified resource identity, supported path rules and replacement/link/race handling. Persisted grants must retain the existing explicit human-unlock rule. No protected operation, file reader, executor, service endpoint or persistence integration is added here.
