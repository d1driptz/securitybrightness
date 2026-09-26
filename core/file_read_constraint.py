"""Inactive effect-aware constraints for the file_read.v1 draft.

Constructing or matching this inspection data never creates a grant. No registry,
policy, approval, lifecycle activation, filesystem access or executor is involved.
"""
import json
from dataclasses import dataclass, field

from .constrained_authority import ConstrainedAuthority
from .constraint_evaluation import ConstraintEvaluation
from .file_read_schema import make_file_read_proposal, inspect_file_read_proposal
from .json_input import loads as strict_json_loads
from .proposal import MAX_MESSAGE_BYTES
from .structured_proposal import StructuredActionProposal
from .validation import application_id as validate_application_id


@dataclass(frozen=True, init=False)
class FileReadConstraint:
    """An owner/reference/byte-ceiling snapshot, not issued or active authority."""
    application_id: str
    reference: str = field(repr=False)
    max_bytes: int
    lifetime: str
    uses: str
    _body: bytes = field(repr=False)

    def __init__(self, application_id, reference, *, max_bytes,
                 lifetime="session", uses="unlimited"):
        authority = ConstrainedAuthority(application_id, "files.read", "file", reference,
                                         lifetime=lifetime, uses=uses)
        proposal = make_file_read_proposal(reference, max_bytes=max_bytes)
        payload = {
            "version": 1, "kind": "file_read_constraint.v1",
            "application_id": authority.application_id,
            "operation": "files.read",
            "resource": {"type": "file", "reference": reference},
            "effects": proposal.to_payload()["effects"],
            "lifetime": authority.lifetime, "uses": authority.uses,
        }
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("file-read constraint is too large")
        for name, value in (
            ("application_id", authority.application_id), ("reference", reference),
            ("max_bytes", max_bytes), ("lifetime", authority.lifetime),
            ("uses", authority.uses), ("_body", body),
        ):
            object.__setattr__(self, name, value)

    def to_payload(self):
        return strict_json_loads(self._body.decode("utf-8"))

    def __bool__(self):
        raise TypeError("A file-read constraint is not permission")


def evaluate_file_read_constraint(application_id, proposal, constraint):
    """Pure applicability check; the supplied application ID is not authenticated.

    Only this explicit evaluator understands byte ceilings. The generic evaluator
    remains unchanged and cannot silently promote these constraints into grants.
    """
    application_id = validate_application_id(application_id)
    if not isinstance(proposal, StructuredActionProposal):
        raise TypeError("proposal must be a StructuredActionProposal")
    if not isinstance(constraint, FileReadConstraint):
        raise TypeError("constraint must be a FileReadConstraint")
    if application_id != constraint.application_id:
        return ConstraintEvaluation(False, "application_mismatch")
    try:
        intent = inspect_file_read_proposal(proposal)
    except (TypeError, ValueError):
        return ConstraintEvaluation(False, "unsupported_file_read_proposal")
    if intent.reference != constraint.reference:
        return ConstraintEvaluation(False, "resource_reference_mismatch")
    if intent.max_bytes > constraint.max_bytes:
        return ConstraintEvaluation(False, "byte_limit_exceeded")
    return ConstraintEvaluation(True, "file_read_constraint_match")
