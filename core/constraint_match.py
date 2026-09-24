"""Applicability checks between structured proposals and inert constraints.

This is pure matching logic. It does not consult registry state, policy, human
approval, or return an authorization decision.
"""
from dataclasses import dataclass

from .constrained_authority import ConstrainedAuthority
from .structured_proposal import StructuredActionProposal


@dataclass(frozen=True)
class ConstraintMatch:
    matches: bool
    reason: str


def matches_constraint(proposal, authority):
    if not isinstance(proposal, StructuredActionProposal):
        raise TypeError("proposal must be a StructuredActionProposal")
    if not isinstance(authority, ConstrainedAuthority):
        raise TypeError("authority must be a ConstrainedAuthority")

    payload = proposal.to_payload()
    if proposal.operation != authority.operation:
        return ConstraintMatch(False, "operation_mismatch")
    resources = payload["resources"]
    if len(resources) != 1:
        return ConstraintMatch(False, "resource_cardinality_mismatch")
    resource = resources[0]
    if resource["type"] != authority.resource_type:
        return ConstraintMatch(False, "resource_type_mismatch")
    if resource["reference"] != authority.resource_reference:
        return ConstraintMatch(False, "resource_reference_mismatch")
    return ConstraintMatch(True, "exact_constraint_match")
