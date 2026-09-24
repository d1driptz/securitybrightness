"""Evaluation of inert structured constraints for one application.

This composes exact proposal matching with application ownership. It deliberately
does not consult policy, human approval, registry activation, or execute actions.
"""
from dataclasses import dataclass

from .constrained_authority import ConstrainedAuthority
from .constraint_match import matches_constraint
from .structured_proposal import StructuredActionProposal
from .validation import application_id as validate_application_id


@dataclass(frozen=True)
class ConstraintEvaluation:
    applicable: bool
    reason: str

    def __bool__(self):
        raise TypeError("Use result.applicable explicitly; applicability is not permission")


def evaluate_constraint(application_id, proposal, authority):
    application_id = validate_application_id(application_id)
    if not isinstance(proposal, StructuredActionProposal):
        raise TypeError("proposal must be a StructuredActionProposal")
    if not isinstance(authority, ConstrainedAuthority):
        raise TypeError("authority must be a ConstrainedAuthority")
    if application_id != authority.application_id:
        return ConstraintEvaluation(False, "application_mismatch")
    match = matches_constraint(proposal, authority)
    return ConstraintEvaluation(match.matches, match.reason)
