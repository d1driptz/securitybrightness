"""Decision binding primitives for structured proposals.

A binding records which immutable proposal snapshot a decision refers to.
It is not an authorization token and does not execute or grant anything.
"""
from dataclasses import dataclass

from .proposal_identity import proposal_identity
from .structured_proposal import StructuredActionProposal


@dataclass(frozen=True)
class ProposalDecisionBinding:
    proposal_id: str
    decision: str

    def __post_init__(self):
        if not isinstance(self.proposal_id, str) or not self.proposal_id:
            raise ValueError("proposal_id must be nonempty")
        if self.decision not in {"allow", "deny"}:
            raise ValueError("decision must be allow or deny")

    @classmethod
    def for_proposal(cls, proposal, decision):
        if not isinstance(proposal, StructuredActionProposal):
            raise TypeError("proposal must be a StructuredActionProposal")
        return cls(proposal_identity(proposal), decision)

    def applies_to(self, proposal):
        if not isinstance(proposal, StructuredActionProposal):
            raise TypeError("proposal must be a StructuredActionProposal")
        return self.proposal_id == proposal_identity(proposal)

    @property
    def allowed(self):
        return self.decision == "allow"

    def __bool__(self):
        raise TypeError("Use binding.allowed and binding.applies_to() explicitly; a binding is not permission")
