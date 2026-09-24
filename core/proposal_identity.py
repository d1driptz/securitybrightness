"""Stable identity for immutable structured proposal snapshots.

A proposal identity detects changes to the canonical requester-intent snapshot.
It is not a signature, credential, grant, approval, or proof that an operation ran.
"""
import hashlib

from .structured_proposal import StructuredActionProposal


PROPOSAL_ID_PREFIX = "sbp2_sha256_"


def proposal_identity(proposal):
    if not isinstance(proposal, StructuredActionProposal):
        raise TypeError("proposal must be a StructuredActionProposal")
    digest = hashlib.sha256(proposal.canonical_bytes()).hexdigest()
    return PROPOSAL_ID_PREFIX + digest
