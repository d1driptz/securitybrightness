import unittest

from core.proposal_identity import PROPOSAL_ID_PREFIX, proposal_identity
from core.structured_proposal import StructuredActionProposal


class ProposalIdentityTests(unittest.TestCase):
    def make(self, *, reference="docs/report.txt", effects=None):
        return StructuredActionProposal(
            "read", [{"type": "file", "reference": reference}],
            effects={} if effects is None else effects,
            requester_context={"purpose": "review"},
        )

    def test_same_canonical_snapshot_has_same_identity(self):
        first = self.make(effects={"visibility": "local", "reversible": True})
        second = StructuredActionProposal(
            "read", [{"reference": "docs/report.txt", "type": "file"}],
            requester_context={"purpose": "review"},
            effects={"reversible": True, "visibility": "local"},
        )
        self.assertEqual(proposal_identity(first), proposal_identity(second))
        self.assertTrue(proposal_identity(first).startswith(PROPOSAL_ID_PREFIX))
        self.assertEqual(len(proposal_identity(first)), len(PROPOSAL_ID_PREFIX) + 64)

    def test_material_changes_change_identity(self):
        baseline = proposal_identity(self.make(effects={"visibility": "local"}))
        changed = [
            self.make(reference="docs/other.txt", effects={"visibility": "local"}),
            self.make(effects={"visibility": "external"}),
            StructuredActionProposal(
                "write", [{"type": "file", "reference": "docs/report.txt"}],
                effects={"visibility": "local"},
                requester_context={"purpose": "review"},
            ),
        ]
        for proposal in changed:
            with self.subTest(payload=proposal.to_payload()):
                self.assertNotEqual(baseline, proposal_identity(proposal))

    def test_identity_is_not_accepted_for_other_objects(self):
        for value in (None, b"x", {}, "proposal"):
            with self.subTest(value=value), self.assertRaises(TypeError):
                proposal_identity(value)
