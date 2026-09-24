import unittest

from core.decision_binding import ProposalDecisionBinding
from core.structured_proposal import StructuredActionProposal


class DecisionBindingTests(unittest.TestCase):
    def proposal(self, operation="read", reference="docs/report.txt"):
        return StructuredActionProposal(
            operation, [{"type": "file", "reference": reference}],
            effects={"visibility": "local"},
        )

    def test_binding_applies_only_to_same_snapshot(self):
        original = self.proposal()
        binding = ProposalDecisionBinding.for_proposal(original, "allow")
        self.assertTrue(binding.allowed)
        self.assertTrue(binding.applies_to(self.proposal()))
        self.assertFalse(binding.applies_to(self.proposal(reference="docs/other.txt")))
        self.assertFalse(binding.applies_to(self.proposal(operation="write")))
        with self.assertRaises(TypeError):
            bool(binding)

    def test_denial_is_bound_too(self):
        binding = ProposalDecisionBinding.for_proposal(self.proposal(), "deny")
        self.assertFalse(binding.allowed)
        self.assertTrue(binding.applies_to(self.proposal()))

    def test_invalid_decisions_and_objects_are_rejected(self):
        for decision in ("yes", "", True, None):
            with self.subTest(decision=decision), self.assertRaises((TypeError, ValueError)):
                ProposalDecisionBinding.for_proposal(self.proposal(), decision)
        with self.assertRaises(TypeError):
            ProposalDecisionBinding.for_proposal({}, "allow")
        binding = ProposalDecisionBinding.for_proposal(self.proposal(), "allow")
        with self.assertRaises(TypeError):
            binding.applies_to({})
