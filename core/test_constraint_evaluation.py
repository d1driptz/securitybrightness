import unittest

from core.constrained_authority import ConstrainedAuthority
from core.constraint_evaluation import evaluate_constraint
from core.structured_proposal import StructuredActionProposal


class ConstraintEvaluationTests(unittest.TestCase):
    def proposal(self, reference="docs/report.txt"):
        return StructuredActionProposal(
            "read", [{"type": "file", "reference": reference}]
        )

    def authority(self, application_id="app"):
        return ConstrainedAuthority(
            application_id, "read", "file", "docs/report.txt"
        )

    def test_exact_application_and_resource_are_applicable(self):
        result = evaluate_constraint("app", self.proposal(), self.authority())
        self.assertTrue(result.applicable)
        self.assertEqual(result.reason, "exact_constraint_match")
        with self.assertRaises(TypeError):
            bool(result)

    def test_application_mismatch_fails_before_resource_match(self):
        result = evaluate_constraint("other", self.proposal(), self.authority())
        self.assertFalse(result.applicable)
        self.assertEqual(result.reason, "application_mismatch")

    def test_resource_mismatch_remains_inapplicable(self):
        result = evaluate_constraint(
            "app", self.proposal("docs/other.txt"), self.authority()
        )
        self.assertFalse(result.applicable)
        self.assertEqual(result.reason, "resource_reference_mismatch")

    def test_inputs_are_strict(self):
        for application_id in ("", False, None):
            with self.subTest(application_id=application_id), self.assertRaises((TypeError, ValueError)):
                evaluate_constraint(application_id, self.proposal(), self.authority())
        with self.assertRaises(TypeError):
            evaluate_constraint("app", {}, self.authority())
        with self.assertRaises(TypeError):
            evaluate_constraint("app", self.proposal(), {})
