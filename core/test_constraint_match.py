import unittest

from core.constrained_authority import ConstrainedAuthority
from core.constraint_match import matches_constraint
from core.structured_proposal import StructuredActionProposal


class ConstraintMatchTests(unittest.TestCase):
    def authority(self):
        return ConstrainedAuthority("app", "read", "file", "docs/report.txt")

    def proposal(self, operation="read", resources=None):
        return StructuredActionProposal(
            operation,
            resources or [{"type": "file", "reference": "docs/report.txt"}],
        )

    def test_exact_match_only(self):
        result = matches_constraint(self.proposal(), self.authority())
        self.assertTrue(result.matches)
        self.assertEqual(result.reason, "exact_constraint_match")
        with self.assertRaises(TypeError):
            bool(result)

    def test_material_mismatches_fail(self):
        cases = [
            (self.proposal("write"), "operation_mismatch"),
            (self.proposal(resources=[{"type": "account", "reference": "docs/report.txt"}]),
             "resource_type_mismatch"),
            (self.proposal(resources=[{"type": "file", "reference": "docs/other.txt"}]),
             "resource_reference_mismatch"),
            (self.proposal(resources=[
                {"type": "file", "reference": "docs/report.txt"},
                {"type": "file", "reference": "docs/other.txt"},
            ]), "resource_cardinality_mismatch"),
        ]
        for proposal, reason in cases:
            with self.subTest(reason=reason):
                result = matches_constraint(proposal, self.authority())
                self.assertFalse(result.matches)
                self.assertEqual(result.reason, reason)

    def test_matching_does_not_consider_application_identity_or_grant(self):
        proposal = self.proposal()
        first = ConstrainedAuthority("app-a", "read", "file", "docs/report.txt")
        second = ConstrainedAuthority("app-b", "read", "file", "docs/report.txt")
        self.assertTrue(matches_constraint(proposal, first).matches)
        self.assertTrue(matches_constraint(proposal, second).matches)

    def test_wrong_types_rejected(self):
        with self.assertRaises(TypeError):
            matches_constraint({}, self.authority())
        with self.assertRaises(TypeError):
            matches_constraint(self.proposal(), {})
