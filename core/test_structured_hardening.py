"""Adversarial coverage for inactive v2 primitives, not enforcement claims."""
import unittest
from unittest.mock import patch
import importlib

from core.structured_proposal import StructuredActionProposal
from core.constrained_authority import ConstrainedAuthority
from core.constraint_evaluation import evaluate_constraint
from core.decision_binding import ProposalDecisionBinding
from core.protocol_identifiers import protocol_identifier
from core.proposal_identity import proposal_identity


class StructuredHardeningTests(unittest.TestCase):
    def proposal(self, reference="x", **kwargs):
        return StructuredActionProposal("files.read", [{"type": "file", "reference": reference}], **kwargs)

    def test_non_ascii_is_rejected_before_case_and_whitespace_normalization(self):
        for value in ("\u212aey", "\u00a0read", "read\u00a0", "r\u00e9ad", "read/path", "*"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    protocol_identifier(value, "operation")
                with self.assertRaises(ValueError):
                    ConstrainedAuthority("app", value, "file", "x")
                with self.assertRaises(ValueError):
                    ConstrainedAuthority("app", "files.read", value, "x")

    def test_non_string_keys_are_not_silently_coerced(self):
        for key in (1, True, None):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.proposal(effects={"nested": ({key: "value"},)})

    def test_cycles_and_extreme_depth_raise_validation_errors(self):
        cyclic = {}
        cyclic["child"] = cyclic
        nested = {}
        for _ in range(1100):
            nested = {"child": nested}
        for value in (cyclic, nested):
            with self.assertRaises(ValueError):
                self.proposal(effects=value)

    def test_tuple_wrapped_authority_cannot_enter_any_requester_container(self):
        bad = {"nested": ({" Approved ": True},)}
        for kwargs in ({"effects": bad}, {"requester_context": bad}):
            with self.assertRaises(ValueError):
                self.proposal(**kwargs)
        with self.assertRaises(ValueError):
            StructuredActionProposal("files.read", [{"type": "file", "reference": "x", "attributes": bad}])

    def test_reference_whitespace_is_material_to_identity_and_matching(self):
        original = self.proposal()
        authority = ConstrainedAuthority("app", "files.read", "file", "x")
        binding = ProposalDecisionBinding.for_proposal(original, "allow")
        for reference in (" x", "x "):
            changed = self.proposal(reference)
            self.assertNotEqual(proposal_identity(original), proposal_identity(changed))
            self.assertFalse(binding.applies_to(changed))
            self.assertFalse(evaluate_constraint("app", changed, authority).applicable)
            other = ConstrainedAuthority("app", "files.read", "file", reference)
            self.assertFalse(evaluate_constraint("app", original, other).applicable)

    def test_unmodeled_effects_and_attributes_are_inapplicable(self):
        authority = ConstrainedAuthority("app", "files.read", "file", "x")
        for effects in ({"recipient": "external"}, {"amount": 10}, {"visibility": "local"}):
            result = evaluate_constraint("app", self.proposal(effects=effects), authority)
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "unsupported_effects")
        proposal = StructuredActionProposal("files.read", [{"type": "file", "reference": "x", "attributes": {"version": 1}}])
        self.assertEqual(evaluate_constraint("app", proposal, authority).reason, "unsupported_resource_attributes")

    def test_effect_and_context_changes_invalidate_bindings(self):
        binding = ProposalDecisionBinding.for_proposal(self.proposal(), "allow")
        for kwargs in ({"effects": {"recipient": "other"}}, {"requester_context": {"purpose": "other"}}):
            self.assertFalse(binding.applies_to(self.proposal(**kwargs)))

    def test_binding_rejects_noncanonical_identity(self):
        for identity in ("arbitrary", "sbp2_sha256_" + "A" * 64, "sbp2_sha256_" + "0" * 63, "sbp2_sha256_" + "0" * 64 + "\n"):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                ProposalDecisionBinding(identity, "allow")

    def test_future_legacy_catalog_additions_require_explicit_migration(self):
        from core import actions, action_migration
        expanded = dict(actions.ACTIONS)
        expanded["future_action"] = actions.ActionDescriptor("future_action", "files", "files.read", "automatic")
        try:
            with patch.object(actions, "ACTIONS", expanded):
                importlib.reload(action_migration)
                with self.assertRaises(ValueError):
                    action_migration.structured_operation_for_legacy_action("future_action")
        finally:
            importlib.reload(action_migration)
        self.assertEqual(set(action_migration.LEGACY_TO_OPERATION), set(actions.ACTIONS))
