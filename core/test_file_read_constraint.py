import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from core.constrained_authority import ConstrainedAuthority
from core.constraint_evaluation import evaluate_constraint
from core.decision_binding import ProposalDecisionBinding
from core.file_read_constraint import FileReadConstraint, evaluate_file_read_constraint
from core.file_read_schema import make_file_read_proposal, MAX_FILE_READ_BYTES
from core.proposal import ActionProposal, MAX_MESSAGE_BYTES
from core.structured_proposal import StructuredActionProposal


class FileReadConstraintTests(unittest.TestCase):
    def constraint(self, **kwargs):
        return FileReadConstraint("app", "notes.txt", max_bytes=16, **kwargs)

    def proposal(self, limit=16, reference="notes.txt", **kwargs):
        return make_file_read_proposal(reference, max_bytes=limit, **kwargs)

    def evaluate(self, proposal):
        return evaluate_file_read_constraint("app", proposal, self.constraint())

    def test_constraint_is_detached_immutable_inspection_data(self):
        constraint = self.constraint()
        payload = constraint.to_payload()
        self.assertEqual(payload, {
            "version": 1, "kind": "file_read_constraint.v1", "application_id": "app",
            "operation": "files.read", "resource": {"type": "file", "reference": "notes.txt"},
            "effects": {"schema": "file_read.v1", "max_bytes": 16,
                        "recipient": "requesting_application"},
            "lifetime": "session", "uses": "unlimited",
        })
        payload["effects"]["max_bytes"] = MAX_FILE_READ_BYTES
        payload["resource"]["reference"] = "other"
        self.assertEqual(constraint.to_payload()["effects"]["max_bytes"], 16)
        self.assertEqual(constraint.reference, "notes.txt")
        for name, value in (("max_bytes", 100), ("reference", "other"), ("application_id", "other")):
            with self.assertRaises(FrozenInstanceError):
                setattr(constraint, name, value)
        with self.assertRaises(TypeError):
            bool(constraint)
        self.assertNotIn("notes.txt", repr(constraint))

    def test_lifetime_and_use_modes_cannot_silently_expand(self):
        for lifetime in ("persistent", "once", "forever", "1h", "", None):
            with self.subTest(lifetime=lifetime), self.assertRaises((TypeError, ValueError)):
                self.constraint(lifetime=lifetime)
        for uses in ("once", "10", 1, "", None):
            with self.subTest(uses=uses), self.assertRaises((TypeError, ValueError)):
                self.constraint(uses=uses)

    def test_invalid_bounds_references_and_application_ids_fail(self):
        for value in (True, False, 1.0, "1", None, 0, -1, MAX_FILE_READ_BYTES + 1):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                FileReadConstraint("app", "notes.txt", max_bytes=value)
        for reference in (None, False, "", " ", "x\x00", "x\n", "\ud800"):
            with self.assertRaises((TypeError, ValueError)):
                FileReadConstraint("app", reference, max_bytes=1)
        for application_id in (None, False, "", " "):
            with self.assertRaises((TypeError, ValueError)):
                FileReadConstraint(application_id, "notes.txt", max_bytes=1)

    def test_complete_constraint_envelope_obeys_message_bound(self):
        import json
        overhead = len(json.dumps(FileReadConstraint("app", "x", max_bytes=1).to_payload(),
                                  ensure_ascii=True, sort_keys=True,
                                  separators=(",", ":")).encode("utf-8")) - 1
        reference = "x" * (MAX_MESSAGE_BYTES - overhead)
        FileReadConstraint("app", reference, max_bytes=1)
        with self.assertRaises(ValueError):
            FileReadConstraint("app", reference + "x", max_bytes=1)

    def test_lower_and_equal_limits_fit_but_higher_does_not(self):
        for limit in (1, 15, 16):
            result = self.evaluate(self.proposal(limit))
            self.assertTrue(result.applicable)
            self.assertEqual(result.reason, "file_read_constraint_match")
            with self.assertRaises(TypeError):
                bool(result)
        for limit in (17, MAX_FILE_READ_BYTES):
            result = self.evaluate(self.proposal(limit))
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "byte_limit_exceeded")

    def test_application_ownership_is_required(self):
        result = evaluate_file_read_constraint("other", self.proposal(), self.constraint())
        self.assertFalse(result.applicable)
        self.assertEqual(result.reason, "application_mismatch")
        for app in (None, False, ""):
            with self.assertRaises((TypeError, ValueError)):
                evaluate_file_read_constraint(app, self.proposal(), self.constraint())

    def test_reference_aliases_do_not_match(self):
        for reference in ("NOTES.TXT", " notes.txt", "notes.txt ", "./notes.txt", "x/../notes.txt"):
            result = self.evaluate(self.proposal(reference=reference))
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "resource_reference_mismatch")
        # Descriptive aliases still cannot prove that two different objects are safe.
        self.assertTrue(self.evaluate(self.proposal()).applicable)

    def test_unknown_or_malformed_effects_fail_closed(self):
        baseline = self.proposal().to_payload()
        effects_cases = [{}, {**baseline["effects"], "schema": "file_read.v2"},
                         {**baseline["effects"], "recipient": "external"},
                         {**baseline["effects"], "max_bytes": True},
                         {**baseline["effects"], "max_bytes": 1.0},
                         {**baseline["effects"], "offset": 0}]
        for effects in effects_cases:
            proposal = StructuredActionProposal("files.read", baseline["resources"], effects=effects)
            result = self.evaluate(proposal)
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "unsupported_file_read_proposal")

    def test_wrong_operation_multiple_resources_and_attributes_fail_closed(self):
        baseline = self.proposal().to_payload()
        for operation, resources in (("files.write", baseline["resources"]),
                                     ("files.read", baseline["resources"] * 2),
                                     ("files.read", [{**baseline["resources"][0], "attributes": {}}])):
            result = self.evaluate(StructuredActionProposal(operation, resources, effects=baseline["effects"]))
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "unsupported_file_read_proposal")

    def test_context_and_mutation_cannot_increase_applicable_limit(self):
        proposal = self.proposal(17, requester_context={"max_bytes": 1, "recipient": "requesting_application"})
        view = proposal.to_payload()
        view["effects"]["max_bytes"] = 1
        self.assertFalse(self.evaluate(proposal).applicable)
        with self.assertRaises(ValueError):
            self.proposal(requester_context={"nested": [{"approved": True}]})
        original = self.proposal(16)
        binding = ProposalDecisionBinding.for_proposal(original, "allow")
        lower = self.proposal(1)
        self.assertTrue(self.evaluate(lower).applicable)
        self.assertFalse(binding.applies_to(lower))

    def test_generic_evaluator_and_legacy_inputs_do_not_gain_support(self):
        with self.assertRaises(TypeError):
            evaluate_constraint("app", self.proposal(), self.constraint())
        generic = ConstrainedAuthority("app", "files.read", "file", "notes.txt")
        self.assertFalse(evaluate_constraint("app", self.proposal(), generic).applicable)
        with self.assertRaises(TypeError):
            evaluate_file_read_constraint("app", self.proposal(), generic)
        for proposal in (None, {}, ActionProposal("read", "notes.txt")):
            with self.assertRaises(TypeError):
                self.evaluate(proposal)

    def test_construction_and_matching_perform_no_file_access(self):
        with patch("builtins.open", side_effect=AssertionError("file opened")), \
             patch("os.open", side_effect=AssertionError("file opened")), \
             patch("pathlib.Path.resolve", side_effect=AssertionError("path resolved")), \
             patch("pathlib.Path.stat", side_effect=AssertionError("file inspected")):
            self.assertTrue(self.evaluate(self.proposal()).applicable)

    def test_each_required_effect_and_type_confusion_is_rejected(self):
        baseline = self.proposal().to_payload()
        cases = [{key: value for key, value in baseline["effects"].items() if key != missing}
                 for missing in baseline["effects"]]
        for field in baseline["effects"]:
            for value in (None, False, True, [], {}, "", 0, -1, 1.0):
                cases.append({**baseline["effects"], field: value})
        for effects in cases:
            result = self.evaluate(StructuredActionProposal("files.read", baseline["resources"], effects=effects))
            self.assertFalse(result.applicable)
            self.assertEqual(result.reason, "unsupported_file_read_proposal")

    def test_both_byte_ceiling_extremes_and_mutation_of_effect_inputs(self):
        for ceiling in (1, MAX_FILE_READ_BYTES):
            constraint = FileReadConstraint("app", "notes.txt", max_bytes=ceiling)
            self.assertTrue(evaluate_file_read_constraint("app", self.proposal(ceiling), constraint).applicable)
            if ceiling == 1:
                self.assertFalse(evaluate_file_read_constraint("app", self.proposal(2), constraint).applicable)
        payload = self.proposal(17).to_payload()
        proposal = StructuredActionProposal(payload["operation"], payload["resources"], effects=payload["effects"])
        payload["effects"]["max_bytes"] = 1
        payload["resources"][0]["reference"] = "other"
        self.assertEqual(self.evaluate(proposal).reason, "byte_limit_exceeded")

    def test_requester_fields_cannot_broaden_owner_reference_or_effects(self):
        context = {"owner": "app", "reference": "notes.txt", "max_bytes": 1,
                   "lifetime": "forever", "uses": "unlimited", "verified": True}
        proposal = self.proposal(17, reference="other.txt", requester_context=context)
        result = evaluate_file_read_constraint("other", proposal, self.constraint())
        self.assertEqual(result.reason, "application_mismatch")
        self.assertEqual(self.evaluate(proposal).reason, "resource_reference_mismatch")
        for key in ("application_id", "authorization", "approved", "grant_id", "granted_scopes"):
            with self.assertRaises(ValueError):
                self.proposal(requester_context={"nested": ({key: "app"},)})
        original = self.proposal()
        binding = ProposalDecisionBinding.for_proposal(original, "allow")
        changed = self.proposal(requester_context={"purpose": "different"})
        self.assertTrue(self.evaluate(changed).applicable)
        self.assertFalse(binding.applies_to(changed))
        self.assertEqual(evaluate_file_read_constraint("APP", original, self.constraint()).reason,
                         "application_mismatch")

    def test_unsupported_operation_resource_and_effect_extensions_are_rejected(self):
        payload = self.proposal().to_payload()
        for operation in ("read", "files.delete", "files.write", "process.execute", "unknown"):
            self.assertFalse(self.evaluate(StructuredActionProposal(operation, payload["resources"],
                                                                   effects=payload["effects"])).applicable)
        for resource in ({"type": "directory", "reference": "notes.txt"},
                         {"type": "file", "reference": "notes.txt", "attributes": {"verified": True}}):
            self.assertFalse(self.evaluate(StructuredActionProposal("files.read", [resource],
                                                                   effects=payload["effects"])).applicable)
        for key, value in (("follow_links", True), ("truncate", False), ("destination", "app"),
                           ("lifetime", "forever"), ("resource_identity", "verified")):
            result = self.evaluate(StructuredActionProposal("files.read", payload["resources"],
                                                           effects={**payload["effects"], key: value}))
            self.assertFalse(result.applicable)
