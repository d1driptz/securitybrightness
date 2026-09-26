import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from core.constrained_authority import ConstrainedAuthority
from core.constraint_evaluation import evaluate_constraint
from core.decision_binding import ProposalDecisionBinding
from core.file_read_schema import (
    FILE_READ_SCHEMA, MAX_FILE_READ_BYTES,
    inspect_file_read_proposal, make_file_read_proposal,
)
from core.proposal import ActionProposal, MAX_MESSAGE_BYTES
from core.proposal_identity import proposal_identity
from core.structured_proposal import StructuredActionProposal


class FileReadSchemaTests(unittest.TestCase):
    def raw(self, *, operation="files.read", resources=None, effects=None):
        return StructuredActionProposal(
            operation,
            [{"type": "file", "reference": "notes.txt"}] if resources is None else resources,
            effects={"schema": FILE_READ_SCHEMA, "max_bytes": 16,
                     "recipient": "requesting_application"} if effects is None else effects,
        )

    def test_valid_bounds_produce_explicit_immutable_inspection(self):
        for limit in (1, 4096, MAX_FILE_READ_BYTES):
            proposal = make_file_read_proposal("notes.txt", max_bytes=limit)
            view = inspect_file_read_proposal(proposal)
            self.assertEqual(view.reference, "notes.txt")
            self.assertEqual(view.max_bytes, limit)
            self.assertEqual(view.proposal_id, proposal_identity(proposal))
            self.assertEqual(proposal.to_payload()["effects"], {
                "schema": "file_read.v1", "max_bytes": limit,
                "recipient": "requesting_application",
            })
            with self.assertRaises(FrozenInstanceError):
                view.max_bytes = 100
            with self.assertRaises(TypeError):
                bool(view)
            self.assertNotIn("notes.txt", repr(view))

    def test_limit_is_required_and_strictly_typed_on_both_entry_points(self):
        with self.assertRaises(TypeError):
            make_file_read_proposal("notes.txt")
        for limit in (True, False, 1.0, "1", None, [], {}, 0, -1, MAX_FILE_READ_BYTES + 1):
            with self.subTest(limit=limit):
                with self.assertRaises((TypeError, ValueError)):
                    make_file_read_proposal("notes.txt", max_bytes=limit)
                with self.assertRaises((TypeError, ValueError)):
                    inspect_file_read_proposal(self.raw(effects={
                        "schema": FILE_READ_SCHEMA, "max_bytes": limit,
                        "recipient": "requesting_application",
                    }))

    def test_missing_and_unknown_effect_fields_fail_closed(self):
        baseline = self.raw().to_payload()["effects"]
        for key in baseline:
            effects = dict(baseline)
            del effects[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(effects=effects))
        for key, value in (("offset", 0), ("truncate", True), ("follow_links", True),
                           ("destination", "external"), ("future_flag", False)):
            with self.subTest(extra=key), self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(effects={**baseline, key: value}))

    def test_schema_and_recipient_are_exact_not_normalized_or_defaulted(self):
        baseline = self.raw().to_payload()["effects"]
        for field, values in (("schema", ("file_read.v2", " FILE_READ.V1 ", 1, None)),
                              ("recipient", ("external", "REQUESTING_APPLICATION", "", None, []))):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    inspect_file_read_proposal(self.raw(effects={**baseline, field: value}))

    def test_other_operations_and_resource_shapes_are_rejected(self):
        for operation in ("read", "files.write", "files.delete", "process.execute"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(operation=operation))
        resources = [{"type": "file", "reference": "notes.txt"}]
        for shape in (resources * 2, [{"type": "directory", "reference": "notes.txt"}],
                      [{**resources[0], "attributes": {}}],
                      [{**resources[0], "attributes": {"verified": True}}]):
            with self.subTest(shape=shape), self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(resources=shape))

    def test_control_characters_are_rejected_without_path_canonicalization(self):
        for reference in ("", " ", "file\x00", "file\n", "file\t", "file\x7f"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                make_file_read_proposal(reference, max_bytes=1)
        # Syntax acceptance is not path safety or file-identity validation.
        references = ("notes.txt", " notes.txt ", "NOTES.TXT", "./notes.txt",
                      "folder/../notes.txt", "folder/notes.txt", "folder\\notes.txt",
                      "C:notes.txt", "C:/notes.txt", "notes.txt:stream", "NUL",
                      "//server/share/notes.txt", "\u00e9.txt", "e\u0301.txt")
        identities = set()
        for reference in references:
            proposal = make_file_read_proposal(reference, max_bytes=1)
            self.assertEqual(inspect_file_read_proposal(proposal).reference, reference)
            identities.add(proposal_identity(proposal))
        self.assertEqual(len(identities), len(references))
        for reference in (None, False, 1, [], {}, b"notes", "\ud800"):
            with self.subTest(reference=reference), self.assertRaises((TypeError, ValueError)):
                make_file_read_proposal(reference, max_bytes=1)
        # The shared message bound includes the entire envelope, not just context.
        overhead = len(make_file_read_proposal("x", max_bytes=1).canonical_bytes()) - 1
        reference = "x" * (MAX_MESSAGE_BYTES - overhead)
        self.assertEqual(len(make_file_read_proposal(reference, max_bytes=1).canonical_bytes()),
                         MAX_MESSAGE_BYTES)
        with self.assertRaises(ValueError):
            make_file_read_proposal(reference + "x", max_bytes=1)

    def test_untrusted_context_is_detached_and_never_interpreted_as_effects(self):
        context = {"purpose": "review", "max_bytes": MAX_FILE_READ_BYTES,
                   "nested": {"items": ["original"]}}
        proposal = make_file_read_proposal("notes.txt", max_bytes=1, requester_context=context)
        context["nested"]["items"].append("changed")
        self.assertEqual(inspect_file_read_proposal(proposal).max_bytes, 1)
        self.assertEqual(proposal.to_payload()["requester_context"]["nested"]["items"], ["original"])
        for key in ("approved", "application_id", "authenticated", "trust", "trusted",
                    "granted_scopes", "credential", "authorization", "human_approval", "grant_id"):
            bad = {"nested": ([{" " + key.upper() + " ": True}],)}
            with self.subTest(key=key), self.assertRaises(ValueError):
                make_file_read_proposal("notes.txt", max_bytes=1, requester_context=bad)
            with self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(effects={
                    **self.raw().to_payload()["effects"], "nested": bad}))
            with self.assertRaises(ValueError):
                inspect_file_read_proposal(self.raw(resources=[{
                    "type": "file", "reference": "notes.txt", "attributes": bad}]))
        cyclic = {}
        cyclic["self"] = cyclic
        deep = {}
        for _ in range(40):
            deep = {"child": deep}
        for bad in ([], False, {"value": float("nan")}, {"value": float("inf")},
                    {"value": "\ud800"}, {1: "value"}, {"value": object()},
                    {"value": "x" * MAX_MESSAGE_BYTES}, cyclic, deep):
            with self.subTest(kind=type(bad)), self.assertRaises((TypeError, ValueError)):
                make_file_read_proposal("notes.txt", max_bytes=1, requester_context=bad)

    def test_material_changes_and_context_changes_invalidate_binding(self):
        original = make_file_read_proposal("notes.txt", max_bytes=16)
        binding = ProposalDecisionBinding.for_proposal(original, "allow")
        for changed in (make_file_read_proposal("other.txt", max_bytes=16),
                        make_file_read_proposal("notes.txt", max_bytes=17),
                        make_file_read_proposal("notes.txt", max_bytes=16,
                                                requester_context={"purpose": "other"})):
            self.assertFalse(binding.applies_to(changed))
        self.assertTrue(binding.applies_to(make_file_read_proposal("notes.txt", max_bytes=16)))
        compatible = StructuredActionProposal(
            " FILES.READ ", [{"reference": "notes.txt", "type": " FILE "}],
            effects={"recipient": "requesting_application", "max_bytes": 16,
                     "schema": FILE_READ_SCHEMA})
        self.assertEqual(inspect_file_read_proposal(compatible).proposal_id,
                         proposal_identity(original))
        self.assertTrue(binding.applies_to(compatible))
        for field, value in (("recipient", "external"), ("schema", "file_read.v2")):
            changed = self.raw(effects={**original.to_payload()["effects"], field: value})
            self.assertFalse(binding.applies_to(changed))
            with self.assertRaises(ValueError):
                inspect_file_read_proposal(changed)

    def test_inspection_does_not_open_or_resolve_a_file(self):
        with patch("builtins.open", side_effect=AssertionError("file opened")), \
             patch("os.open", side_effect=AssertionError("file opened")), \
             patch("pathlib.Path.resolve", side_effect=AssertionError("path resolved")), \
             patch("pathlib.Path.stat", side_effect=AssertionError("file inspected")):
            proposal = make_file_read_proposal("nonexistent-file", max_bytes=16)
            self.assertEqual(inspect_file_read_proposal(proposal).reference, "nonexistent-file")

    def test_schema_validation_does_not_enable_inert_constraints(self):
        proposal = make_file_read_proposal("notes.txt", max_bytes=16)
        authority = ConstrainedAuthority("app", "files.read", "file", "notes.txt")
        result = evaluate_constraint("app", proposal, authority)
        self.assertFalse(result.applicable)
        self.assertEqual(result.reason, "unsupported_effects")

    def test_payload_inspection_cannot_mutate_validated_intent(self):
        proposal = make_file_read_proposal("notes.txt", max_bytes=16)
        view = proposal.to_payload()
        view["effects"]["max_bytes"] = MAX_FILE_READ_BYTES
        view["resources"][0]["reference"] = "other.txt"
        self.assertEqual(inspect_file_read_proposal(proposal).max_bytes, 16)
        self.assertEqual(inspect_file_read_proposal(proposal).reference, "notes.txt")

    def test_v1_and_nonproposal_inputs_are_not_silently_migrated(self):
        for value in (None, {}, "notes.txt", ActionProposal("read", "notes.txt")):
            with self.subTest(kind=type(value)), self.assertRaises(TypeError):
                inspect_file_read_proposal(value)
