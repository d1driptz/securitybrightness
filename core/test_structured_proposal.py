import unittest
from dataclasses import FrozenInstanceError

from core.structured_proposal import StructuredActionProposal


class StructuredProposalTests(unittest.TestCase):
    def test_snapshot_is_canonical_and_detached(self):
        resources = [{"reference": "docs/report.txt", "type": " FILE ",
                      "attributes": {"label": "report"}}]
        effects = {"reversible": False, "visibility": "local"}
        context = {"purpose": "review old report"}
        proposal = StructuredActionProposal(" READ ", resources, effects=effects,
                                            requester_context=context)
        resources[0]["attributes"]["label"] = "changed"
        effects["visibility"] = "external"
        context["purpose"] = "changed"
        self.assertEqual(proposal.to_payload(), {
            "version": 2, "operation": "read",
            "resources": [{"type": "file", "reference": "docs/report.txt",
                           "attributes": {"label": "report"}}],
            "effects": {"reversible": False, "visibility": "local"},
            "requester_context": {"purpose": "review old report"},
        })
        same = StructuredActionProposal(
            "read",
            [{"type": "file", "attributes": {"label": "report"},
              "reference": "docs/report.txt"}],
            requester_context={"purpose": "review old report"},
            effects={"visibility": "local", "reversible": False},
        )
        self.assertEqual(proposal.canonical_bytes(), same.canonical_bytes())
        with self.assertRaises(FrozenInstanceError):
            proposal.operation = "write"
        self.assertNotIn("review old report", repr(proposal))

    def test_authority_fields_are_rejected_recursively(self):
        cases = [
            {"effects": {"approved": True}},
            {"effects": {"nested": {"granted_scopes": ["all"]}}},\n            {"effects": {"nested": ({"approved": True},)}},
            {"requester_context": {"authorization": "caller-value"}},
            {"resources": [{"type": "file", "reference": "x",
                            "attributes": {"application_id": "caller"}}]},
        ]
        for case in cases:
            kwargs = {
                "resources": case.get("resources", [{"type": "file", "reference": "x"}]),
                "effects": case.get("effects"),
                "requester_context": case.get("requester_context"),
            }
            with self.subTest(case=case), self.assertRaises(ValueError):
                StructuredActionProposal("read", **kwargs)

    def test_resource_shape_is_strict(self):
        invalid = [
            [], [{}], [{"type": "file"}], [{"reference": "x"}],
            [{"type": " ", "reference": "x"}],
            [{"type": "file", "reference": " "}],
            [{"type": "file", "reference": "x", "extra": True}],
            [{"type": "file", "reference": "x", "attributes": []}],
            ["file:x"],\n            [{1: "bad-key", "type": "file", "reference": "x"}],
        ]
        for resources in invalid:
            with self.subTest(resources=resources), self.assertRaises((TypeError, ValueError)):
                StructuredActionProposal("read", resources)

    def test_invalid_json_and_bounds_fail_closed(self):
        nested = {}
        for _ in range(40):
            nested = {"child": nested}
        invalid_effects = [
            {"value": float("nan")}, {"value": "\ud800"}, nested,
            {"value": "x" * 65536},
        ]
        for effects in invalid_effects:
            with self.subTest(kind=type(effects)), self.assertRaises(ValueError):
                StructuredActionProposal(
                    "read", [{"type": "file", "reference": "x"}], effects=effects
                )

    def test_operation_and_container_types_are_validated(self):
        for operation in ("", " ", False, None):
            with self.subTest(operation=operation), self.assertRaises((TypeError, ValueError)):
                StructuredActionProposal(operation, [{"type": "file", "reference": "x"}])
        with self.assertRaises(TypeError):
            StructuredActionProposal("read", [{"type": "file", "reference": "x"}],
                                     effects=[])
        with self.assertRaises(TypeError):
            StructuredActionProposal("read", [{"type": "file", "reference": "x"}],
                                     requester_context=[])
