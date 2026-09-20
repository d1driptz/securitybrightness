import unittest
from dataclasses import FrozenInstanceError

from core.proposal import ActionProposal


class ProposalTests(unittest.TestCase):
    def test_snapshot_and_inspection_are_detached_from_nested_inputs(self):
        details = {"purpose": "review bills", "context": {"items": ["bill-A"]}}
        proposal = ActionProposal(" read ", " bills ", details=details)
        details["context"]["items"].append("bill-B")
        view = proposal.to_payload()
        view["details"]["context"]["items"].clear()
        self.assertEqual(proposal.to_payload(), {
            "action": "read", "target": "bills",
            "details": {"purpose": "review bills", "context": {"items": ["bill-A"]}},
        })
        with self.assertRaises(FrozenInstanceError):
            proposal.action = "transfer_money"
        self.assertNotIn("review bills", repr(proposal))

    def test_invalid_or_authority_bearing_proposals_are_rejected(self):
        for details in (False, [], {"authenticated": True}, {"application_id": "admin"},
                        {"trust": "trusted"}, {"granted_scopes": ["*"]},
                        {"value": float("nan")}, {"value": "\ud800"},
                        {"value": "x" * 65536}):
            with self.subTest(details_type=type(details)), self.assertRaises((TypeError, ValueError)):
                ActionProposal("read", "bills", details=details)
        for action, target in (("", "bills"), ("read", " "), (False, "bills")):
            with self.assertRaises((TypeError, ValueError)):
                ActionProposal(action, target)

    def test_cycles_and_excessive_nesting_are_rejected(self):
        cyclic = {}
        cyclic["self"] = cyclic
        nested = {}
        for _ in range(40):
            nested = {"child": nested}
        for details in (cyclic, nested):
            with self.assertRaises(ValueError):
                ActionProposal("read", "bills", details=details)
