import unittest
from dataclasses import FrozenInstanceError

from core.constrained_authority import ConstrainedAuthority


class ConstrainedAuthorityTests(unittest.TestCase):
    def test_snapshot_is_normalized_and_immutable(self):
        authority = ConstrainedAuthority(
            "notes-app", " FILES.READ ", " FILE ", "docs/report.txt"
        )
        self.assertEqual(authority.to_payload(), {
            "version": 1,
            "application_id": "notes-app",
            "operation": "files.read",
            "resource": {"type": "file", "reference": "docs/report.txt"},
            "lifetime": "session",
            "uses": "unlimited",
        })
        with self.assertRaises(FrozenInstanceError):
            authority.operation = "files.write"

    def test_unsupported_lifetime_and_use_modes_fail_closed(self):
        for lifetime in ("persistent", "forever", "one-hour", ""):
            with self.subTest(lifetime=lifetime), self.assertRaises(ValueError):
                ConstrainedAuthority("app", "files.read", "file", "x", lifetime=lifetime)
        for uses in ("once", "10", ""):
            with self.subTest(uses=uses), self.assertRaises(ValueError):
                ConstrainedAuthority("app", "files.read", "file", "x", uses=uses)

    def test_required_values_are_validated(self):
        cases = [
            ("", "files.read", "file", "x"),
            ("app", "", "file", "x"),
            ("app", "files.read", "", "x"),
            ("app", "files.read", "file", ""),
            ("app", False, "file", "x"),
        ]
        for args in cases:
            with self.subTest(args=args), self.assertRaises((TypeError, ValueError)):
                ConstrainedAuthority(*args)

    def test_authority_is_detached_inspection_data(self):
        authority = ConstrainedAuthority("app", "files.read", "file", "x")
        view = authority.to_payload()
        view["resource"]["reference"] = "other"
        self.assertEqual(authority.resource_reference, "x")
        self.assertEqual(authority.to_payload()["resource"]["reference"], "x")
