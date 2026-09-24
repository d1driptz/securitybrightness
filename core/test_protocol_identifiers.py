import unittest

from core.protocol_identifiers import protocol_identifier


class ProtocolIdentifierTests(unittest.TestCase):
    def test_normalizes_safe_ascii_identifiers(self):
        self.assertEqual(protocol_identifier(" FILES.Read ", "operation"), "files.read")
        self.assertEqual(protocol_identifier("file-system_v2", "type"), "file-system_v2")

    def test_rejects_ambiguous_or_natural_language_values(self):
        invalid = ["", " ", "files read", ".read", "read.", "read..file",
                   "réad", "ＲＥＡＤ", "read/path", "read:*", "_read", False, None]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                protocol_identifier(value, "identifier")
