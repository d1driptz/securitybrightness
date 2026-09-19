import unittest

from core.events import MAX_TEXT_LENGTH, SecurityEvent


class EventTests(unittest.TestCase):
    def test_event_has_unique_request_id(self):
        first = SecurityEvent.create("test", "suite", "read", "a.txt")
        second = SecurityEvent.create("test", "suite", "read", "a.txt")
        self.assertNotEqual(first.request_id, second.request_id)

    def test_timestamp_is_utc(self):
        event = SecurityEvent.create("test", "suite", "read", "a.txt")
        self.assertTrue(event.timestamp.endswith("Z"))

    def test_details_must_be_dictionary(self):
        with self.assertRaises(TypeError):
            SecurityEvent.create(
                "test",
                "suite",
                "read",
                "a.txt",
                details="invalid",
            )

    def test_oversized_text_is_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEvent.create(
                "test",
                "suite",
                "x" * (MAX_TEXT_LENGTH + 1),
                "a.txt",
            )


if __name__ == "__main__":
    unittest.main()
