import json
import unittest
from unittest.mock import patch

from core.client import check


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps({"decision": "allow"}).encode("utf-8")


class ClientTests(unittest.TestCase):
    @patch("core.client.request.urlopen")
    def test_application_id_is_sent_as_authentication_header(self, urlopen):
        urlopen.return_value = FakeResponse()
        result = check(
            "read",
            "example.txt",
            token="app-credential",
            application_id="app-1",
        )

        req = urlopen.call_args.args[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer app-credential")
        self.assertEqual(req.get_header("X-securitybrightness-app"), "app-1")
        self.assertEqual(result["decision"], "allow")

    @patch("core.client.request.urlopen")
    def test_legacy_session_token_client_remains_supported(self, urlopen):
        urlopen.return_value = FakeResponse()
        check("read", "example.txt", token="session-token")

        req = urlopen.call_args.args[0]
        self.assertIsNone(req.get_header("X-securitybrightness-app"))


if __name__ == "__main__":
    unittest.main()
