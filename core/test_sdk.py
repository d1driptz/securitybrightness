import io
import json
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from contextlib import redirect_stdout
from dataclasses import asdict
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from core.proposal import ActionProposal
from core.review_channel import OperatorReviewChannel
from core.registry import ApplicationRegistry
from core.sdk import ActionDenied, ApplicationClient, AuthorizationResult, SDKError, MAX_MESSAGE_BYTES
from core.service import create_server


class SDKIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log = Path(self.temp.name) / "events.json"
        self.patch = patch("core.logger.LOG_FILE", self.log)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.registry = ApplicationRegistry()
        self.credential = self.registry.register("app", ["files.read", "communications.send"])
        self.server = create_server(port=0, token="admin", registry=self.registry)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.client = ApplicationClient("app", self.credential, port=self.server.server_port, timeout=2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_scoped_read_returns_typed_result_matching_audit(self):
        result = self.client.check("read", "notes.txt", details={"purpose": "summarize notes"})
        self.assertIsInstance(result, AuthorizationResult)
        self.assertTrue(result.allowed)
        self.assertIs(result.require_allowed(), result)
        with self.assertRaises(TypeError):
            bool(result)
        record = json.loads(self.log.read_text())[0]
        for field in ("request_id", "action_category", "risk_level", "review_reason", "required_scope"):
            self.assertEqual(record[field], getattr(result, field))
        self.assertEqual(result.action_category, "files")
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(record["source"], "app")
        self.assertEqual(record["details"], {"purpose": "summarize notes"})
        self.assertEqual(record["application_id"], "app")
        self.assertTrue(record["authenticated"])

    def test_prepared_proposal_preserves_snapshot_through_service_and_audit(self):
        details = {"purpose": "summarize", "context": {"items": ["bill-A"]}}
        proposal = ActionProposal("read", "bills", details=details)
        details["context"]["items"].append("bill-B")
        proposal.to_payload()["details"]["context"]["items"].clear()
        result = self.client.check_proposal(proposal)
        self.assertTrue(result.allowed)
        record = json.loads(self.log.read_text())[0]
        self.assertEqual(record["details"]["context"], {"items": ["bill-A"]})
        self.assertEqual(record["request_id"], result.request_id)
        with patch.object(self.client._opener, "open") as network:
            with self.assertRaises(TypeError):
                self.client.check_proposal({"action": "read", "target": "bills"})
            network.assert_not_called()

    def test_reusing_proposal_reauthenticates_and_does_not_cache_permission(self):
        proposal = ActionProposal("read", "bills")
        self.assertTrue(self.client.check_proposal(proposal).allowed)
        self.registry.set_scopes("app", [])
        self.assertFalse(self.client.check_proposal(proposal).allowed)
        self.registry.revoke("app")
        with self.assertRaises(SDKError) as caught:
            self.client.check_proposal(proposal)
        self.assertEqual(caught.exception.status, 401)

    def test_scope_denial_is_distinct_from_transport_error(self):
        with patch("core.permissions.TerminalApprovalProvider") as provider:
            result = self.client.check("write", "notes.txt")
        provider.assert_not_called()
        self.assertFalse(result.allowed)
        with self.assertRaises(ActionDenied) as caught:
            result.require_allowed()
        self.assertIs(caught.exception.result, result)
        self.assertEqual(result.decision_source, "scope")

    def test_human_control_remains_in_the_service_not_the_application(self):
        with patch("core.approval.TerminalApprovalProvider.request_approval", return_value=False) as approval:
            denied = self.client.check("send_message", "recipient", details={"impact": "low", "approved": True})
        self.assertFalse(denied.allowed)
        self.assertTrue(approval.call_args.kwargs["strong"])
        with patch("core.approval.TerminalApprovalProvider.request_approval", return_value=True):
            allowed = self.client.check("send_message", "recipient")
        self.assertTrue(allowed.allowed)
        self.assertEqual((allowed.human_control, allowed.risk_level), ("strong_confirm", "high"))

    def test_actual_terminal_review_explains_sensitive_read_before_consent(self):
        output = io.StringIO()
        def respond(prompt):
            display = output.getvalue()
            self.assertIn('Policy rule: "sensitive_target"', display)
            self.assertIn("target appears sensitive", display)
            self.assertIn("Why human review is required:", display)
            self.assertIn('Source: "app"', display)
            self.assertNotIn("FAKE_POLICY", display)
            return "no"
        with redirect_stdout(output), patch("builtins.input", side_effect=respond) as prompt:
            result = self.client.check("read", ".env", details={"policy_reason": "FAKE_POLICY"})
        prompt.assert_called_once()
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_source, "user")
        self.assertIn(result.request_id, output.getvalue())
        self.assertIn(result.review_reason, output.getvalue())
        record = json.loads(self.log.read_text())[0]
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["policy_rule"], result.policy_rule)

    def test_actual_terminal_strong_review_still_requires_allow(self):
        for answer, allowed in (("yes", False), ("ALLOW", True)):
            output = io.StringIO()
            with self.subTest(answer=answer), redirect_stdout(output), patch("builtins.input", return_value=answer):
                result = self.client.check_proposal(ActionProposal("send_message", "recipient"))
            self.assertEqual(result.allowed, allowed)
            self.assertIn("STRONG CONFIRMATION", output.getvalue())
            self.assertIn(result.review_reason, output.getvalue())
            self.assertIn(result.request_id, output.getvalue())

    def test_operator_channel_integrates_without_application_api_changes(self):
        channel = OperatorReviewChannel(timeout=2)
        self.addCleanup(channel.close)
        self.server.approval_provider = channel
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.client.check, "send_message", "recipient")
            deadline = time.monotonic() + 1
            while not channel.pending_reviews() and time.monotonic() < deadline:
                time.sleep(0.005)
            reviews = channel.pending_reviews()
            self.assertEqual(len(reviews), 1)
            self.assertEqual(reviews[0].application_id, "app")
            self.assertTrue(reviews[0].authenticated)
            self.assertTrue(channel.respond(reviews[0].review_id, True, confirmation="ALLOW"))
            result = future.result(timeout=1)
        self.assertTrue(result.allowed)
        self.assertEqual(result.request_id, reviews[0].request_id)
        record = json.loads(self.log.read_text())[0]
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["request_id"], result.request_id)

    def test_failed_operator_channel_does_not_fall_back_to_terminal(self):
        channel = OperatorReviewChannel(timeout=0.02)
        self.server.approval_provider = channel
        with patch("builtins.input") as terminal:
            with self.assertRaises(SDKError) as caught:
                self.client.check("send_message", "recipient")
        self.assertEqual(caught.exception.status, 503)
        terminal.assert_not_called()

    def test_rotated_and_revoked_credentials_fail_authentication(self):
        fresh = self.registry.rotate_credential("app")
        with self.assertRaises(SDKError) as caught:
            self.client.check("read", "x")
        self.assertEqual(caught.exception.status, 401)
        self.assertNotIn(self.credential, str(caught.exception))
        client = ApplicationClient("app", fresh, port=self.server.server_port)
        self.assertTrue(client.check("read", "x").allowed)
        self.registry.revoke("app")
        with self.assertRaises(SDKError) as caught:
            client.check("read", "x")
        self.assertEqual(caught.exception.code, "invalid_application_credentials")

    def test_invalid_proposals_never_contact_the_service(self):
        for details in ([], False, {"authenticated": True}, {"granted_scopes": ["*"]}, {"number": float("nan")}):
            with self.subTest(details=details), patch.object(self.client._opener, "open") as network:
                with self.assertRaises((TypeError, ValueError)):
                    self.client.check("read", "x", details=details)
                network.assert_not_called()

    def test_timeout_is_unknown_outcome_and_never_automatically_retried(self):
        with patch.object(self.client._opener, "open", side_effect=URLError(socket.timeout())) as network:
            with self.assertRaises(SDKError) as caught:
                self.client.check("read", "x")
        self.assertTrue(caught.exception.outcome_unknown)
        network.assert_called_once()

    def test_error_bodies_are_not_exposed_as_credentials_or_instructions(self):
        import io
        failure = HTTPError("http://127.0.0.1/check", 503, "secret", {}, io.BytesIO(self.credential.encode()))
        with patch.object(self.client._opener, "open", side_effect=failure):
            with self.assertRaises(SDKError) as caught:
                self.client.check("read", "x")
        self.assertEqual(str(caught.exception), "service_unavailable")
        self.assertTrue(caught.exception.outcome_unknown)

    def test_malformed_or_contradictory_success_cannot_be_used_as_permission(self):
        valid = asdict(self.client.check("read", "x"))
        payloads = [{}, {**valid, "authenticated": 1}, {**valid, "decision": "yes"},
                    {**valid, "application_id": "other"}, {**valid, "scope_granted": False},
                    {**valid, "required_scope": "files.write"}, {**valid, "risk_level": "high"}]
        class Response:
            status = 200
            headers = Message()
            headers["Content-Type"] = "application/json"
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return self.body[:size]
        for payload in payloads:
            response = Response()
            response.body = json.dumps(payload).encode()
            with self.subTest(payload=payload), patch.object(self.client._opener, "open", return_value=response):
                with self.assertRaises(SDKError) as caught:
                    self.client.check("read", "x")
                self.assertEqual(caught.exception.code, "invalid_response")
                self.assertTrue(caught.exception.outcome_unknown)
        for body in (b'{"decision":"allow","decision":"deny"}', b'x' * (MAX_MESSAGE_BYTES + 1)):
            response = Response()
            response.body = body
            with patch.object(self.client._opener, "open", return_value=response), self.assertRaises(SDKError):
                self.client.check("read", "x")

    def test_redirect_is_not_followed_and_environment_proxy_is_ignored(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        received = []
        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.path)
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(307)
                self.send_header("Location", "/credential-sink")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            with patch.dict("os.environ", {"http_proxy": "http://127.0.0.1:1", "no_proxy": ""}):
                client = ApplicationClient("app", self.credential, port=server.server_port)
                with self.assertRaises(SDKError) as caught:
                    client.check("read", "x")
            self.assertEqual(caught.exception.status, 307)
            self.assertEqual(received, ["/check"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
