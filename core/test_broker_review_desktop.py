"""Real widget automation, not a completed human demonstration."""
import tkinter as tk
import unittest
from dataclasses import replace
from core import test_broker_operator_handoff as helpers
from core.broker_review_desktop import FixtureReviewWindow, display_text
from core.broker_operator_handoff import BrokerOperatorPrompt, BrokerOperatorError


class FixtureReviewDesktopTests(unittest.TestCase):
    def setUp(self):
        helpers.BrokerOperatorHandoffTests.setUp(self)
        self.root = tk.Tk()
        self.root.withdraw()
        self.future, self.prompt = helpers.BrokerOperatorHandoffTests.start(self)
        self.window = FixtureReviewWindow(self.root, self.channel.operator, self.future)
        self.addCleanup(self.window.close)

    def finish(self):
        try: self.future.result(timeout=1)
        except BrokerOperatorError: pass
        self.window.poll()

    def test_allow_requires_exact_confirmation_and_reports_evidence_only(self):
        self.window.allow.invoke()
        self.assertFalse(self.future.done())
        self.window.confirmation.insert(0, 'allow once')
        self.window.allow.invoke()
        self.assertFalse(self.future.done())
        self.window.confirmation.delete(0, 'end')
        self.window.confirmation.insert(0, 'ALLOW ONCE')
        self.window.allow.invoke()
        self.assertIn('queued', self.window.status.get())
        self.finish()
        self.assertIn('No operation authorized; 0 protected bytes', self.window.status.get())
        self.assertEqual(str(self.window.allow['state']), 'disabled')
        self.assertFalse(hasattr(self.future.result(), 'data'))
        self.assertEqual(self.window.confirmation.get(), '')

    def test_deny_and_no_enter_approval_binding(self):
        self.assertEqual(self.window.confirmation.bind('<Return>'), '')
        self.window.deny.invoke()
        self.finish()
        self.assertIn('recorded: deny', self.window.status.get())

    def test_close_cancels_waiter(self):
        self.window.close()
        with self.assertRaises(BrokerOperatorError): self.future.result(timeout=1)

    def test_revocation_between_display_and_click_rejects(self):
        self.registry.revoke('app')
        self.window.respond('ALLOW ONCE')
        self.finish()
        self.assertIn('rejected or expired', self.window.status.get())

    def test_mutation_after_display_rejects_before_queue(self):
        object.__setattr__(self.prompt, 'canonical_display', b'{}')
        self.window.respond('ALLOW ONCE')
        self.assertIn('Response rejected', self.window.status.get())
        with self.assertRaises(BrokerOperatorError): self.future.result(timeout=1)

    def test_replay_does_not_reopen_terminal_window(self):
        self.window.respond('DENY')
        self.finish()
        status = self.window.status.get()
        self.window.respond('ALLOW ONCE')
        self.assertEqual(self.window.status.get(), status)

    def test_cancelled_pending_prompt_disables_controls(self):
        self.channel.close()
        self.finish()
        self.assertEqual(str(self.window.allow['state']), 'disabled')
        self.assertIn('0 protected bytes', self.window.status.get())

    def test_display_is_readonly_complete_and_credential_free(self):
        self.assertEqual(str(self.window.text['state']), 'disabled')
        text = self.window.text.get('1.0', 'end')
        for name in ('file_id', 'volume_serial', 'proposal_json', 'max_bytes', 'application_id'):
            self.assertIn(name, text)
        self.assertNotIn(self.credential, text)

    def test_malformed_or_oversized_display_rejected(self):
        for raw in (b'{}', b'x' * 16385, b'[]', b'null', b'{"x":1,"x":2}'):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                display_text(replace(self.prompt, canonical_display=raw))
        with self.assertRaises(ValueError): display_text({'canonical_display': b'{}'})

    def test_control_and_bidi_strings_are_escaped(self):
        import json
        from core.broker_protocol import _canonical
        value = json.loads(self.prompt.canonical_display)
        value['display_path'] = 'label\nFORGED\u202e'
        rendered = display_text(BrokerOperatorPrompt(self.prompt.review_id, _canonical(value)))
        self.assertIn(r'label\nFORGED\u202e', rendered)
        self.assertNotIn('\u202e', rendered)
