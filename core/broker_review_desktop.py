"""Opt-in local fixture metadata review UI. No service, broker read or delivery."""
import json
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields
import tkinter as tk
from tkinter import ttk

from .broker_operator_handoff import BrokerOperatorHandoff, BrokerOperatorPrompt
from .broker_pending_review import PendingBrokerReview, PendingDisplay, ReviewRecorded
from .broker_protocol import _canonical
from .json_input import loads


def display_text(prompt):
    """Render bounded canonical facts with controls/bidi escaped, never interpreted."""
    if type(prompt) is not BrokerOperatorPrompt or type(prompt.canonical_display) is not bytes:
        raise ValueError('invalid prompt')
    raw = prompt.canonical_display
    if not 0 < len(raw) <= 16384:
        raise ValueError('display limit')
    value = loads(raw)
    if (type(value) is not dict or set(value) != {f.name for f in fields(PendingDisplay)}
            or _canonical(value) != raw):
        raise ValueError('invalid display')
    return json.dumps(value, ensure_ascii=True, indent=2)


class FixtureReviewWindow:
    """Trusted operator adapter. Host owns worker, completion future and cleanup.

    This UI has only the operator port, never application credentials. A completion
    result reports evidence recording, not authority, acquisition or delivery.
    """
    def __init__(self, root, operator, completion):
        self.root, self.operator, self.completion = root, operator, completion
        self.closed = self.terminal = False
        self.current = None
        self.snapshot = None
        self.timer = None
        root.title('SecurityBrightness - inactive fixture metadata review')
        root.geometry('880x700')
        ttk.Label(root, text='Generated fixture only. Trusted local operator prototype.\n'
                  'Review evidence is not permission. No protected bytes will be read or delivered.\n'
                  '30-second deadline; path is a display label, not resource identity.').pack()
        self.status = tk.StringVar(value='Waiting for exact request')
        ttk.Label(root, textvariable=self.status).pack()
        self.text = tk.Text(root, wrap='char', state='disabled')
        self.text.pack(fill='both', expand=True)
        ttk.Label(root, text='To record allow evidence, type ALLOW ONCE and click the button.').pack()
        self.confirmation = ttk.Entry(root)
        self.confirmation.pack(fill='x')
        self.allow = ttk.Button(root, text='Record ALLOW ONCE evidence', command=self.approve, state='disabled')
        self.allow.pack()
        self.deny = ttk.Button(root, text='DENY', command=lambda: self.respond('DENY'), state='disabled')
        self.deny.pack()
        root.protocol('WM_DELETE_WINDOW', self.close)
        self.poll()

    def disable(self):
        self.allow.configure(state='disabled')
        self.deny.configure(state='disabled')
        self.confirmation.delete(0, 'end')

    def stop(self):
        self.terminal = True
        self.disable()
        self.operator.cancel()

    def poll(self):
        if self.closed or self.terminal:
            return
        try:
            if self.completion.done():
                result = self.completion.result()
                if type(result) is not ReviewRecorded or result.decision not in ('allow_once', 'deny'):
                    raise ValueError('invalid completion')
                self.stop()  # This demonstration never consumes or retains evidence.
                self.status.set('Review evidence recorded: ' + result.decision +
                                '. Session closed. No operation authorized; 0 protected bytes released.')
                return
            pending = self.operator.pending()
            if len(pending) > 1:
                raise ValueError('ambiguous prompt')
            if pending:
                prompt = pending[0]
                rendered = display_text(prompt)
                if self.current is None:
                    self.current, self.snapshot = prompt, (prompt.review_id, prompt.canonical_display)
                    self.text.configure(state='normal')
                    self.text.insert('1.0', rendered)
                    self.text.configure(state='disabled')
                    self.allow.configure(state='normal')
                    self.deny.configure(state='normal')
                    self.status.set('Awaiting explicit operator decision')
                elif prompt is not self.current or (prompt.review_id, prompt.canonical_display) != self.snapshot:
                    raise ValueError('changed prompt')
        except Exception:
            self.stop()
            self.status.set('Review rejected or expired. Session closed; 0 protected bytes released.')
            return
        self.timer = self.root.after(50, self.poll)

    def approve(self):
        if self.confirmation.get() != 'ALLOW ONCE':
            self.status.set('Exact confirmation required: ALLOW ONCE')
            return
        self.respond('ALLOW ONCE')

    def respond(self, answer):
        if self.closed or self.terminal or self.current is None:
            return
        try:
            if (self.current.review_id, self.current.canonical_display) != self.snapshot:
                raise ValueError('changed prompt')
            self.operator.respond(self.current, answer)
            self.disable()
            self.status.set('Response queued; freshness not yet confirmed. No permission granted.')
        except Exception:
            self.stop()
            self.status.set('Response rejected. Session closed; 0 protected bytes released.')

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.operator.cancel()
        finally:
            if self.timer is not None:
                self.root.after_cancel(self.timer)
            self.root.destroy()


def main():
    from .registry import ApplicationRegistry
    from .file_read_review import FileReadReviewLedger
    from .file_read_constraint import FileReadConstraint
    from .file_read_schema import make_file_read_proposal
    import os
    import sys
    if os.name != 'nt' or len(sys.argv) != 1:
        raise SystemExit('Windows generated-fixture demonstration; no arguments accepted.')
    root = tk.Tk()
    root.withdraw()
    try:
        with closing(ApplicationRegistry()) as registry:
            credential = registry.register('inactive-fixture-demo', ['files.read'])
            ledger = FileReadReviewLedger()
            draft = ledger.create(FileReadConstraint('inactive-fixture-demo', 'generated-fixture', max_bytes=128))
            proposal = make_file_read_proposal('generated-fixture', max_bytes=128)
            with PendingBrokerReview(registry, ledger) as model:
                request = model.application.propose('inactive-fixture-demo', credential, proposal, draft.draft_id, 1)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    with BrokerOperatorHandoff(model) as channel:
                        future = pool.submit(channel.worker.request_review, request)
                        window = FixtureReviewWindow(root, channel.operator, future)
                        root.deiconify()
                        try:
                            root.mainloop()
                        finally:
                            window.close()
    finally:
        try: root.destroy()
        except tk.TclError: pass


if __name__ == '__main__':
    main()
