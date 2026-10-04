"""Separate opt-in generated-fixture UI for the inactive process-owned host."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict
import tkinter as tk
from tkinter import ttk
from .broker_live_review import RetiredMappedReview
from .broker_pending_review import PendingDisplay
from .broker_operator_handoff import BrokerOperatorPrompt
from .broker_protocol import _canonical
from .broker_review_desktop import display_text
from .broker_review_host import BrokerReviewHost, BrokerShutdownStatus


class BrokerHostWindow:
    """UI thread alone touches widgets. Closing waits asynchronously for cleanup.

    Trusted bootstrap supplies only operator port, future and worker-pool owner.
    It must cancel and join the pool if construction or the Tk loop fails.
    """
    def __init__(self, root, operator, completion, pool):
        self.root, self.operator, self.completion, self.pool = root, operator, completion, pool
        self.closed = self.closing = self.terminal = self.queued = False
        self.current = self.snapshot = self.timer = None
        self.expected = None
        root.title('SecurityBrightness - child-process fixture review (inactive)')
        root.geometry('900x720')
        ttk.Label(root, text='Generated fixture only. Metadata review; no file contents read or delivered.\n'
                  'Trusted local operator prototype, not independent human authentication.\n'
                  '30-second total session limit, including startup and cleanup. Paths are display labels.').pack()
        self.status = tk.StringVar(value='Starting private fixture child; no permission granted.')
        ttk.Label(root, textvariable=self.status, wraplength=850).pack()
        self.text = tk.Text(root, state='disabled', wrap='char')
        self.text.pack(fill='both', expand=True)
        ttk.Label(root, text='Type exactly ALLOW ONCE, then click to record review evidence.').pack()
        self.confirmation = ttk.Entry(root); self.confirmation.pack(fill='x')
        self.allow = ttk.Button(root, text='Record ALLOW ONCE evidence', command=self.approve, state='disabled')
        self.allow.pack()
        self.deny = ttk.Button(root, text='DENY', command=lambda: self.respond('DENY'), state='disabled')
        self.deny.pack()
        self.cancel = ttk.Button(root, text='Cancel session', command=self.cancel_session); self.cancel.pack()
        root.protocol('WM_DELETE_WINDOW', self.close)
        self.poll()

    def disable(self):
        self.allow.configure(state='disabled'); self.deny.configure(state='disabled')
        self.confirmation.delete(0, 'end')

    def cancel_session(self):
        if self.closed or self.terminal: return
        self.queued = True
        self.disable()
        self.operator.cancel()
        self.status.set('Cancellation requested; waiting for worker cleanup. 0 protected bytes released.')

    def approve(self):
        if self.closed or self.closing or self.terminal or self.queued: return
        if self.confirmation.get() != 'ALLOW ONCE':
            self.status.set('Exact confirmation required: ALLOW ONCE')
            return
        self.respond('ALLOW ONCE')

    def respond(self, answer):
        if self.closed or self.closing or self.terminal or self.queued or self.current is None: return
        try:
            if _canonical(asdict(self.current)) != self.snapshot: raise ValueError('changed display')
            self.operator.respond(self.current, answer)
            self.expected = 'allow_once' if answer == 'ALLOW ONCE' else 'deny'
            self.queued = True
            self.disable()
            self.status.set('Response queued; awaiting freshness checks, child retirement and cleanup. No permission granted.')
        except Exception:
            self.cancel_session()

    def _completed(self):
        # done() alone does not certify cleanup. Join the task's thread owner, then
        # require the host's explicit cleanup status, including on rejection.
        self.pool.shutdown(wait=True)
        self.terminal = True
        self.disable(); self.cancel.configure(state='disabled')
        try: shutdown = self.operator.shutdown_status()
        except Exception: shutdown = None
        if type(shutdown) is not BrokerShutdownStatus or shutdown.cleanup_confirmed is not True:
            self.status.set('Worker stopped; cleanup could NOT be confirmed. No successful review; 0 protected bytes released.')
            self.closing = False  # Keep the failure visible; a subsequent close may dismiss it.
            return
        try:
            result = self.completion.result()
            if (type(result) is not RetiredMappedReview or result.decision != self.expected
                    or self.expected not in ('allow_once', 'deny') or result.lifecycle != 'retired'
                    or result.canonical_display != self.snapshot):
                raise ValueError('unexpected result')
            self.status.set('Review evidence retired: '+result.decision+
                            '. Worker joined; child cleanup confirmed. No operation authorized; 0 protected bytes released.')
        except Exception:
            self.status.set('Review cancelled, expired or rejected. Worker joined; child cleanup confirmed. 0 protected bytes released.')
        if self.closing: self._destroy()

    def poll(self):
        if self.closed or self.terminal: return
        self.timer = None
        if self.completion.done():
            self._completed()
            return
        try:
            if not self.closing and not self.queued:
                pending = self.operator.pending()
                if len(pending) > 1: raise ValueError('ambiguous display')
                if pending:
                    display = pending[0]
                    if type(display) is not PendingDisplay: raise ValueError('invalid display')
                    snapshot = _canonical(asdict(display))
                    rendered = display_text(BrokerOperatorPrompt(display.request_id, snapshot))
                    if self.current is None:
                        self.current, self.snapshot = display, snapshot
                        self.text.configure(state='normal'); self.text.insert('1.0', rendered); self.text.configure(state='disabled')
                        self.allow.configure(state='normal'); self.deny.configure(state='normal')
                        self.status.set('Awaiting explicit decision within the fixed session deadline.')
                    elif display is not self.current or snapshot != self.snapshot:
                        raise ValueError('changed display')
        except Exception:
            self.cancel_session()
        self.timer = self.root.after(50, self.poll)

    def _destroy(self):
        if self.closed: return
        self.closed = True
        if self.timer is not None: self.root.after_cancel(self.timer)
        self.root.destroy()

    def close(self):
        if self.closed: return
        if self.terminal:
            self._destroy()
            return
        self.closing = True
        self.cancel_session()
        # Keep Tk alive until the worker finishes and its thread is joined.


def main():
    import os
    import sys
    from .registry import ApplicationRegistry
    from .file_read_review import FileReadReviewLedger
    from .file_read_constraint import FileReadConstraint
    from .file_read_schema import make_file_read_proposal
    if os.name != 'nt' or len(sys.argv) != 1:
        raise SystemExit('Windows generated-fixture demonstration; no arguments accepted.')
    root = tk.Tk(); root.withdraw()
    try:
        with closing(ApplicationRegistry()) as registry:
            credential = registry.register('broker-fixture-demo', ['files.read'])
            ledger = FileReadReviewLedger()
            draft = ledger.create(FileReadConstraint('broker-fixture-demo', 'generated-fixture', max_bytes=128))
            proposal = make_file_read_proposal('generated-fixture', max_bytes=128)
            session = BrokerReviewHost(registry, ledger)
            pool = ThreadPoolExecutor(max_workers=1)
            window = None
            try:
                future = pool.submit(session.worker.run, 'broker-fixture-demo', credential, proposal, draft.draft_id, 1)
                window = BrokerHostWindow(root, session.operator, future, pool)
                root.deiconify(); root.mainloop()
            finally:
                session.close()
                pool.shutdown(wait=True)
                if window is not None: window._destroy()
    finally:
        try: root.destroy()
        except tk.TclError: pass


if __name__ == '__main__': main()
