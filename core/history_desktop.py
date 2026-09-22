"""Read-only history tab; takes a snapshot reader, no mutation callbacks."""

import json
import queue
import threading
import tkinter as tk
from tkinter import ttk


def describe_history(snapshot):
    if snapshot.status == 'missing':
        return 'No audit file is present. This does not prove that no requests or actions occurred.'
    lines = [f'{snapshot.total_records} stored records; showing latest {len(snapshot.records)} in append order.',
             'Local unverified history. An allow record is not execution evidence or continuing permission.']
    for row in snapshot.records:
        lines.append(f'\nRecord {row.position} | {row.timestamp} | recorded decision: {row.decision}')
        lines.append('Recorded application: ' + json.dumps(row.application_id, ensure_ascii=True))
        lines.append(f'Request ID: {row.request_id}\nAction: {row.action}\nPolicy rule: {row.policy_rule}\nHuman-control classification: {row.human_control}')
    lines.append('\nTargets, details, raw reasons and source text are omitted from this view. '
                 'Lifecycle changes, failed reviews and file analyses are not comprehensively recorded. '
                 'Missing fields remain unknown; this is not the current grant state or proof of human identity.')
    return '\n'.join(lines)


class HistoryPanel:
    def __init__(self, parent, reader):
        self.frame = ttk.Frame(parent, padding=20)
        self._reader = reader
        self._results = queue.Queue(maxsize=1)
        self.closed = False
        self.busy = False
        ttk.Label(self.frame, text='Recorded authorization decisions', font=('Segoe UI', 16, 'bold')).pack(anchor='w')
        ttk.Label(self.frame, wraplength=730, text='Read-only local history, not tamper-proof evidence. '
                  'Records describe decisions, not actions performed. No permissions can be changed here.').pack(anchor='w', pady=10)
        self.refresh = ttk.Button(self.frame, text='Refresh decision history', command=self.load)
        self.refresh.pack(anchor='w')
        self.status = tk.StringVar(value='Not loaded. Refresh explicitly to read a snapshot.')
        ttk.Label(self.frame, textvariable=self.status, wraplength=730).pack(anchor='w', pady=10)
        box = ttk.Frame(self.frame)
        box.pack(fill='both', expand=True)
        self.text = tk.Text(box, wrap='word', state='disabled')
        scroll = ttk.Scrollbar(box, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.text.pack(side='left', fill='both', expand=True)
        self._timer = self.frame.after(100, self.poll)

    def _show(self, text):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.insert('1.0', text)
        self.text.configure(state='disabled')

    def load(self):
        if self.closed or self.busy:
            return
        self.busy = True
        self.refresh.configure(state='disabled')
        self.status.set('Loading a new snapshot; prior results are cleared.')
        self._show('No current history snapshot is available yet.')
        reader, results = self._reader, self._results
        def work():
            try:
                report = describe_history(reader())
                status = 'Snapshot loaded. Refresh for later changes; records are not independently verified.'
            except Exception:
                report = 'History unavailable. It may be busy, inaccessible, oversized or malformed. No empty-history conclusion can be drawn.'
                status = 'History unavailable; no current snapshot displayed.'
            results.put_nowait((status, report))
        try:
            threading.Thread(target=work, name='decision-history-read', daemon=True).start()
        except RuntimeError:
            results.put_nowait(('History unavailable.', 'History reader could not start; no current snapshot is available.'))

    def poll(self):
        if self.closed:
            return
        try:
            status, report = self._results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._show(report)
            self.status.set(status)
            self.busy = False
            self.refresh.configure(state='normal')
        self._timer = self.frame.after(100, self.poll)

    def close(self):
        self.closed = True
        self.frame.after_cancel(self._timer)
