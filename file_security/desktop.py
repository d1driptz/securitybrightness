"""Operator-selected header review UI. Receives no core authority objects."""

import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from .acquisition import FileInputError, read_selected_file
from .worker import AnalysisUnavailable, analyze_in_worker


def describe_result(result):
    lines = [f'Analysis status: {result.status}', f'Analyzer: {result.analyzer_version}',
             f'Snapshot bytes: {result.byte_count}', f'Snapshot SHA-256: {result.artifact_sha256}',
             'This digest identifies the reviewed bytes, not the current file or its safety.']
    if result.status == 'rejected':
        lines.append(f'Not analyzed: {result.reason}')
    elif not result.findings:
        lines.append('No supported header patterns found. This does not prove safety.')
    for finding in result.findings:
        lines.append(f'\nReview pattern: {finding.rule_id} (rule version {finding.rule_version})')
        lines.append(f'{finding.occurrence_count} occurrences; first {len(finding.locations)} locations:')
        for loc in finding.locations:
            lines.append(f'Line {loc.line}, code-point column {loc.column}; byte offset {loc.byte_offset}')
    lines.append('\nLimitations:\n' + '\n'.join(result.limitations))
    lines.append('\nMatched values are withheld. No file was modified and no permission was granted.')
    return '\n'.join(lines)


class FileReviewPanel:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=20)
        self.closed = False
        self.busy = False
        self._cancel = threading.Event()
        self._job = None
        self._results = queue.Queue(maxsize=1)
        ttk.Label(self.frame, text='Private-key header review', font=('Segoe UI', 16, 'bold')).pack(anchor='w')
        ttk.Label(self.frame, wraplength=730, text=(
            'Choose one regular UTF-8 file, up to 1 MiB. Only three private-key header patterns are checked. '
            'This is not a malware scan, proof of safety or authorization. No file is changed. '
            'Analysis uses a same-user worker, not a security sandbox.'
        )).pack(anchor='w', pady=10)
        self.choose = ttk.Button(self.frame, text='Choose file and review headers', command=self.select_file)
        self.choose.pack(anchor='w')
        self.status = tk.StringVar(value='No file selected. Nothing is scanned automatically.')
        ttk.Label(self.frame, textvariable=self.status, wraplength=730).pack(anchor='w', pady=10)
        box = ttk.Frame(self.frame)
        box.pack(fill='both', expand=True)
        self.evidence = tk.Text(box, wrap='word', state='disabled')
        scroll = ttk.Scrollbar(box, command=self.evidence.yview)
        self.evidence.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.evidence.pack(side='left', fill='both', expand=True)
        self._timer = self.frame.after(100, self.poll)

    def _show(self, text):
        self.evidence.configure(state='normal')
        self.evidence.delete('1.0', 'end')
        self.evidence.insert('1.0', text)
        self.evidence.configure(state='disabled')

    def select_file(self):
        if self.closed or self.busy:
            return
        path = filedialog.askopenfilename(parent=self.frame, title='Choose one file for header-pattern review')
        if not path or self.closed:
            return
        self.busy = True
        self.choose.configure(state='disabled')
        label = json.dumps(path, ensure_ascii=True)
        self._selection_label = label if len(label) <= 512 else label[:512] + '... (display truncated)'
        self.status.set('Reviewing selected file: ' + self._selection_label)
        self._show('Reading a bounded snapshot and running header rules. No conclusion is available yet.')
        # Only the queue and selected path reach the background job. No Tk,
        # registry, credentials or approval provider is passed to analysis.
        results = self._results
        cancel = self._cancel
        def work():
            try:
                report = describe_result(analyze_in_worker(read_selected_file(path), cancel=cancel))
            except (FileInputError, AnalysisUnavailable) as error:
                report = 'No analysis conclusion is available: ' + str(error)
            except Exception:
                report = 'No analysis conclusion is available: unexpected analysis failure'
            results.put_nowait(report)
        self._job = threading.Thread(target=work, name='file-header-review', daemon=True)
        try:
            self._job.start()
        except RuntimeError:
            self._job = None
            results.put_nowait('No analysis conclusion is available: background review could not start')

    def poll(self):
        if self.closed:
            return
        try:
            report = self._results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._show(report)
            self.busy = False
            self.choose.configure(state='normal')
            self.status.set('Review finished for ' + self._selection_label + '. Snapshot only; rescan after edits. No authority changed.')
        self._timer = self.frame.after(100, self.poll)

    def close(self):
        self.closed = True
        self.cancel_analysis()
        self.frame.after_cancel(self._timer)

    def cancel_analysis(self):
        self._cancel.set()

    def wait_for_cleanup(self):
        # Used after mainloop ends. File I/O has no hard deadline, so it cannot
        # indefinitely hold desktop shutdown; cancellation prevents a later
        # read completion from launching a child.
        if self._job is not None:
            self._job.join(timeout=2.0)
