"""Fixed inactive Windows peer for metadata-only dry publication commits.

It inherits the original process, pipe and job ownership guards. No executable,
entry, application, resource or transport selector is accepted from a caller.
The peer has no file acquisition or protected-byte delivery operation.
"""
from pathlib import Path
from .broker_recipient_process import _RecipientWitnessChild


class _PublicationCommitPeer(_RecipientWitnessChild):
    """One fixed cooperating test peer; not installed application identity."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_native_commit_entry.py')
