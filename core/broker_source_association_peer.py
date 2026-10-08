"""Fixed inactive native peer for original-source association metadata only."""
from pathlib import Path
from .broker_recipient_process import _RecipientWitnessChild


class _SourceAssociationPeer(_RecipientWitnessChild):
    """Original process, pipes and job guards; no caller endpoint selector."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_source_association_entry.py')
