"""Fixed inactive discard peer; no caller-selected executable or file access."""
from pathlib import Path
from .broker_recipient_process import _RecipientWitnessChild


class _SyntheticPayloadPeer(_RecipientWitnessChild):
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_synthetic_payload_entry.py')
