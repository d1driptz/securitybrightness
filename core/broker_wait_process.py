"""Fixed inactive wait-capable generated-fixture child; no active host selects it."""
from pathlib import Path

from .broker_recipient_process import _RecipientWitnessChild


class _WaitFixtureChild(_RecipientWitnessChild):
    """Original guarded Windows process/job/pipes, one fixed entry, no selectors."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_wait_entry.py')
