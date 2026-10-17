"""Fixed inactive generated-fixture child with original Windows ownership guards.

The existing publication entry creates its own harmless fixture. This private
profile accepts no caller path, executable, handle or endpoint. It provides no
application identity, human permission or delivery channel; a containing host
must independently own admission, review, quarantine and complete retirement.
Existing publication children and hosts remain unchanged.
"""
from pathlib import Path
from .broker_recipient_process import _RecipientWitnessChild


class _SourceFixtureChild(_RecipientWitnessChild):
    """Fixed fixture profile; original process, pipes and job remain guarded."""
    def _entry_path(self):
        return Path(__file__).resolve().with_name('broker_publication_entry.py')
