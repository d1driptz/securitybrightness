"""Inactive schema for one bounded whole-file read proposal.

Validation describes requester intent only. No files are opened and no permission
is granted. References are descriptive strings, not verified filesystem identity.
"""
from dataclasses import dataclass, field

from .proposal_identity import proposal_identity
from .structured_proposal import StructuredActionProposal

FILE_READ_SCHEMA = "file_read.v1"
MAX_FILE_READ_BYTES = 1024 * 1024
_EFFECT_FIELDS = frozenset({"schema", "max_bytes", "recipient"})


def _byte_limit(value):
    # bool and integral floats must not silently become byte-count integers.
    if type(value) is not int:
        raise TypeError("max_bytes must be an integer")
    if not 1 <= value <= MAX_FILE_READ_BYTES:
        raise ValueError("max_bytes must be between 1 and 1048576")
    return value


@dataclass(frozen=True)
class FileReadIntent:
    """Inspection data, not authenticated provenance or an execution capability."""
    proposal_id: str
    reference: str = field(repr=False)
    max_bytes: int

    def __bool__(self):
        raise TypeError("File-read intent is not permission")


def inspect_file_read_proposal(proposal):
    """Reject everything outside the file_read.v1 schema; never access a file.

    The intended operation returns the entire file to the requesting application
    only if it fits the explicit limit. Truncation, ranges and other recipients
    are not part of this schema. A later adapter must establish resource identity
    and obtain authorization before any protected read.
    """
    if not isinstance(proposal, StructuredActionProposal):
        raise TypeError("proposal must be a StructuredActionProposal")
    payload = proposal.to_payload()
    if payload["operation"] != "files.read":
        raise ValueError("file-read schema requires files.read")
    resources = payload["resources"]
    if len(resources) != 1:
        raise ValueError("file-read schema requires exactly one resource")
    resource = resources[0]
    if set(resource) != {"type", "reference"} or resource["type"] != "file":
        raise ValueError("file-read schema requires one file without attributes")
    reference = resource["reference"]
    if any(ord(char) < 32 or ord(char) == 127 for char in reference):
        raise ValueError("file reference must not contain control characters")
    effects = payload["effects"]
    if set(effects) != _EFFECT_FIELDS:
        raise ValueError("file-read schema requires exactly schema, max_bytes and recipient")
    if effects["schema"] != FILE_READ_SCHEMA:
        raise ValueError("unsupported file-read schema")
    if effects["recipient"] != "requesting_application":
        raise ValueError("unsupported file-read recipient")
    return FileReadIntent(proposal_identity(proposal), reference,
                          _byte_limit(effects["max_bytes"]))


def make_file_read_proposal(reference, *, max_bytes, requester_context=None):
    """Build an immutable proposal with explicit bounds, never a read or grant."""
    proposal = StructuredActionProposal(
        "files.read", [{"type": "file", "reference": reference}],
        effects={"schema": FILE_READ_SCHEMA, "max_bytes": _byte_limit(max_bytes),
                 "recipient": "requesting_application"},
        requester_context=requester_context,
    )
    inspect_file_read_proposal(proposal)
    return proposal
