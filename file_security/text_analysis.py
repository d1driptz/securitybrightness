"""Bounded, deterministic UTF-8 private-key-header analysis.

This is neither malware detection nor an authorization decision. Do not pass
credentials, registries or operator callbacks into this component. Inputs are
already-acquired immutable bytes; this module never opens a supplied path.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256

MAX_BYTES = 1024 * 1024
MAX_LOCATIONS = 5
ANALYZER_VERSION = "text-headers/1"
LIMITATIONS = (
    "Only three exact, case-sensitive private-key header shapes are recognized.",
    "A header match does not establish valid key material or malicious intent.",
    "No findings do not prove safety; this is not malware analysis or authorization.",
    "No archive, binary, obfuscation or non-UTF-8 analysis is performed.",
    "Same-process analysis is not isolation and has no enforced wall-clock deadline.",
)
_RULES = (
    ("pem.private-key", b"-----BEGIN PRIVATE KEY-----"),
    ("pem.rsa-private-key", b"-----BEGIN RSA PRIVATE KEY-----"),
    ("openssh.private-key", b"-----BEGIN OPENSSH PRIVATE KEY-----"),
)


@dataclass(frozen=True)
class Location:
    byte_offset: int  # zero-based in the exact original supplied bytes
    byte_length: int
    line: int  # one-based; CRLF, LF and CR are line breaks
    column: int  # one-based Unicode code points, not visual columns


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_version: int
    evidence_kind: str
    review_priority: str
    occurrence_count: int
    locations: tuple[Location, ...]


@dataclass(frozen=True)
class AnalysisResult:
    schema_version: int
    analyzer_version: str
    status: str  # complete means the declared rules ran, never that input is safe
    reason: str | None
    byte_count: int
    artifact_sha256: str | None
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict:
        """Return a detached JSON-compatible view, containing no source snippets."""
        result = asdict(self)
        result["limitations"] = list(result["limitations"])
        result["findings"] = list(result["findings"])
        for finding in result["findings"]:
            finding["locations"] = list(finding["locations"])
        return result


def _location(content: bytes, offset: int, length: int) -> Location:
    # Only called for at most 15 examples. Decode original prefix so offsets
    # remain byte-exact even with a UTF-8 BOM or multibyte characters.
    prefix = content[:offset].decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return Location(offset, length, prefix.count("\n") + 1, len(prefix.rsplit("\n", 1)[-1]) + 1)


def analyze_bytes(content: bytes) -> AnalysisResult:
    """Analyze an immutable byte snapshot, without acquiring or changing files.

    Wrong Python types raise TypeError before invoking any input methods.
    Unsupported content returns rejected with no findings. Oversized content
    is rejected before hashing/decoding. Unexpected internal errors propagate;
    callers must never translate errors or rejection into a clean verdict.
    """
    if type(content) is not bytes:
        raise TypeError("content must be immutable bytes")

    size = len(content)
    digest = None

    def result(status: str, reason: str | None, findings=()) -> AnalysisResult:
        return AnalysisResult(1, ANALYZER_VERSION, status, reason, size, digest, tuple(findings), LIMITATIONS)

    if size > MAX_BYTES:
        return result("rejected", "input_too_large")
    digest = sha256(content).hexdigest()
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return result("rejected", "invalid_utf8")
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        return result("rejected", "unsupported_control_character")

    findings = []
    for rule_id, marker in _RULES:
        count = 0
        locations = []
        start = 0
        while True:
            offset = content.find(marker, start)
            if offset < 0:
                break
            count += 1
            if len(locations) < MAX_LOCATIONS:
                locations.append(_location(content, offset, len(marker)))
            start = offset + len(marker)
        if count:
            findings.append(Finding(rule_id, 1, "literal_header_pattern", "review", count, tuple(locations)))
    return result("complete", None, findings)
