"""Read-only bounded projection of existing decision logs, never authority."""

from dataclasses import dataclass
from datetime import datetime
import re

from . import logger
from .actions import ACTIONS
from .json_input import loads

MAX_HISTORY_BYTES = 4 * 1024 * 1024
MAX_HISTORY_ROWS = 100
_RULES = frozenset(('missing_action', 'blocked_action', 'sensitive_target',
                    'safe_read', 'destructive_action', 'unknown_action'))
_CONTROLS = frozenset(('automatic', 'notify', 'approval', 'strong_confirm', 'blocked'))


class HistoryUnavailable(RuntimeError):
    """No current history snapshot is available; does not imply no events."""


@dataclass(frozen=True)
class DecisionSummary:
    position: int
    timestamp: str
    request_id: str
    application_id: str
    action: str
    decision: str
    policy_rule: str
    human_control: str


@dataclass(frozen=True)
class HistorySnapshot:
    status: str
    total_records: int
    records: tuple[DecisionSummary, ...]


def _known(value, choices):
    return value if type(value) is str and value in choices else 'not recorded / unrecognized'


def _timestamp(value):
    if type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value, flags=re.ASCII):
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
            return value
        except ValueError:
            pass
    return 'not recorded / unrecognized'


def project_history(payload: bytes) -> HistorySnapshot:
    """Project known fields only. Never expose free-form targets/details/reasons."""
    try:
        if type(payload) is not bytes or len(payload) > MAX_HISTORY_BYTES:
            raise ValueError()
        records = loads(payload.decode('utf-8', errors='strict'), max_depth=64)
        if type(records) is not list or any(type(row) is not dict for row in records):
            raise ValueError()
        summaries = []
        for index in range(len(records) - 1, max(-1, len(records) - MAX_HISTORY_ROWS - 1), -1):
            record = records[index]
            request_id = record.get('request_id')
            if type(request_id) is not str or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', request_id):
                request_id = 'not recorded / unrecognized'
            application_id = record.get('application_id')
            if type(application_id) is not str or not 1 <= len(application_id) <= 128:
                application_id = 'not recorded / withheld'
            summaries.append(DecisionSummary(
                index + 1, _timestamp(record.get('timestamp')), request_id, application_id,
                _known(record.get('action'), ACTIONS),
                _known(record.get('decision'), ('allow', 'deny', 'ask')),
                _known(record.get('policy_rule'), _RULES),
                _known(record.get('human_control'), _CONTROLS),
            ))
        return HistorySnapshot('available', len(records), tuple(summaries))
    except (ValueError, TypeError, RecursionError):
        raise HistoryUnavailable('History could not be read as a supported bounded snapshot') from None


def read_decision_history() -> HistorySnapshot:
    """Read configured audit file with writer coordination; never repair/reset it."""
    if not logger._LOG_LOCK.acquire(timeout=0.25):
        raise HistoryUnavailable('History is busy; refresh later')
    try:
        try:
            with logger.LOG_FILE.open('rb') as stream:
                payload = stream.read(MAX_HISTORY_BYTES + 1)
        except FileNotFoundError:
            return HistorySnapshot('missing', 0, ())
        except OSError:
            raise HistoryUnavailable('History file is unavailable') from None
    finally:
        logger._LOG_LOCK.release()
    return project_history(payload)  # parsing does not hold up audit writers
