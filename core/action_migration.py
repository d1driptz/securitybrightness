"""Explicit mapping between legacy actions and structured operations.

This is migration metadata only. It does not authorize either representation.
"""
from types import MappingProxyType

from .actions import ACTIONS
from .protocol_identifiers import protocol_identifier


_LEGACY_TO_OPERATION = {
    action: descriptor.required_scope
    for action, descriptor in ACTIONS.items()
}
LEGACY_TO_OPERATION = MappingProxyType(_LEGACY_TO_OPERATION)
del _LEGACY_TO_OPERATION


def structured_operation_for_legacy_action(action):
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    normalized = action.strip().lower()
    if normalized not in LEGACY_TO_OPERATION:
        raise ValueError("legacy action has no explicit structured-operation mapping")
    return protocol_identifier(LEGACY_TO_OPERATION[normalized], "operation")
