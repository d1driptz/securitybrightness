"""Explicit mapping between legacy actions and structured operations.

This is migration metadata only. It does not authorize either representation.
"""
from types import MappingProxyType

from .protocol_identifiers import protocol_identifier


_LEGACY_TO_OPERATION = {
    "read": "files.read", "open": "files.read", "view": "files.read",
    "write": "files.write", "modify": "files.write", "overwrite": "files.write",
    "delete": "files.delete", "remove": "files.delete",
    "execute": "process.execute", "run": "process.execute",
    "send_message": "communications.send",
    "post": "communications.publish", "publish": "communications.publish",
    "share": "data.share", "purchase": "payments.purchase", "pay": "payments.pay",
    "transfer_money": "payments.transfer", "change_account": "account.change",
    "delete_account": "account.delete",
    "delete_system_file": "action.delete_system_file",
    "disable_security": "action.disable_security",
    "bypass_permission": "action.bypass_permission",
}
LEGACY_TO_OPERATION = MappingProxyType(_LEGACY_TO_OPERATION)
del _LEGACY_TO_OPERATION


def structured_operation_for_legacy_action(action):
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    normalized = protocol_identifier(action, "legacy action")
    if normalized not in LEGACY_TO_OPERATION:
        raise ValueError("legacy action has no explicit structured-operation mapping")
    return protocol_identifier(LEGACY_TO_OPERATION[normalized], "operation")
