"""Discoverable action vocabulary; descriptors are not permission grants."""
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ActionDescriptor:
    action: str
    category: str
    required_scope: str
    baseline_control: str


CONTROL_RISKS = MappingProxyType({
    "automatic": "low", "notify": "low", "approval": "elevated",
    "strong_confirm": "high", "blocked": "prohibited",
})

_GROUPS = (
    (("read", "open", "view"), "files", "files.read", "automatic"),
    (("write", "modify", "overwrite"), "files", "files.write", "approval"),
    (("delete", "remove"), "files", "files.delete", "approval"),
    (("execute", "run"), "process", "process.execute", "approval"),
    (("send_message",), "communications", "communications.send", "strong_confirm"),
    (("post", "publish"), "communications", "communications.publish", "strong_confirm"),
    (("share",), "data", "data.share", "strong_confirm"),
    (("purchase",), "payments", "payments.purchase", "strong_confirm"),
    (("pay",), "payments", "payments.pay", "strong_confirm"),
    (("transfer_money",), "payments", "payments.transfer", "strong_confirm"),
    (("change_account",), "account", "account.change", "strong_confirm"),
    (("delete_account",), "account", "account.delete", "strong_confirm"),
)
_catalog = {
    action: ActionDescriptor(action, category, scope, control)
    for actions, category, scope, control in _GROUPS for action in actions
}
for _action in ("delete_system_file", "disable_security", "bypass_permission"):
    _catalog[_action] = ActionDescriptor(_action, "security", "action." + _action, "blocked")
ACTIONS = MappingProxyType(_catalog)
del _catalog


def describe_action(action: str) -> ActionDescriptor:
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    action = action.strip().lower()
    return ACTIONS.get(action, ActionDescriptor(action, "unknown", "action." + (action or "unknown"), "approval"))


def list_actions() -> tuple[ActionDescriptor, ...]:
    """Return immutable descriptors for UI/tool adapters, never authorization."""
    return tuple(ACTIONS[name] for name in sorted(ACTIONS))
