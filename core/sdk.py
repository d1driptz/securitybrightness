"""Registered-application SDK. Proposals and decisions only; no execution hooks."""
import math
from dataclasses import dataclass, fields
from http.client import HTTPException
from urllib import error, request

from .actions import CONTROL_RISKS, describe_action
from .proposal import ActionProposal, MAX_MESSAGE_BYTES
from .json_input import loads as strict_json_loads
from .validation import application_id as validate_application_id



class SDKError(RuntimeError):
    def __init__(self, code, *, status=None, outcome_unknown=None):
        self.code = code
        self.status = status
        self.outcome_unknown = code == "invalid_response" if outcome_unknown is None else outcome_unknown
        super().__init__(code)


class ActionDenied(SDKError):
    def __init__(self, result):
        self.result = result
        super().__init__("action_denied")


@dataclass(frozen=True)
class AuthorizationResult:
    request_id: str
    timestamp: str
    decision: str
    decision_source: str
    policy_rule: str
    human_control: str
    application_id: str
    application_trust: str
    authenticated: bool
    required_scope: str
    scope_granted: bool
    reason: str
    action_category: str
    risk_level: str
    review_reason: str

    @property
    def allowed(self):
        return self.decision == "allow"

    def require_allowed(self):
        if not self.allowed:
            raise ActionDenied(self)
        return self

    def __bool__(self):
        raise TypeError("Use result.allowed explicitly; a result object is not permission")

    @classmethod
    def _from_payload(cls, payload, application_id, action):
        if not isinstance(payload, dict):
            raise SDKError("invalid_response")
        values = {}
        for field in fields(cls):
            value = payload.get(field.name)
            if field.name in {"authenticated", "scope_granted"}:
                if type(value) is not bool:
                    raise SDKError("invalid_response")
            elif not isinstance(value, str) or not value.strip():
                raise SDKError("invalid_response")
            values[field.name] = value
        if (values["decision"] not in {"allow", "deny"}
                or values["decision_source"] not in {"policy", "scope", "user"}
                or values["human_control"] not in {"automatic", "notify", "approval", "strong_confirm", "blocked"}
                or values["application_trust"] not in {"recognized", "trusted"}
                or values["risk_level"] not in {"low", "elevated", "high", "prohibited"}
                or values["application_id"] != application_id
                or not values["authenticated"]
                or values["required_scope"] != describe_action(action).required_scope):
            raise SDKError("invalid_response")
        descriptor = describe_action(action)
        levels = {"automatic": 0, "notify": 0, "approval": 1, "strong_confirm": 2, "blocked": 3}
        if (values["action_category"] != descriptor.category
                or levels[values["human_control"]] < levels[descriptor.baseline_control]
                or values["risk_level"] != CONTROL_RISKS[values["human_control"]]):
            raise SDKError("invalid_response")
        if values["decision"] == "allow" and (
                not values["scope_granted"] or values["human_control"] == "blocked"
                or values["decision_source"] == "scope"
                or (values["human_control"] in {"approval", "strong_confirm"}
                    and values["decision_source"] != "user")):
            raise SDKError("invalid_response")
        return cls(**values)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ApplicationClient:
    """Use a registered credential with the loopback service; never retries checks."""
    def __init__(self, application_id, credential, *, port=8765, timeout=60):
        self.application_id = validate_application_id(application_id)
        if any(not 33 <= ord(c) <= 126 for c in self.application_id):
            raise ValueError("SDK application_id must be printable ASCII without spaces")
        if not isinstance(credential, str) or not credential or any(not 33 <= ord(c) <= 126 for c in credential):
            raise ValueError("credential must be nonempty printable ASCII without spaces")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be an integer from 1 to 65535")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        self._credential = credential
        self._url = f"http://127.0.0.1:{port}/check"
        self._timeout = timeout
        self._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())

    def check(self, action, target, *, details=None):
        return self.check_proposal(ActionProposal(action, target, details=details))

    def check_proposal(self, proposal):
        """Submit one prepared snapshot; never cache, retry, or execute it."""
        if not isinstance(proposal, ActionProposal):
            raise TypeError("proposal must be an ActionProposal")
        body = proposal._body
        req = request.Request(self._url, data=body, method="POST", headers={
            "Authorization": "Bearer " + self._credential,
            "X-SecurityBrightness-App": self.application_id,
            "Content-Type": "application/json",
        })
        try:
            with self._opener.open(req, timeout=self._timeout) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise SDKError("invalid_response")
                raw = response.read(MAX_MESSAGE_BYTES + 1)
                if len(raw) > MAX_MESSAGE_BYTES:
                    raise SDKError("invalid_response")
                try:
                    payload = strict_json_loads(raw.decode("utf-8"))
                except (UnicodeError, ValueError):
                    raise SDKError("invalid_response") from None
                return AuthorizationResult._from_payload(payload, self.application_id, proposal.action)
        except error.HTTPError as exc:
            status = exc.code
            exc.close()
            code = {401: "invalid_application_credentials", 400: "invalid_request",
                    408: "request_timeout", 413: "request_too_large", 415: "unsupported_content_type",
                    503: "service_unavailable"}.get(status, "request_failed")
            raise SDKError(code, status=status, outcome_unknown=status not in {400, 401, 408, 413, 415}) from None
        except (error.URLError, OSError, HTTPException):
            raise SDKError("transport_error", outcome_unknown=True) from None
