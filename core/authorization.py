from dataclasses import dataclass, field

from .scopes import normalize_scopes


@dataclass(frozen=True)
class AuthorizationContext:
    application_id: str
    authenticated: bool = False
    trusted: bool = False
    granted_scopes: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def authenticated_application(cls, application_id, scopes=None, trusted=False):
        application_id = str(application_id).strip()
        if not application_id:
            raise ValueError("application_id is required")
        return cls(
            application_id=application_id,
            authenticated=True,
            trusted=bool(trusted),
            granted_scopes=frozenset(normalize_scopes(scopes)),
        )

    def apply(self, details=None):
        merged = dict(details or {})
        reserved = {"application_id", "authenticated", "trust", "granted_scopes"}
        if reserved.intersection(merged):
            raise ValueError("authorization fields must come from AuthorizationContext")
        merged.update({
            "application_id": self.application_id,
            "authenticated": self.authenticated,
            "trust": "trusted" if self.trusted else "recognized",
            "granted_scopes": sorted(self.granted_scopes),
        })
        return merged
