from dataclasses import dataclass, field

from .scopes import normalize_scopes
from .validation import application_id as validate_application_id, boolean


@dataclass(frozen=True)
class AuthorizationContext:
    application_id: str
    authenticated: bool = False
    trusted: bool = False
    granted_scopes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self):
        object.__setattr__(self, "application_id", validate_application_id(self.application_id))
        boolean(self.authenticated, "authenticated")
        boolean(self.trusted, "trusted")
        object.__setattr__(self, "granted_scopes", frozenset(normalize_scopes(self.granted_scopes)))

    @classmethod
    def authenticated_application(cls, application_id, scopes=None, trusted=False):
        return cls(
            application_id=application_id,
            authenticated=True,
            trusted=trusted,
            granted_scopes=frozenset(normalize_scopes(scopes)),
        )

    def validate_details(self, details=None):
        if details is not None and not isinstance(details, dict):
            raise TypeError("details must be a dictionary")
        merged = dict(details or {})
        reserved = {"application_id", "authenticated", "trust", "granted_scopes"}
        if reserved.intersection(merged):
            raise ValueError("authorization fields must come from AuthorizationContext")
        return merged

    def apply(self, details=None):
        """Legacy trusted-Python adapter; service events keep context separate."""
        merged = self.validate_details(details)
        merged.update({
            "application_id": self.application_id,
            "authenticated": self.authenticated,
            "trust": "trusted" if self.trusted else "recognized",
            "granted_scopes": sorted(self.granted_scopes),
        })
        return merged
