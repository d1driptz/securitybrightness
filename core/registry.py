import hashlib
import hmac
import secrets
from dataclasses import dataclass, field, replace
from threading import RLock

from .scopes import normalize_scopes
from .validation import application_id as validate_application_id, boolean


@dataclass(frozen=True)
class RegisteredApplication:
    application_id: str
    credential_hash: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    trusted: bool = False


class ApplicationRegistry:
    def __init__(self):
        self._applications = {}
        self._lock = RLock()

    @staticmethod
    def _hash_credential(credential: str) -> str:
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()

    def register(self, application_id: str, scopes=None, trusted=False):
        with self._lock:
            application_id = validate_application_id(application_id)
            if application_id in self._applications:
                raise ValueError("application is already registered")

            credential = secrets.token_urlsafe(32)
            self._applications[application_id] = RegisteredApplication(
                application_id=application_id,
                credential_hash=self._hash_credential(credential),
                scopes=frozenset(normalize_scopes(scopes)),
                trusted=boolean(trusted, "trusted"),
            )
            return credential

    def get(self, application_id: str):
        with self._lock:
            return self._applications.get(validate_application_id(application_id))

    def update_permissions(self, application_id: str, **changes):
        """Validate all fields before replacing one immutable registry snapshot."""
        with self._lock:
            application_id = validate_application_id(application_id)
            if set(changes) - {"scopes", "trusted"}:
                raise TypeError("unknown permission fields")
            if "scopes" in changes:
                changes["scopes"] = frozenset(normalize_scopes(changes["scopes"]))
            if "trusted" in changes:
                changes["trusted"] = boolean(changes["trusted"], "trusted")
            application = self.get(application_id)
            if application is None:
                raise KeyError("application is not registered")
            updated = replace(application, **changes)
            self._applications[application_id] = updated
            return updated

    def set_scopes(self, application_id: str, scopes):
        with self._lock:
            return set(self.update_permissions(application_id, scopes=scopes).scopes)

    def set_trusted(self, application_id: str, trusted: bool):
        with self._lock:
            return self.update_permissions(application_id, trusted=trusted).trusted

    def revoke(self, application_id: str) -> bool:
        with self._lock:
            application_id = validate_application_id(application_id)
            return self._applications.pop(application_id, None) is not None

    def rotate_credential(self, application_id: str):
        with self._lock:
            application = self.get(application_id)
            if application is None:
                raise KeyError("application is not registered")

            credential = secrets.token_urlsafe(32)
            self._applications[application.application_id] = replace(
                application, credential_hash=self._hash_credential(credential),
            )
            return credential

    def authenticate(self, application_id: str, credential: str):
        with self._lock:
            try:
                application = self.get(application_id)
            except (TypeError, ValueError):
                return None
            if application is None or not isinstance(credential, str) or not credential:
                return None

            try:
                supplied_hash = self._hash_credential(credential)
            except UnicodeEncodeError:
                return None
            if not hmac.compare_digest(supplied_hash, application.credential_hash):
                return None
            return application
