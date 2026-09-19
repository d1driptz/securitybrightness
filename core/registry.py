import hashlib
import hmac
import secrets
from dataclasses import dataclass, field


@dataclass
class RegisteredApplication:
    application_id: str
    credential_hash: str
    scopes: set[str] = field(default_factory=set)
    trusted: bool = False


class ApplicationRegistry:
    def __init__(self):
        self._applications = {}

    @staticmethod
    def _hash_credential(credential: str) -> str:
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()

    def register(self, application_id: str, scopes=None, trusted=False):
        application_id = str(application_id).strip()
        if not application_id:
            raise ValueError("application_id is required")
        if application_id in self._applications:
            raise ValueError("application is already registered")

        credential = secrets.token_urlsafe(32)
        self._applications[application_id] = RegisteredApplication(
            application_id=application_id,
            credential_hash=self._hash_credential(credential),
            scopes={str(scope).strip().lower() for scope in (scopes or []) if str(scope).strip()},
            trusted=bool(trusted),
        )
        return credential

    def revoke(self, application_id: str) -> bool:
        application_id = str(application_id).strip()
        return self._applications.pop(application_id, None) is not None

    def rotate_credential(self, application_id: str):
        application_id = str(application_id).strip()
        application = self._applications.get(application_id)
        if application is None:
            raise KeyError("application is not registered")

        credential = secrets.token_urlsafe(32)
        application.credential_hash = self._hash_credential(credential)
        return credential

    def authenticate(self, application_id: str, credential: str):
        application = self._applications.get(str(application_id).strip())
        if application is None or not isinstance(credential, str):
            return None

        supplied_hash = self._hash_credential(credential)
        if not hmac.compare_digest(supplied_hash, application.credential_hash):
            return None
        return application
