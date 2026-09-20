import hashlib
import hmac
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from threading import RLock
from uuid import UUID, uuid4

from .authority_store import AuthorityStoreError
from .scopes import normalize_scopes
from .validation import application_id as validate_application_id, boolean


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class AuthorityInactiveError(RuntimeError):
    """The current grant is inactive, unavailable or no longer applicable."""


@dataclass(frozen=True)
class RegisteredApplication:
    application_id: str
    credential_hash: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    trusted: bool = False
    grant_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    lifetime: str = "session"
    expires_at: str | None = None


@dataclass(frozen=True)
class ApplicationSummary:
    """Operator view; no credential material or activation capability."""
    application_id: str
    scopes: frozenset[str]
    trusted: bool
    grant_id: str
    created_at: str
    updated_at: str
    lifetime: str
    expires_at: str | None
    active: bool


def _serialize(app):
    return {"application_id": app.application_id, "credential_hash": app.credential_hash,
            "scopes": sorted(app.scopes), "trusted": app.trusted, "grant_id": app.grant_id,
            "created_at": app.created_at, "updated_at": app.updated_at,
            "lifetime": app.lifetime, "expires_at": app.expires_at}


def _restore(record):
    expected = {"application_id", "credential_hash", "scopes", "trusted", "grant_id",
                "created_at", "updated_at", "lifetime", "expires_at"}
    if not isinstance(record, dict) or set(record) != expected:
        raise ValueError("invalid stored grant fields")
    app_id = validate_application_id(record["application_id"])
    if app_id != record["application_id"]:
        raise ValueError("noncanonical stored identity")
    if not isinstance(record["credential_hash"], str) or not re.fullmatch("[0-9a-f]{64}", record["credential_hash"]):
        raise ValueError("invalid credential hash")
    scopes = record["scopes"]
    if not isinstance(scopes, list) or scopes != sorted(normalize_scopes(scopes)):
        raise ValueError("invalid stored scopes")
    boolean(record["trusted"], "trusted")
    if not isinstance(record["grant_id"], str) or str(UUID(record["grant_id"])) != record["grant_id"]:
        raise ValueError("invalid grant identity")
    for key in ("created_at", "updated_at"):
        value = record[key]
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("invalid grant timestamp")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
            raise ValueError("noncanonical grant timestamp")
    if record["updated_at"] < record["created_at"]:
        raise ValueError("invalid grant chronology")
    if record["lifetime"] != "persistent" or record["expires_at"] is not None:
        raise ValueError("unsupported lifetime; no implicit expiry or one-shot semantics")
    return RegisteredApplication(**{**record, "scopes": frozenset(scopes)})


class ApplicationRegistry:
    def __init__(self, *, store=None):
        self._applications = {}
        self._lock = RLock()
        self._store = store
        self._active = {}
        self._failed = False
        self._closed = False
        if store is not None:
            try:
                for record in store.load():
                    app = _restore(record)
                    if app.application_id in self._applications:
                        raise ValueError("duplicate stored identity")
                    self._applications[app.application_id] = app
            except (AuthorityStoreError, TypeError, ValueError) as exc:
                store.close()
                raise AuthorityStoreError("stored authority failed validation") from exc

    @property
    def persistent(self):
        return self._store is not None

    @staticmethod
    def _hash_credential(credential: str) -> str:
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()

    def _commit(self, applications):
        if self._failed or self._closed:
            raise AuthorityStoreError("authority registry unavailable")
        if self._store is not None:
            try:
                self._store.save([_serialize(app) for _, app in sorted(applications.items())])
            except AuthorityStoreError:
                self._failed = True
                self._active.clear()
                raise
        self._applications = applications

    def register(self, application_id: str, scopes=None, trusted=False):
        with self._lock:
            application_id = validate_application_id(application_id)
            if application_id in self._applications:
                raise ValueError("application is already registered")
            credential = secrets.token_urlsafe(32)
            now = _now()
            app = RegisteredApplication(
                application_id, self._hash_credential(credential),
                frozenset(normalize_scopes(scopes)), boolean(trusted, "trusted"),
                created_at=now, updated_at=now,
                lifetime="persistent" if self.persistent else "session")
            self._commit({**self._applications, application_id: app})
            return credential

    def get(self, application_id: str):
        with self._lock:
            return self._applications.get(validate_application_id(application_id))

    def _is_active(self, app):
        return (not self._closed and not self._failed
                and self._applications.get(app.application_id) is app
                and (not self.persistent or self._active.get(app.application_id, (None,))[0] == app.grant_id))

    def list_applications(self) -> tuple[ApplicationSummary, ...]:
        with self._lock:
            return tuple(ApplicationSummary(
                app.application_id, app.scopes, app.trusted, app.grant_id,
                app.created_at, app.updated_at, app.lifetime, app.expires_at, self._is_active(app))
                for _, app in sorted(self._applications.items()))

    def operator_unlock(self, application_id, grant_id):
        """Trusted operator-only method, never exposed through application/admin HTTP."""
        with self._lock:
            app = self.get(application_id)
            if (not self.persistent or self._failed or self._closed or app is None
                    or not isinstance(grant_id, str) or app.grant_id != grant_id):
                return False
            if not self._is_active(app):
                self._active[app.application_id] = (app.grant_id, str(uuid4()))
            return True

    def lock_all(self):
        with self._lock:
            self._active.clear()

    @contextmanager
    def authorization_guard(self, application):
        # Final validation + audit commit serialize with lifecycle changes.
        with self._lock:
            if not self._is_active(application):
                raise AuthorityInactiveError("authority locked, changed or unavailable")
            yield

    def authorization_lease(self, application):
        """Capture activation identity now; locking/re-unlocking cannot revive it."""
        with self._lock:
            if not self._is_active(application):
                raise AuthorityInactiveError("authority locked, changed or unavailable")
            activation = self._active.get(application.application_id)
        @contextmanager
        def final_check():
            with self.authorization_guard(application):
                if self._active.get(application.application_id) != activation:
                    raise AuthorityInactiveError("authority activation changed during review")
                yield
        return final_check

    def operator_revoke(self, application_id, grant_id):
        with self._lock:
            app = self.get(application_id)
            if app is None or app.grant_id != grant_id:
                return False
            return self.revoke(application_id)

    def update_permissions(self, application_id: str, **changes):
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
            updated = replace(application, **changes, grant_id=str(uuid4()),
                              updated_at=max(_now(), application.updated_at))
            self._commit({**self._applications, application_id: updated})
            self._active.pop(application_id, None)
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
            if application_id not in self._applications:
                return False
            applications = dict(self._applications)
            del applications[application_id]
            self._commit(applications)
            self._active.pop(application_id, None)
            return True

    def rotate_credential(self, application_id: str):
        with self._lock:
            application = self.get(application_id)
            if application is None:
                raise KeyError("application is not registered")
            credential = secrets.token_urlsafe(32)
            updated = replace(application, credential_hash=self._hash_credential(credential),
                              grant_id=str(uuid4()), updated_at=max(_now(), application.updated_at))
            self._commit({**self._applications, application.application_id: updated})
            self._active.pop(application.application_id, None)
            return credential

    def authenticate(self, application_id: str, credential: str, *, allow_inactive=False):
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
            return application if allow_inactive is True or self._is_active(application) else None

    def close(self):
        with self._lock:
            self._closed = True
            self._active.clear()
            if self._store is not None:
                self._store.close()
