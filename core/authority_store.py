"""Opt-in local SQLite authority storage; activation is never persisted."""
import json
import os
from pathlib import Path
import sqlite3
from threading import RLock

from .json_input import loads

MAX_STORE_BYTES = 4 * 1024 * 1024
_SCHEMA = "CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL)"


class AuthorityStoreError(RuntimeError):
    """Storage is unavailable or invalid; authority must not be used."""


class SQLiteAuthorityStore:
    def __init__(self, path):
        self._lock = RLock()
        self._connection = None
        path = Path(path).absolute()
        try:
            if path.is_symlink() or str(path).startswith("\\\\"):
                raise ValueError("use a private local file, not a symlink or UNC path")
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                created = False
            else:
                os.close(descriptor)
                created = True
            connection = sqlite3.connect(str(path), timeout=0.1, isolation_level=None, check_same_thread=False)
            self._connection = connection
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("unsupported authority journal mode")
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("PRAGMA locking_mode=EXCLUSIVE")
            connection.execute("BEGIN EXCLUSIVE")
            if created:
                connection.execute(_SCHEMA)
                connection.execute("INSERT INTO authority VALUES (1, ?)",
                                   (json.dumps({"version": 1, "applications": []}),))
            else:
                schema = connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
                if schema != [("table", "authority", _SCHEMA)]:
                    raise ValueError("unexpected authority schema")
            connection.execute("COMMIT")
            self.load()
        except (OSError, sqlite3.Error, ValueError, TypeError, AuthorityStoreError) as exc:
            self.close()
            raise AuthorityStoreError("authority store could not be opened safely") from exc

    def load(self):
        with self._lock:
            try:
                if self._connection is None:
                    raise ValueError("store closed")
                rows = self._connection.execute("SELECT id, length(payload) FROM authority").fetchall()
                if len(rows) != 1 or rows[0][0] != 1 or not 0 < rows[0][1] <= MAX_STORE_BYTES:
                    raise ValueError("invalid authority record")
                text = self._connection.execute("SELECT payload FROM authority WHERE id=1").fetchone()[0]
                value = loads(text)
                if (not isinstance(value, dict) or set(value) != {"version", "applications"}
                        or type(value["version"]) is not int or value["version"] != 1
                        or not isinstance(value["applications"], list)):
                    raise ValueError("unsupported authority document")
                return value["applications"]
            except (sqlite3.Error, ValueError, TypeError) as exc:
                raise AuthorityStoreError("authority store is invalid or unavailable") from exc

    def save(self, applications):
        with self._lock:
            try:
                if self._connection is None:
                    raise ValueError("store closed")
                text = json.dumps({"version": 1, "applications": applications}, ensure_ascii=True, allow_nan=False)
                loads(text)
                if len(text.encode("utf-8")) > MAX_STORE_BYTES:
                    raise ValueError("authority store size limit exceeded")
                self._connection.execute("BEGIN EXCLUSIVE")
                changed = self._connection.execute("UPDATE authority SET payload=? WHERE id=1", (text,))
                if changed.rowcount != 1:
                    raise ValueError("missing authority record")
                self._connection.execute("COMMIT")
            except (sqlite3.Error, ValueError, TypeError) as exc:
                if self._connection is not None and self._connection.in_transaction:
                    try:
                        self._connection.rollback()
                    except sqlite3.Error:
                        pass
                raise AuthorityStoreError("authority update could not be committed") from exc

    def close(self):
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
