import http.client
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from core.authority_store import SQLiteAuthorityStore, AuthorityStoreError
from core.registry import ApplicationRegistry, AuthorityInactiveError
from core.review_channel import OperatorReviewChannel
from core.sdk import ApplicationClient, SDKError
from core.service import create_server


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.db"
        self.registry = self.open_registry()

    def open_registry(self):
        registry = ApplicationRegistry(store=SQLiteAuthorityStore(self.path))
        self.addCleanup(registry.close)
        return registry

    def unlock(self):
        app = self.registry.list_applications()[0]
        self.assertTrue(self.registry.operator_unlock(app.application_id, app.grant_id))
        return app

    def test_restart_never_restores_activation_or_raw_credential(self):
        credential = self.registry.register("app", ["files.read"], trusted=True)
        summary = self.registry.list_applications()[0]
        self.assertFalse(summary.active)
        self.assertEqual(summary.lifetime, "persistent")
        self.assertTrue(summary.created_at.endswith("Z"))
        self.assertIsNone(summary.expires_at)
        self.assertIsNone(self.registry.authenticate("app", credential))
        self.unlock()
        self.assertIsNotNone(self.registry.authenticate("app", credential))
        self.registry.close()
        self.assertNotIn(credential.encode(), self.path.read_bytes())
        self.registry = self.open_registry()
        self.assertEqual(self.registry.list_applications()[0], summary)
        self.assertIsNone(self.registry.authenticate("app", credential))
        self.unlock()
        self.assertIsNotNone(self.registry.authenticate("app", credential))

    def test_inactive_revocation_and_rotation_are_durable(self):
        old = self.registry.register("app", ["files.read"])
        previous = self.registry.list_applications()[0]
        fresh = self.registry.rotate_credential("app")
        self.assertFalse(self.registry.operator_unlock("app", previous.grant_id))
        self.assertIsNone(self.registry.authenticate("app", old, allow_inactive=True))
        self.registry.close()
        self.registry = self.open_registry()
        self.assertIsNotNone(self.registry.authenticate("app", fresh, allow_inactive=True))
        self.assertFalse(self.registry.list_applications()[0].active)
        current = self.registry.list_applications()[0]
        self.assertTrue(self.registry.operator_revoke("app", current.grant_id))
        self.registry.close()
        self.registry = self.open_registry()
        self.assertEqual(self.registry.list_applications(), ())
        self.assertIsNone(self.registry.authenticate("app", fresh, allow_inactive=True))

    def test_admin_changes_do_not_inherit_activation_and_old_views_cannot_unlock(self):
        credential = self.registry.register("app", ["files.read"])
        old = self.unlock()
        self.registry.update_permissions("app", scopes=["*"])
        self.assertFalse(self.registry.list_applications()[0].active)
        self.assertFalse(self.registry.operator_unlock("app", old.grant_id))
        self.assertFalse(self.registry.operator_revoke("app", old.grant_id))
        self.assertIsNone(self.registry.authenticate("app", credential))
        self.unlock()
        self.assertIsNotNone(self.registry.authenticate("app", credential))

    def test_single_writer_store_rejects_second_owner_without_resetting(self):
        self.registry.register("app", ["files.read"])
        with self.assertRaises(AuthorityStoreError):
            SQLiteAuthorityStore(self.path)
        self.registry.close()
        self.registry = self.open_registry()
        self.assertEqual(len(self.registry.list_applications()), 1)

    def test_storage_failure_never_publishes_change_and_deactivates_authority(self):
        credential = self.registry.register("app", ["files.read"])
        self.unlock()
        previous = self.registry.get("app")
        with patch.object(self.registry._store, "save", side_effect=AuthorityStoreError("disk failure")):
            with self.assertRaises(AuthorityStoreError):
                self.registry.update_permissions("app", scopes=["*"])
        self.assertIs(self.registry.get("app"), previous)
        self.assertIsNone(self.registry.authenticate("app", credential))
        self.assertFalse(self.registry.operator_unlock("app", previous.grant_id))
        self.registry.close()
        self.registry = self.open_registry()
        self.assertEqual(self.registry.get("app").scopes, frozenset({"files.read"}))
        self.assertFalse(self.registry.list_applications()[0].active)

    def test_real_database_write_denial_rolls_back_and_locks_registry(self):
        credential = self.registry.register("app", ["files.read"])
        self.unlock()
        connection = self.registry._store._connection
        connection.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_UPDATE else sqlite3.SQLITE_OK)
        try:
            with self.assertRaises(AuthorityStoreError):
                self.registry.revoke("app")
        finally:
            connection.set_authorizer(None)
        self.assertFalse(connection.in_transaction)
        self.assertEqual(len(self.registry._store.load()), 1)
        self.assertIsNone(self.registry.authenticate("app", credential))

    def test_corrupt_unknown_version_or_active_fields_are_rejected(self):
        self.registry.register("app", ["files.read"])
        records = self.registry._store.load()
        self.registry.close()
        payloads = ["not json", json.dumps({"version": 2, "applications": records}),
                    json.dumps({"version": True, "applications": records}),
                    json.dumps({"version": 1, "applications": [{**records[0], "active": True}]}),
                    json.dumps({"version": 1, "applications": [{**records[0], "expires_at": "tomorrow"}]}),
                    json.dumps({"version": 1, "applications": [{**records[0], "lifetime": "one-shot"}]})]
        for payload in payloads:
            with self.subTest(payload=payload[:40]):
                with closing(sqlite3.connect(self.path)) as connection:
                    connection.execute("UPDATE authority SET payload=?", (payload,))
                    connection.commit()
                with self.assertRaises(AuthorityStoreError):
                    self.open_registry()
                with closing(sqlite3.connect(self.path)) as connection:
                    self.assertEqual(connection.execute("SELECT payload FROM authority").fetchone()[0], payload)

    def test_lock_then_reunlock_does_not_revive_authorization_lease(self):
        credential = self.registry.register("app", ["files.read"])
        self.unlock()
        lease = self.registry.authorization_lease(self.registry.authenticate("app", credential))
        self.registry.lock_all()
        self.unlock()
        with self.assertRaises(AuthorityInactiveError), lease():
            pass

    def test_truncated_file_is_not_silently_reinitialized(self):
        self.registry.close()
        self.path.write_bytes(b"not-a-database")
        with self.assertRaises(AuthorityStoreError):
            self.open_registry()
        self.assertEqual(self.path.read_bytes(), b"not-a-database")


class PersistentServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.registry = ApplicationRegistry(store=SQLiteAuthorityStore(self.path / "authority.db"))
        self.channel = OperatorReviewChannel(timeout=1.5)
        self.server = create_server(port=0, token="admin", registry=self.registry, approval_provider=self.channel)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.log = self.path / "events.json"
        self.logging = patch("core.logger.LOG_FILE", self.log)
        self.logging.start()

    def tearDown(self):
        self.channel.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.registry.close()
        self.logging.stop()
        self.temp.cleanup()

    def post(self, path, body, token="admin", app=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if app is not None:
            headers["X-SecurityBrightness-App"] = app
        try:
            connection.request("POST", path, json.dumps(body), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_application_admin_and_caller_flags_cannot_unlock(self):
        credential = self.registry.register("app", ["files.read"])
        client = ApplicationClient("app", credential, port=self.server.server_port, timeout=2)
        with self.assertRaises(SDKError) as caught:
            client.check("read", "notes", details={"unlocked": True, "active": True})
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(self.post("/check", {"action": "read", "target": "notes"})[0], 403)
        for token, app in (("admin", None), (credential, "app")):
            self.assertEqual(self.post("/unlock", {"application_id": "app"}, token, app)[0], 404)
        self.assertEqual(self.post("/permissions", {"application_id": "app", "scopes": ["*"]})[0], 200)
        self.assertFalse(self.registry.list_applications()[0].active)
        self.assertFalse(self.log.exists())
        current = self.registry.list_applications()[0]
        self.assertTrue(self.registry.operator_unlock(current.application_id, current.grant_id))
        self.assertTrue(client.check("read", "notes").allowed)
        self.assertEqual(json.loads(self.log.read_text())[0]["decision"], "allow")

    def test_revocation_rotation_change_and_relocking_during_review_fail_closed(self):
        for mutation in ("revoke", "rotate", "scopes", "lock", "lock_then_unlock"):
            with self.subTest(mutation=mutation):
                app_id = "app-" + mutation
                credential = self.registry.register(app_id, ["communications.send"])
                snapshot = self.registry.get(app_id)
                self.registry.operator_unlock(app_id, snapshot.grant_id)
                client = ApplicationClient(app_id, credential, port=self.server.server_port, timeout=2)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(client.check, "send_message", "recipient")
                    deadline = time.monotonic() + 1
                    while not self.channel.pending_reviews() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    reviews = self.channel.pending_reviews()
                    self.assertEqual(len(reviews), 1)
                    if mutation == "revoke":
                        self.registry.revoke(app_id)
                    elif mutation == "rotate":
                        self.registry.rotate_credential(app_id)
                    elif mutation == "scopes":
                        self.registry.set_scopes(app_id, ["*"])
                    else:
                        self.registry.lock_all()
                        if mutation == "lock_then_unlock":
                            self.registry.operator_unlock(app_id, snapshot.grant_id)
                    self.assertTrue(self.channel.respond(reviews[0].review_id, True, confirmation="ALLOW"))
                    with self.assertRaises(SDKError) as caught:
                        future.result(timeout=2)
                    self.assertEqual(caught.exception.status, 503)
        self.assertFalse(self.log.exists(), "stale authority must never produce an allow audit record")

    def test_failed_admin_commit_returns_503_and_preserves_previous_state(self):
        self.registry.register("app", ["files.read"])
        with patch.object(self.registry._store, "save", side_effect=AuthorityStoreError("failure")):
            status, body = self.post("/revoke", {"application_id": "app"})
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "authority_unavailable")
        self.assertIsNotNone(self.registry.get("app"))
        self.assertFalse(self.registry.list_applications()[0].active)
