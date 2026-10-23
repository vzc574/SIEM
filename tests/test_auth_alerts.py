import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from siem.api.server import AlertFileSync, create_server, parse_named_api_keys
from siem.pipeline.worker import run_incremental
from siem.storage.sqlite import SqliteEventStore

PASSWORD = "correct-horse-battery"


def _alert(event_id: str, severity: str = "high", rule_id: str = "auth.failed-login", **evidence) -> dict:
    return {"alert_id": f"a-{event_id}-{rule_id}", "rule_id": rule_id, "title": "t", "severity": severity,
            "event_id": event_id, "reason": "r", "recommended_action": "x", "evidence": evidence,
            "created_at": datetime.now(timezone.utc).isoformat()}


class AlertStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.store = SqliteEventStore(self.root / "siem.db")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_alerts_are_unique_by_key_and_searchable(self) -> None:
        self.assertEqual(len(self.store.append_alerts([_alert("e1"), _alert("e2", "medium")])), 2)
        duplicate = {**_alert("e1"), "alert_id": "different-id"}
        self.assertEqual(self.store.append_alerts([duplicate]), [])
        self.assertEqual([a["event_id"] for a in self.store.search_alerts(severity="medium")], ["e2"])
        self.assertEqual(self.store.alert_summary()["by_severity"], {"high": 1, "medium": 1})

    def test_alert_file_sync_imports_only_new_lines(self) -> None:
        path = self.root / "alerts.jsonl"
        path.write_text(json.dumps(_alert("e1")) + "\n", encoding="utf-8")
        sync = AlertFileSync(self.store, [path])
        self.assertEqual(sync.sync(), 1)
        self.assertEqual(sync.sync(), 0)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(_alert("e2")) + "\n" + '{"partial": ')
        self.assertEqual(sync.sync(), 1)
        self.assertEqual(len(self.store.search_alerts()), 2)

    def test_worker_deduplicates_through_the_database(self) -> None:
        events = self.root / "events.jsonl"
        record = {"event_id": "e1", "source": "t", "event_type": "login.failed", "message": "m", "severity": "medium",
                  "observed_at": "2026-09-23T10:00:00+00:00", "attributes": {}}
        events.write_text(json.dumps(record) + "\n", encoding="utf-8")
        output, state, database = self.root / "out.jsonl", self.root / "s.json", self.root / "siem.db"
        self.assertEqual(run_incremental(events, output, state, incident_database=database), 1)
        state.unlink()  # force a full replay
        self.assertEqual(run_incremental(events, output, state, incident_database=database), 0)
        self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)


class UserTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.store = SqliteEventStore(Path(self._directory.name) / "siem.db")
        self.store.create_user("alice", PASSWORD, "analyst")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_authentication(self) -> None:
        self.assertEqual(self.store.authenticate("alice", PASSWORD), "analyst")
        self.assertIsNone(self.store.authenticate("alice", "wrong-password-123"))
        self.assertIsNone(self.store.authenticate("nobody", PASSWORD))

    def test_password_rules_and_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            self.store.create_user("bob", "short", "viewer")
        with self.assertRaises(ValueError):
            self.store.create_user("alice", PASSWORD, "viewer")
        with self.assertRaises(ValueError):
            self.store.create_user("bad name!", PASSWORD, "viewer")

    def test_password_is_not_stored_in_clear(self) -> None:
        from siem.storage.sqlite import connect
        with connect(self.store.path) as connection:
            stored = connection.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertNotIn(PASSWORD, stored)

    def test_sessions_expire_and_are_revoked_by_changes(self) -> None:
        token = self.store.create_session("alice")
        self.assertEqual(self.store.session_user(token), ("alice", "analyst"))
        self.store.update_user("alice", role="viewer")
        self.assertIsNone(self.store.session_user(token))
        expired = self.store.create_session("alice", ttl=timedelta(seconds=-1))
        self.assertIsNone(self.store.session_user(expired))
        self.store.update_user("alice", disabled=True)
        self.assertIsNone(self.store.authenticate("alice", PASSWORD))


class ServerAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.database = Path(self._directory.name) / "siem.db"
        self.store = SqliteEventStore(self.database)

    def tearDown(self) -> None:
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        self._directory.cleanup()

    def _start(self, **kwargs) -> None:
        try:
            self.server = create_server("127.0.0.1", 0, self.database, **kwargs)
        except PermissionError:
            self.skipTest("environment does not permit local listening sockets")
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def _call(self, path: str, method: str = "GET", body: dict | None = None, *, cookie: str | None = None,
              content_type: str = "application/json", key: str | None = None):
        headers = {"Content-Type": content_type}
        if cookie:
            headers["Cookie"] = cookie
        if key:
            headers["X-API-Key"] = key
        request = Request(self.base + path, method=method, headers=headers,
                          data=json.dumps(body).encode() if body is not None else None)
        with urlopen(request) as response:
            return response.status, response.headers, json.loads(response.read())

    def _status(self, *args, **kwargs) -> int:
        try:
            return self._call(*args, **kwargs)[0]
        except HTTPError as error:
            error.close()
            return error.code

    def test_refuses_to_start_without_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "no credentials"):
            create_server("127.0.0.1", 0, self.database)
        with self.assertRaisesRegex(ValueError, "loopback|127.0.0.1"):
            create_server("0.0.0.0", 0, self.database, allow_insecure_local=True)

    def test_insecure_local_is_explicit_and_keys_disable_it(self) -> None:
        self._start(api_keys=parse_named_api_keys("ops:k1=viewer"), allow_insecure_local=True)
        self.assertEqual(self._status("/me"), 401)
        self.assertEqual(self._status("/me", key="k1"), 200)

    def test_login_session_flow(self) -> None:
        self.store.create_user("alice", PASSWORD, "analyst")
        self._start()
        self.assertEqual(self._status("/me"), 401)
        self.assertEqual(self._status("/login", "POST", {"username": "alice", "password": "nope-nope-nope"}), 401)
        _, headers, me = self._call("/login", "POST", {"username": "alice", "password": PASSWORD})
        cookie_header = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Strict", cookie_header)
        cookie = cookie_header.split(";")[0]
        self.assertEqual(me, {"name": "alice", "role": "analyst"})
        self.assertEqual(self._call("/me", cookie=cookie)[2]["name"], "alice")

        incident = self.store.create_incident("x", "high", [], actor="pipeline")
        path = f"/incidents/{incident['incident_id']}"
        self.assertEqual(self._status(path, "PATCH", {"status": "closed"}, cookie=cookie, content_type="text/plain"), 415)
        self.assertEqual(self._status(path, "PATCH", {"status": "closed"}, cookie=cookie), 200)
        self.assertEqual(self.store.audit_for_incident(incident["incident_id"])[-1]["actor"], "alice")

        self._call("/logout", "POST", {}, cookie=cookie)
        self.assertEqual(self._status("/me", cookie=cookie), 401)

        logins = [event["event_type"] for event in self.store.search(text="Dashboard login")]
        self.assertEqual(sorted(logins), ["login.failed", "login.success"])

    def test_repeated_failed_logins_are_locked_out(self) -> None:
        self.store.create_user("alice", PASSWORD, "analyst")
        self._start()
        for _ in range(10):
            self._status("/login", "POST", {"username": "alice", "password": "wrong-password-1"})
        self.assertEqual(self._status("/login", "POST", {"username": "alice", "password": PASSWORD}), 429)


if __name__ == "__main__":
    unittest.main()
