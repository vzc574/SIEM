import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from database import main, open_store, stats  # noqa: E402
from siem.storage.retention import prune_events  # noqa: E402
from siem.storage.sqlite import SCHEMA_VERSION  # noqa: E402


def _event(event_id: str, observed_at: str, event_type: str = "login.failed", **attributes) -> dict:
    return {"event_id": event_id, "source": "auth", "event_type": event_type, "message": "m",
            "observed_at": observed_at, "severity": "medium", "attributes": attributes}


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.path = self.root / "siem.db"

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_wal_mode_and_schema_version(self) -> None:
        open_store(self.path)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        connection.close()

    def test_timestamps_are_stored_in_utc_and_ordered_correctly(self) -> None:
        store = open_store(self.path)
        # 10:30+03:00 is 07:30Z, i.e. earlier than 08:00Z although it sorts later as text.
        store.append_records([_event("late", "2026-09-23T08:00:00+00:00"), _event("early", "2026-09-23T10:30:00+03:00")])
        results = store.search()
        self.assertEqual([event["event_id"] for event in results], ["late", "early"])
        self.assertEqual(results[1]["observed_at"], "2026-09-23T07:30:00+00:00")

    def test_migrates_version_one_database(self) -> None:
        shutil.copy(ROOT / "demo" / "siem.db", self.path)
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA user_version = 0")
            connection.execute("INSERT INTO security_events VALUES ('old', 'auth', 'login.failed', 'm', "
                               "'2026-09-23T10:30:00+03:00', 'medium', NULL, '{\"src_ip\": \"203.0.113.9\"}')")
        connection.close()
        store = open_store(self.path)
        self.assertEqual(store.events_since(datetime(2026, 9, 23, 7, 30, tzinfo=timezone.utc), event_types=["login.failed"])[0]["event_id"], "old")
        self.assertEqual(store.top_values("src_ip", event_type="login.failed")[0], {"value": "203.0.113.9", "count": 1})

    def test_events_since_filters_types_and_hides_generated_columns(self) -> None:
        store = open_store(self.path)
        store.append_records([_event("a", "2026-09-23T10:00:00+00:00", username="alice"),
                              _event("b", "2026-09-23T10:05:00+00:00", event_type="web.request"),
                              _event("c", "2026-09-23T09:00:00+00:00")])
        events = store.events_since(datetime(2026, 9, 23, 9, 30, tzinfo=timezone.utc), event_types=["login.failed"])
        self.assertEqual([event["event_id"] for event in events], ["a"])
        self.assertNotIn("username", events[0])
        self.assertEqual(events[0]["attributes"]["username"], "alice")

    def test_top_values_rejects_unknown_columns(self) -> None:
        with self.assertRaises(ValueError):
            open_store(self.path).top_values("message; DROP TABLE incidents")

    def test_open_incident_lookup_and_alert_attachment(self) -> None:
        store = open_store(self.path)
        incident = store.create_incident("Automated investigation: alice", "high", ["a1"], actor="pipeline")
        self.assertEqual(store.find_open_incident("Automated investigation: alice")["incident_id"], incident["incident_id"])
        updated = store.attach_alerts(incident["incident_id"], ["a1", "a2"], actor="pipeline", severity="critical")
        self.assertEqual(updated["alert_ids"], ["a1", "a2"])
        self.assertEqual(updated["severity"], "critical")
        store.update_incident(incident["incident_id"], actor="analyst", status="closed")
        self.assertIsNone(store.find_open_incident("Automated investigation: alice"))

    def test_assignee_must_be_a_string(self) -> None:
        store = open_store(self.path)
        incident = store.create_incident("x", "high", [], actor="a")
        with self.assertRaises(ValueError):
            store.update_incident(incident["incident_id"], actor="a", assignee={"name": "bob"})  # type: ignore[arg-type]

    def test_retention_uses_true_time_order(self) -> None:
        store = open_store(self.path)
        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        # Older than the cutoff in real time, but its +14:00 text sorts after the cutoff text.
        old_local = (cutoff - timedelta(hours=1)).astimezone(timezone(timedelta(hours=14))).isoformat()
        store.append_records([_event("old", old_local)])
        self.assertEqual(prune_events(self.path, older_than_days=1, apply=True), 1)

    def test_stats_and_cli(self) -> None:
        store = open_store(self.path)
        now = datetime.now(timezone.utc).isoformat()
        store.append_records([_event(str(i), now, src_ip="203.0.113.9", username="root") for i in range(3)])
        result = stats(store)
        self.assertEqual(result["top_failed_login_ips"], [{"value": "203.0.113.9", "count": 3}])
        events = self.root / "events.jsonl"
        events.write_text(json.dumps(_event("x", now)) + "\n", encoding="utf-8")
        self.assertEqual(main(["index", str(events), "--database", str(self.path)]), 0)
        self.assertEqual(main(["verify", str(self.path)]), 0)
        self.assertEqual(store.metrics()["security_events"], 4)


if __name__ == "__main__":
    unittest.main()
