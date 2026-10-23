import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from urllib.error import URLError
from urllib.request import Request, urlopen

from siem.api.server import create_server, parse_named_api_keys, render_csv
from siem.pipeline.worker import run_incremental
from siem.response.notify import Notifier, SmtpSettings, summarize
from siem.storage.sqlite import SqliteEventStore


def _alert(event_id: str, severity: str, created_at: datetime, **extra) -> dict:
    return {"alert_id": f"a-{event_id}", "rule_id": "r", "title": "Burst", "severity": severity, "event_id": event_id,
            "reason": "why", "recommended_action": "act", "evidence": {}, "created_at": created_at.isoformat(), **extra}


class TimelineTests(unittest.TestCase):
    def test_buckets_are_zero_filled_and_split_by_severity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqliteEventStore(Path(directory) / "siem.db")
            now = datetime.now(timezone.utc)
            store.append_alerts([_alert("1", "high", now), _alert("2", "critical", now), _alert("3", "high", now - timedelta(hours=3))])
            store.append_records([{"event_id": "f1", "source": "s", "event_type": "login.failed", "message": "m",
                                   "observed_at": now.isoformat(), "attributes": {}}])
            buckets = store.timeline(since=now - timedelta(hours=6), bucket_minutes=60)
            self.assertIn(len(buckets), (7, 8))
            self.assertEqual(buckets[-1]["alerts"], {"high": 1, "critical": 1})
            self.assertEqual(buckets[-1]["failed_logins"], 1)
            self.assertEqual(sum(sum(b["alerts"].values()) for b in buckets), 3)
            self.assertEqual(sum(1 for b in buckets if not b["alerts"]), len(buckets) - 2)


class CsvTests(unittest.TestCase):
    def test_formula_cells_are_neutralized(self) -> None:
        text = render_csv([{"title": "=HYPERLINK(\"http://evil\")", "reason": "-2+3", "evidence": {"a": 1}, "ok": "plain"}],
                          ("title", "reason", "ok"))
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[1], ["'=HYPERLINK(\"http://evil\")", "'-2+3", "plain"])


class ExportEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        database = Path(self._directory.name) / "siem.db"
        store = SqliteEventStore(database)
        now = datetime.now(timezone.utc)
        store.append_alerts([_alert("1", "high", now), _alert("2", "low", now)])
        try:
            self.server = create_server("127.0.0.1", 0, database, api_keys=parse_named_api_keys("noc:k=viewer"))
        except PermissionError:
            self.skipTest("environment does not permit local listening sockets")
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        self._directory.cleanup()

    def _get(self, path: str):
        with urlopen(Request(self.base + path, headers={"X-API-Key": "k"})) as response:
            return response.headers, response.read().decode()

    def test_alert_csv_respects_filters(self) -> None:
        headers, body = self._get("/alerts.csv?severity=high")
        self.assertIn('attachment; filename="siem-alerts-', headers["Content-Disposition"])
        rows = list(csv.DictReader(io.StringIO(body)))
        self.assertEqual([row["event_id"] for row in rows], ["1"])

    def test_timeline_endpoint_picks_bucket_size(self) -> None:
        _, body = self._get("/stats/timeline?hours=168")
        data = json.loads(body)
        self.assertEqual(data["bucket_minutes"], 360)
        self.assertEqual(sum(sum(b["alerts"].values()) for b in data["buckets"]), 2)


class FakeResponse:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): return False


class FakeSmtp:
    instances: list["FakeSmtp"] = []
    def __init__(self, host, port):
        self.host, self.port, self.calls = host, port, []
        FakeSmtp.instances.append(self)
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def starttls(self, context): self.calls.append("starttls")
    def login(self, user, password): self.calls.append(("login", user))
    def send_message(self, message): self.calls.append(("send", message["Subject"], message["To"]))


class NotifierTests(unittest.TestCase):
    ALERTS = [_alert("1", "critical", datetime.now(timezone.utc)), _alert("2", "high", datetime.now(timezone.utc)),
              _alert("3", "medium", datetime.now(timezone.utc))]

    def test_from_env_and_channels(self) -> None:
        notifier = Notifier.from_env({"SIEM_SLACK_WEBHOOK_URL": "https://hooks.slack.com/x", "SIEM_TELEGRAM_BOT_TOKEN": "t",
                                      "SIEM_TELEGRAM_CHAT_ID": "42", "SIEM_SMTP_HOST": "smtp.example.com",
                                      "SIEM_SMTP_TO": "a@example.com, b@example.com", "SIEM_NOTIFY_MIN_SEVERITY": "medium"})
        self.assertEqual(notifier.channels, ["slack", "telegram", "email"])
        self.assertEqual(notifier.email.recipients, ("a@example.com", "b@example.com"))
        self.assertEqual(Notifier.from_env({}).channels, [])
        with self.assertRaises(ValueError):
            Notifier.from_env({"SIEM_NOTIFY_MIN_SEVERITY": "loud"})

    def test_all_channels_receive_high_alerts_only(self) -> None:
        posts = []
        def opener(request, timeout):
            posts.append((request.full_url, json.loads(request.data)))
            return FakeResponse()
        FakeSmtp.instances.clear()
        notifier = Notifier(slack_webhook="https://hooks.slack.com/x", telegram=("TOKEN", "42"),
                            email=SmtpSettings("smtp.example.com", 587, "siem@example.com", ("soc@example.com",), "siem", "pw"),
                            opener=opener, smtp_factory=FakeSmtp)
        self.assertEqual(notifier.notify(self.ALERTS), [])
        slack, telegram = posts
        self.assertIn("2 new alert(s) (1 critical, 1 high)", slack[1]["text"])
        self.assertEqual(telegram[0], "https://api.telegram.org/botTOKEN/sendMessage")
        self.assertEqual(telegram[1]["chat_id"], "42")
        self.assertEqual(FakeSmtp.instances[0].calls[:2], ["starttls", ("login", "siem")])
        self.assertEqual(FakeSmtp.instances[0].calls[2][2], "soc@example.com")

    def test_one_failing_channel_does_not_block_others(self) -> None:
        def opener(request, timeout):
            raise URLError("down")
        FakeSmtp.instances.clear()
        notifier = Notifier(slack_webhook="https://hooks.slack.com/x",
                            email=SmtpSettings("smtp", 587, "f@x", ("t@x",)), opener=opener, smtp_factory=FakeSmtp)
        with self.assertLogs("siem.response.notify", level="WARNING"):
            self.assertEqual(notifier.notify(self.ALERTS), ["slack"])
        self.assertEqual(notifier.sent["email"], 2)

    def test_summary_is_ordered_by_severity(self) -> None:
        subject, body = summarize(list(reversed(self.ALERTS)))
        self.assertTrue(body.startswith("[CRITICAL]"))
        self.assertEqual(subject, "SIEM: 3 new alert(s) (1 critical, 1 high, 1 medium)")

    def test_worker_notifies_fresh_alerts_once(self) -> None:
        sent = []
        class Recorder(Notifier):
            def notify(self, alerts):
                sent.append(len(alerts))
                return []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            events.write_text(json.dumps({"event_id": "e1", "source": "s", "event_type": "malware.detected", "message": "m",
                                          "severity": "high", "observed_at": "2026-09-23T10:00:00+00:00", "attributes": {}}) + "\n",
                              encoding="utf-8")
            notifier = Recorder()
            run_incremental(events, root / "a.jsonl", root / "s.json", incident_database=root / "siem.db", notifier=notifier)
            (root / "s.json").unlink()
            run_incremental(events, root / "a.jsonl", root / "s.json", incident_database=root / "siem.db", notifier=notifier)
        self.assertEqual(sent, [2])


if __name__ == "__main__":
    unittest.main()
