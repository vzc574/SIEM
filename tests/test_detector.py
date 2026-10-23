import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import describe_rules, load_rules, main  # noqa: E402
from siem.detection.correlation import correlate  # noqa: E402
from siem.pipeline.run import create_incidents_for_alerts, process_event_records  # noqa: E402
from siem.pipeline.worker import run_incremental  # noqa: E402
from siem.storage.sqlite import SqliteEventStore  # noqa: E402


def _failed(index: int, user: str = "alice", ip: str = "203.0.113.9", second: int | None = None) -> dict:
    second = index * 10 if second is None else second
    return {"event_id": f"e{user}{index}", "source": "auth", "event_type": "login.failed", "message": "x",
            "severity": "medium", "observed_at": f"2026-09-23T10:{second // 60:02d}:{second % 60:02d}+00:00",
            "attributes": {"username": user, "src_ip": ip}}


def _sshd(second: int, text: str) -> str:
    return f"Sep 23 10:{second // 60:02d}:{second % 60:02d} web-01 sshd[811]: {text}\n"


class CorrelationTests(unittest.TestCase):
    def test_separate_events_from_one_source_are_not_merged(self) -> None:
        alerts = process_event_records([_failed(1, "alice"), _failed(2, "bob"), _failed(3, "carol")])
        self.assertEqual(sum(alert.rule_id == "auth.failed-login" for alert in alerts), 3)

    def test_long_attack_alerts_once_per_window_not_per_event(self) -> None:
        alerts = correlate([_failed(index, second=index * 20) for index in range(20)])  # 20 failures over ~6.5 min
        bursts = [alert for alert in alerts if alert.rule_id == "correlation.failed-login-burst"]
        self.assertEqual(len(bursts), 2)

    def test_password_spray_from_one_ip_is_detected(self) -> None:
        alerts = correlate([_failed(index, user=f"user{index}") for index in range(10)])
        self.assertEqual([alert.rule_id for alert in alerts], ["correlation.source-login-spray"])
        self.assertEqual(len(alerts[0].evidence["usernames"]), 10)

    def test_success_after_failures_alerts_only_once(self) -> None:
        success = lambda second, event_id: {**_failed(0, second=second), "event_id": event_id, "event_type": "login.success"}
        alerts = correlate([_failed(index) for index in range(3)] + [success(40, "s1"), success(50, "s2")])
        self.assertEqual([alert.event_id for alert in alerts if alert.rule_id == "correlation.failed-then-success"], ["s1"])


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        root = Path(self._directory.name)
        self.log, self.alerts, self.state, self.db = root / "auth.log", root / "alerts.jsonl", root / "state.json", root / "siem.db"

    def tearDown(self) -> None:
        self._directory.cleanup()

    def _cycle(self, text: str) -> int:
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(text)
        return run_incremental(self.log, self.alerts, self.state, input_format="syslog", source="auth",
                               incident_database=self.db)

    def _rules(self) -> list[str]:
        return [json.loads(line)["rule_id"] for line in self.alerts.read_text(encoding="utf-8").splitlines()]

    def test_real_ssh_brute_force_spanning_cycles_is_detected(self) -> None:
        failure = "Failed password for root from 203.0.113.9 port 50122 ssh2"
        self._cycle("".join(_sshd(second, failure) for second in (0, 5, 10)))
        self._cycle("".join(_sshd(second, failure) for second in (15, 20, 25)))
        self.assertEqual(self._rules().count("correlation.failed-login-burst"), 1)
        self._cycle(_sshd(30, "Accepted password for root from 203.0.113.9 port 50200 ssh2"))
        self.assertIn("correlation.failed-then-success", self._rules())

    def test_malformed_line_is_skipped_and_worker_keeps_going(self) -> None:
        with self.assertLogs("siem.pipeline.worker", level="WARNING"):
            self._cycle("this is not syslog\n" + _sshd(0, "Failed password for root from 203.0.113.9 port 1 ssh2"))
        self.assertIn("auth.failed-login", self._rules())
        self.assertEqual(self._cycle(""), 0)

    def test_incidents_are_extended_not_duplicated(self) -> None:
        failure = "Failed password for root from 203.0.113.9 port 50122 ssh2"
        for start in (0, 400):  # two separate bursts, more than a window apart
            self._cycle("".join(_sshd(start + second, failure) for second in range(0, 25, 5)))
        incidents = SqliteEventStore(self.db).list_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0]["alert_ids"]), 2)

    def test_version_one_line_checkpoint_is_upgraded(self) -> None:
        self.log.write_text(_sshd(0, "Failed password for a from 1.1.1.1 port 1 ssh2") * 2, encoding="utf-8")
        self.state.write_text(json.dumps({"line_offset": 1}), encoding="utf-8")
        run_incremental(self.log, self.alerts, self.state, input_format="syslog")
        self.assertEqual(json.loads(self.state.read_text(encoding="utf-8"))["offset"], self.log.stat().st_size)


class DetectorCliTests(unittest.TestCase):
    def test_detect_and_rules_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            events.write_text("".join(json.dumps(_failed(index)) + "\n" for index in range(5)), encoding="utf-8")
            self.assertEqual(main(["detect", str(events), "--output", str(root / "a.jsonl"), "--database", str(root / "siem.db")]), 0)
            rules = [json.loads(line)["rule_id"] for line in (root / "a.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertIn("correlation.failed-login-burst", rules)
            self.assertEqual(len(SqliteEventStore(root / "siem.db").list_incidents()), 1)
        self.assertEqual(main(["rules"]), 0)
        self.assertIn("correlation.source-login-spray", dict(describe_rules(load_rules())))

    def test_incident_helper_returns_group_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            alerts = process_event_records([_failed(index) for index in range(5)])
            self.assertEqual(create_incidents_for_alerts(alerts, Path(directory) / "siem.db"), 1)


if __name__ == "__main__":
    unittest.main()
