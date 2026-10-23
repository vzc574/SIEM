import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ingestion import ingest, main  # noqa: E402
from siem.ingestion.agent import poll  # noqa: E402
from siem.ingestion.formats import LogLineError, parse_line  # noqa: E402
from siem.ingestion.syslog import parse_syslog_line  # noqa: E402
from siem.ingestion.windows import parse_windows_event  # noqa: E402

AUTH_LOG = """\
Sep 23 10:20:30 web-01 sshd[811]: Failed password for root from 203.0.113.9 port 50122 ssh2
Sep 23 10:20:33 web-01 sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 50124 ssh2
Sep 23 10:20:40 web-01 sshd[815]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2
Sep 23 10:21:00 web-01 CRON[900]: pam_unix(cron:session): session opened for user root
"""


def _windows(event_id: int, **data: str) -> dict:
    return {"Event": {"System": {"EventID": event_id, "TimeCreated": "2026-09-23T10:00:00+03:00", "Computer": "WIN-01"},
                      "EventData": {"Data": [{"Name": key, "#text": value} for key, value in data.items()]}}}


class SyslogAuthTests(unittest.TestCase):
    def test_real_auth_log_lines_become_login_events(self) -> None:
        events = [parse_line(line, "syslog", source="auth") for line in AUTH_LOG.splitlines()]
        self.assertEqual([event.event_type for event in events],
                         ["login.failed", "login.failed", "login.success", "syslog.CRON"])
        self.assertEqual(events[0].attributes["username"], "root")
        self.assertEqual(events[0].attributes["src_ip"], "203.0.113.9")
        self.assertEqual(events[0].attributes["src_port"], 50122)
        self.assertEqual(events[1].attributes["username"], "admin")
        self.assertEqual(events[2].attributes["username"], "deploy")
        self.assertEqual(events[0].severity, "medium")

    def test_syslog_timestamps_are_utc(self) -> None:
        event = parse_syslog_line("Sep 23 10:20:30 host sshd: x")
        self.assertEqual(event.observed_at.utcoffset().total_seconds(), 0)

    def test_december_lines_read_in_january_use_previous_year(self) -> None:
        event = parse_syslog_line("Dec 31 23:59:00 host sshd: x", now=datetime(2027, 1, 1, 12, tzinfo=timezone.utc))
        self.assertEqual(event.observed_at.year, 2026)


class WindowsLogonTests(unittest.TestCase):
    def test_failed_logon_is_normalized_with_user_and_ip(self) -> None:
        event = parse_windows_event(_windows(4625, TargetUserName="alice", IpAddress="10.0.0.5"))
        self.assertEqual(event.event_type, "login.failed")
        self.assertEqual(event.attributes["src_ip"], "10.0.0.5")
        self.assertEqual(event.observed_at.isoformat(), "2026-09-23T07:00:00+00:00")

    def test_only_user_logon_types_count_as_login_success(self) -> None:
        self.assertEqual(parse_windows_event(_windows(4624, TargetUserName="alice", LogonType="10")).event_type, "login.success")
        self.assertEqual(parse_windows_event(_windows(4624, TargetUserName="SYSTEM", LogonType="5")).event_type, "windows.event.4624")

    def test_missing_ip_placeholder_is_dropped(self) -> None:
        event = parse_windows_event(_windows(4625, TargetUserName="alice", IpAddress="-"))
        self.assertNotIn("src_ip", event.attributes)


class IngestTests(unittest.TestCase):
    def test_ingest_skips_bad_lines_unless_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "auth.log"
            log.write_text(AUTH_LOG + "garbage line\n", encoding="utf-8")
            result = ingest(log, root / "events.jsonl", input_format="syslog", source="auth")
            self.assertEqual(result.events_written, 4)
            self.assertEqual(len(result.errors), 1)
            with self.assertRaisesRegex(LogLineError, "auth.log:5"):
                ingest(log, root / "strict.jsonl", input_format="syslog", source="auth", strict=True)

    def test_cli_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "auth.log"
            log.write_text(AUTH_LOG, encoding="utf-8")
            self.assertEqual(main(["ingest", str(log), "--format", "syslog", "--output", str(root / "e.jsonl")]), 0)
            self.assertEqual(len((root / "e.jsonl").read_text(encoding="utf-8").splitlines()), 4)


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        root = Path(self._directory.name)
        self.log, self.output, self.state = root / "auth.log", root / "events.jsonl", root / "state.json"

    def tearDown(self) -> None:
        self._directory.cleanup()

    def _poll(self):
        return poll(self.log, self.output, self.state, input_format="syslog", source="auth")

    def _lines(self) -> list[dict]:
        return [json.loads(line) for line in self.output.read_text(encoding="utf-8").splitlines()]

    def test_agent_reads_only_new_lines(self) -> None:
        lines = AUTH_LOG.splitlines(keepends=True)
        self.log.write_text("".join(lines[:2]), encoding="utf-8")
        self.assertEqual(self._poll().events_written, 2)
        self.assertEqual(self._poll().events_written, 0)
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write("".join(lines[2:]))
        self.assertEqual(self._poll().events_written, 2)
        self.assertEqual(len(self._lines()), 4)

    def test_agent_waits_for_partial_line(self) -> None:
        line = AUTH_LOG.splitlines()[0]
        self.log.write_text(line[:20], encoding="utf-8")
        self.assertEqual(self._poll().events_written, 0)
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(line[20:] + "\n")
        self.assertEqual(self._poll().events_written, 1)

    def test_agent_skips_bad_lines_and_continues(self) -> None:
        self.log.write_text("garbage\n" + AUTH_LOG, encoding="utf-8")
        result = self._poll()
        self.assertEqual(result.events_written, 4)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(self._poll().errors, [])

    def test_agent_detects_rotation(self) -> None:
        self.log.write_text(AUTH_LOG, encoding="utf-8")
        self._poll()
        os.replace(self.log, self.log.with_suffix(".log.1"))
        self.log.write_text(AUTH_LOG.splitlines(keepends=True)[0], encoding="utf-8")
        self.assertEqual(self._poll().events_written, 1)

    def test_agent_event_ids_are_stable_across_replay(self) -> None:
        self.log.write_text(AUTH_LOG, encoding="utf-8")
        self._poll()
        first = [event["event_id"] for event in self._lines()]
        self.state.unlink()
        self._poll()
        self.assertEqual([event["event_id"] for event in self._lines()][4:], first)


if __name__ == "__main__":
    unittest.main()
