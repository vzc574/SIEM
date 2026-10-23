import json
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from siem.api.server import create_server, parse_named_api_keys
from siem.detection.config import RulesConfigError, load_rules, parse_rules
from siem.ingestion.agent import ShipError, http_sink, poll
from siem.ingestion.syslog import parse_syslog_line
from siem.pipeline.run import process_event_records
from siem.pipeline.worker import run_incremental
from siem.storage.sqlite import SqliteEventStore


def _sudo(second: int, message: str, tag: str = "sudo") -> str:
    return f"Sep 23 10:00:{second:02d} web-01 {tag}: {message}\n"


SUDO_FAIL = "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"


def _windows_line(event_id: int, **data: str) -> str:
    """The JSON shape deploy/windows/siem-collector.ps1 produces."""
    return json.dumps({"Event": {"System": {"EventID": event_id, "TimeCreated": "2026-09-23T07:00:00.123456Z",
                                            "Computer": "WIN-01", "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                                            "EventRecordID": 77},
                                 "EventData": {"Data": [{"Name": k, "#text": v} for k, v in data.items()]}},
                       "Message": "An event occurred."})


class PrivilegeParsingTests(unittest.TestCase):
    def test_sudo_and_su_lines(self) -> None:
        cases = {
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash": ("privilege.sudo", "alice"),
            SUDO_FAIL: ("privilege.failed", "alice"),
            "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow": ("privilege.denied", "bob"),
        }
        for message, (event_type, user) in cases.items():
            event = parse_syslog_line(_sudo(0, message))
            self.assertEqual((event.event_type, event.attributes["username"]), (event_type, user), message)
        su_fail = parse_syslog_line(_sudo(0, "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root", "su[42]"))
        self.assertEqual((su_fail.event_type, su_fail.attributes["target_user"]), ("privilege.failed", "root"))
        self.assertEqual(parse_syslog_line(_sudo(0, "(to root) alice on pts/0", "su[43]")).event_type, "privilege.su")

    def test_sudo_give_up_summary_is_not_a_success(self) -> None:
        line = _sudo(0, "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id")
        self.assertEqual(parse_syslog_line(line).event_type, "syslog.sudo")


class RulesConfigTests(unittest.TestCase):
    def _alerts(self, events, rules=None) -> list[str]:
        return [alert.rule_id for alert in process_event_records(events, rules=rules)]

    def _event(self, index: int, event_type: str = "login.failed", **attributes) -> dict:
        return {"event_id": f"e{index}", "source": "s", "event_type": event_type, "message": "m", "severity": "info",
                "observed_at": f"2026-09-23T10:00:{index:02d}+00:00", "host": "web-01",
                "attributes": {"username": "alice", **attributes}}

    def test_thresholds_and_disabling_are_configurable(self) -> None:
        events = [self._event(index) for index in range(3)]
        self.assertNotIn("correlation.failed-login-burst", self._alerts(events))
        rules = parse_rules({"correlation": {"failed_login_burst": {"threshold": 3}}, "rules": {"failed_login": {"enabled": False}}})
        self.assertEqual(self._alerts(events, rules), ["correlation.failed-login-burst"])

    def test_builtin_match_rules(self) -> None:
        shell = self._event(1, "privilege.sudo", command="/bin/bash", target_user="root")
        harmless = self._event(2, "privilege.sudo", command="/usr/bin/systemctl restart nginx", target_user="root")
        denied = self._event(3, "privilege.denied", command="/bin/cat /etc/shadow", target_user="root")
        self.assertEqual(self._alerts([shell, harmless]), ["privilege.root-shell"])
        alerts = process_event_records([denied])
        self.assertIn("alice tried to run '/bin/cat /etc/shadow' as root", [a.reason for a in alerts if a.rule_id == "privilege.not-in-sudoers"][0])

    def test_custom_match_rule_and_disabled_builtin(self) -> None:
        rules = parse_rules({
            "disabled_match": ["privilege.root-shell"],
            "match": [{"id": "web.admin-probe", "title": "Admin probe", "severity": "high", "event_type": "web.*",
                       "attribute_regex": {"path": "^/wp-admin"}, "reason": "{src_ip} asked for {path}"}],
        })
        probe = self._event(1, "web.request", path="/wp-admin/login.php", src_ip="203.0.113.9")
        shell = self._event(2, "privilege.sudo", command="/bin/bash")
        alerts = process_event_records([probe, shell], rules=rules)
        self.assertEqual([(a.rule_id, a.reason) for a in alerts if not a.rule_id.startswith("event.")],
                         [("web.admin-probe", "203.0.113.9 asked for /wp-admin/login.php")])

    def test_invalid_configs_are_rejected_with_clear_errors(self) -> None:
        bad = [
            ({"correlation": {"failed_login_burst": {"threshhold": 3}}}, "threshhold"),
            ({"correlation": {"nope": {}}}, "unknown rule"),
            ({"match": [{"id": "x", "title": "t", "event_type": "a", "message_regex": "("}]}, "regular expression"),
            ({"match": [{"id": "x", "title": "t", "event_type": "a", "severity": "urgent"}]}, "severity"),
            ({"rulez": {}}, "unknown section"),
        ]
        for data, message in bad:
            with self.assertRaisesRegex(RulesConfigError, message):
                parse_rules(data)

    def test_example_file_is_valid_and_env_path_is_used(self) -> None:
        example = Path(__file__).resolve().parents[1] / "rules.example.toml"
        load_rules(example)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.toml"
            path.write_text("[rules.failed_login]\nenabled = false\n", encoding="utf-8")
            import os
            os.environ["SIEM_RULES"] = str(path)
            try:
                self.assertFalse(load_rules().failed_login)
            finally:
                del os.environ["SIEM_RULES"]


class PrivilegeCorrelationTests(unittest.TestCase):
    def test_sudo_password_guessing_across_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log, out, state, db = root / "auth.log", root / "a.jsonl", root / "s.json", root / "siem.db"
            for seconds in ((0, 5), (10,)):
                with log.open("a", encoding="utf-8") as stream:
                    stream.write("".join(_sudo(second, SUDO_FAIL) for second in seconds))
                run_incremental(log, out, state, input_format="syslog", incident_database=db)
            rules = [alert["rule_id"] for alert in SqliteEventStore(db).search_alerts()]
            self.assertEqual(rules.count("correlation.privilege-failures"), 1)


class IngestEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        root = Path(self._directory.name)
        self.database, self.ingest_file = root / "siem.db", root / "events.jsonl"
        keys = parse_named_api_keys("win01:ingest-key=ingest,noc:viewer-key=viewer")
        try:
            self.server = create_server("127.0.0.1", 0, self.database, api_keys=keys, ingest_path=self.ingest_file)
        except PermissionError:
            self.skipTest("environment does not permit local listening sockets")
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        self._directory.cleanup()

    def _post(self, body: dict, key: str = "ingest-key"):
        request = Request(self.base + "/ingest", data=json.dumps(body).encode(), method="POST",
                          headers={"Content-Type": "application/json", "X-API-Key": key})
        try:
            with urlopen(request) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            error.close()
            return error.code, None

    def _ingested(self) -> list[dict]:
        return [json.loads(line) for line in self.ingest_file.read_text(encoding="utf-8").splitlines()]

    def test_windows_collector_batch_is_normalized_and_detected(self) -> None:
        lines = [_windows_line(4625, TargetUserName="alice", IpAddress="10.0.0.5"), _windows_line(1102), "not json"]
        status, result = self._post({"format": "windows-json", "source": "windows-win-01", "lines": lines})
        self.assertEqual((status, result["accepted"], result["rejected"]), (202, 2, 1))
        events = self._ingested()
        self.assertEqual([event["event_type"] for event in events], ["login.failed", "windows.event.1102"])
        self.assertEqual(events[0]["attributes"]["collector"], "win01")
        self.assertIn("windows.audit-log-cleared", [a.rule_id for a in process_event_records(events)])

    def test_retried_batches_keep_the_same_event_ids(self) -> None:
        body = {"format": "windows-json", "source": "w", "lines": [_windows_line(4625, TargetUserName="a")]}
        self._post(body)
        self._post(body)
        ids = [event["event_id"] for event in self._ingested()]
        self.assertEqual(len(ids), 2)
        self.assertEqual(ids[0], ids[1])

    def test_role_separation(self) -> None:
        self.assertEqual(self._post({"events": []}, key="viewer-key")[0], 403)
        request = Request(self.base + "/alerts", headers={"X-API-Key": "ingest-key"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        caught.exception.close()
        self.assertEqual(caught.exception.code, 403)

    def test_linux_agent_ships_to_the_server(self) -> None:
        root = Path(self._directory.name)
        log = root / "auth.log"
        log.write_text("Sep 23 10:00:00 web-02 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n", encoding="utf-8")
        result = poll(log, None, root / "agent.state", input_format="syslog", source="web-02",
                      sink=http_sink(self.base, "ingest-key"))
        self.assertEqual(result.events_written, 1)
        self.assertEqual(self._ingested()[0]["attributes"]["src_ip"], "203.0.113.9")


class ShipFailureTests(unittest.TestCase):
    def test_failed_delivery_does_not_advance_checkpoint(self) -> None:
        def broken(request, timeout):
            raise URLError("connection refused")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log, state = root / "auth.log", root / "agent.state"
            log.write_text("Sep 23 10:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n", encoding="utf-8")
            with self.assertRaises(ShipError):
                poll(log, None, state, input_format="syslog", source="h", sink=http_sink("https://siem.invalid", "k", opener=broken))
            self.assertFalse(state.exists())

    def test_plain_http_is_refused_for_remote_hosts(self) -> None:
        with self.assertRaises(ValueError):
            http_sink("http://siem.example.com", "k")


if __name__ == "__main__":
    unittest.main()
