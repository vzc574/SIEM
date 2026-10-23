import json
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import main  # noqa: E402
from siem.api.server import client_address, create_server, parse_named_api_keys, parse_trusted_proxies  # noqa: E402
from siem.storage.sqlite import SqliteEventStore  # noqa: E402


class AuthParsingTests(unittest.TestCase):
    def test_named_keys_and_legacy_format(self) -> None:
        keys = parse_named_api_keys("alice:k1=analyst, k2=viewer, bad=root")
        self.assertEqual(keys["k1"], ("analyst", "alice"))
        self.assertEqual(keys["k2"][0], "viewer")
        self.assertTrue(keys["k2"][1].startswith("key-"))
        self.assertNotIn("bad", keys)

    def test_forwarded_address_only_trusted_from_proxy(self) -> None:
        trusted = parse_trusted_proxies("172.16.0.0/12")
        headers = {"X-Real-IP": "203.0.113.9"}
        self.assertEqual(client_address("172.18.0.2", headers, trusted), "203.0.113.9")
        self.assertEqual(client_address("198.51.100.1", headers, trusted), "198.51.100.1")


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        root = Path(self._directory.name)
        self.database = root / "siem.db"
        self.alerts = root / "alerts.jsonl"
        store = SqliteEventStore(self.database)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        store.append_records([{"event_id": f"e{i}", "source": "auth", "event_type": "login.failed", "message": "m",
                               "observed_at": now, "severity": "medium",
                               "attributes": {"username": "root", "src_ip": "203.0.113.9"}} for i in range(3)])
        self.incident = store.create_incident("Automated investigation: root", "high", [], actor="pipeline")
        self.alerts.write_text(json.dumps({"rule_id": "correlation.failed-login-burst", "severity": "high",
                                           "title": "t", "created_at": now}) + "\n", encoding="utf-8")
        keys = parse_named_api_keys("alice:analyst-key=analyst,noc:viewer-key=viewer")
        try:
            self.server = create_server("127.0.0.1", 0, self.database, alert_paths=[self.alerts], api_keys=keys)
        except PermissionError:
            self.skipTest("environment does not permit local listening sockets")
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        self._directory.cleanup()

    def _call(self, path: str, key: str | None = None, method: str = "GET", body: dict | None = None, headers: dict | None = None):
        request = Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                          headers={**({"X-API-Key": key} if key else {}), "Content-Type": "application/json", **(headers or {})})
        with urlopen(request) as response:
            return response.status, response.headers, response.read()

    def test_audit_actor_comes_from_key_not_header(self) -> None:
        path = f"/incidents/{self.incident['incident_id']}"
        self._call(path, "analyst-key", "PATCH", {"status": "investigating"}, {"X-Actor": "someone-else"})
        _, _, body = self._call(path, "viewer-key")
        self.assertEqual(json.loads(body)["audit"][-1]["actor"], "alice")

    def test_viewer_cannot_modify_incidents(self) -> None:
        with self.assertRaises(HTTPError) as caught:
            self._call(f"/incidents/{self.incident['incident_id']}", "viewer-key", "PATCH", {"status": "closed"})
        self.assertEqual(caught.exception.code, 403)
        with self.assertRaises(HTTPError) as caught:
            self._call("/stats")
        self.assertEqual(caught.exception.code, 401)

    def test_bad_assignee_returns_400(self) -> None:
        with self.assertRaises(HTTPError) as caught:
            self._call(f"/incidents/{self.incident['incident_id']}", "analyst-key", "PATCH", {"assignee": {"x": 1}})
        self.assertEqual(caught.exception.code, 400)

    def test_stats_reports_threat_pivots_and_alerts(self) -> None:
        _, _, body = self._call("/stats?hours=24", "viewer-key")
        stats = json.loads(body)
        self.assertEqual(stats["top_failed_login_ips"], [{"value": "203.0.113.9", "count": 3}])
        self.assertEqual(stats["top_failed_login_users"][0]["value"], "root")
        self.assertEqual(stats["alerts"]["by_severity"], {"high": 1})

    def test_dashboard_script_is_external_and_csp_blocks_inline(self) -> None:
        _, headers, page = self._call("/")
        self.assertIn(b'<script src="/dashboard.js">', page)
        self.assertIn("script-src 'self';", headers["Content-Security-Policy"])
        _, headers, script = self._call("/dashboard.js")
        self.assertTrue(headers["Content-Type"].startswith("text/javascript"))
        self.assertIn(b"/stats", script)
        _, _, me = self._call("/me", "analyst-key")
        self.assertEqual(json.loads(me), {"name": "alice", "role": "analyst"})


class ReportCliTests(unittest.TestCase):
    def test_report_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alerts = root / "alerts.jsonl"
            alerts.write_text(json.dumps({"title": "Burst", "severity": "high"}) + "\n", encoding="utf-8")
            self.assertEqual(main(["report", "--alerts", str(alerts), "--output", str(root / "r.md")]), 0)
            self.assertIn("Burst", (root / "r.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
