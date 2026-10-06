import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import json

from siem.domain.events import SecurityEvent
from siem.ingestion.json_lines import JsonLogParseError, collect_json_lines
from siem.ingestion.runner import ingest_file
from siem.storage.jsonl import JsonlEventStore
from siem.detection.engine import detect
from siem.analysis.static import analyze_file
from siem.response.quarantine import quarantine_file
from siem.reporting.report import build_context, render_markdown
from siem.storage.sqlite import SqliteEventStore
from siem.ingestion.syslog import SyslogParseError, collect_syslog, parse_syslog_line
from siem.ingestion.syslog_runner import ingest_syslog
from siem.detection.correlation import correlate
from siem.api.server import create_server, is_authorized, _read_jsonl, parse_api_keys, role_for_request, render_metrics
from siem.api.dashboard import DASHBOARD_HTML
from siem.ai.openai_reports import build_ai_prompt
from siem.intel.store import IOCStore
from siem.intel.matcher import match_event
from siem.intel.virustotal import parse_file_response
from siem.intel.external import enrich_events
from siem.pipeline.run import create_incidents_for_alerts, deduplicate_alerts, process_event_records, process_events
from siem.pipeline.worker import run_once, run_incremental
from siem.storage.backup import backup_database
from siem.storage.verify import verify_database
from siem.storage.retention import prune_events
from siem.sandbox.jobs import create_job
from siem.sandbox.results import SandboxResultError, result_to_events, validate_result
from siem.response.notify import send_webhook
from siem.ingestion.windows import parse_windows_event
from siem.ingestion.network import parse_access_line, parse_ufw_line
from threading import Thread
from urllib.request import urlopen


class FoundationTests(unittest.TestCase):
    def test_event_serializes_with_timezone_and_id(self) -> None:
        event = SecurityEvent(
            source="test-agent",
            event_type="process.started",
            message="A test process started",
            observed_at=datetime.now(timezone.utc),
            severity="low",
        )
        record = event.to_record()
        self.assertEqual(record["source"], "test-agent")
        self.assertIsInstance(record["event_id"], str)
        self.assertTrue(str(record["observed_at"]).endswith("+00:00"))

    def test_store_appends_and_reads_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JsonlEventStore(Path(directory) / "events.jsonl")
            store.append(SecurityEvent.now(
                source="test-agent",
                event_type="file.created",
                message="A harmless test file was created",
            ))
            self.assertEqual(len(store.read_all()), 1)

    def test_empty_message_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SecurityEvent.now(source="test", event_type="test", message=" ")

    def test_json_lines_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.jsonl"
            path.write_text(json.dumps({
                "type": "login.failed",
                "message": "Invalid password",
                "timestamp": "2026-09-23T10:00:00Z",
                "severity": "high",
                "username": "analyst",
            }) + "\n", encoding="utf-8")
            events = list(collect_json_lines(path, default_source="auth-service"))
            self.assertEqual(events[0].source, "auth-service")
            self.assertEqual(events[0].event_type, "login.failed")
            self.assertEqual(events[0].attributes["username"], "analyst")

    def test_malformed_json_is_rejected_with_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("not-json\n", encoding="utf-8")
            with self.assertRaisesRegex(JsonLogParseError, "bad.jsonl:1"):
                list(collect_json_lines(path, default_source="test"))

    def test_ingestion_runner_writes_normalized_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.jsonl"
            output_path = root / "data" / "events.jsonl"
            input_path.write_text(json.dumps({
                "event_type": "file.created",
                "message": "A file appeared",
            }) + "\n", encoding="utf-8")
            result = ingest_file(input_path, output_path, default_source="test-agent")
            self.assertEqual(result.events_written, 1)
            self.assertEqual(len(JsonlEventStore(output_path).read_all()), 1)

    def test_detection_generates_explainable_alerts(self) -> None:
        alerts = detect([{
            "event_id": "event-1",
            "source": "endpoint-1",
            "event_type": "malware.detected",
            "severity": "high",
            "message": "Test detection",
            "attributes": {"sha256": "example"},
        }])
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(alert.reason for alert in alerts))
        self.assertTrue(all(alert.recommended_action for alert in alerts))

    def test_static_analysis_is_non_executing_and_classifies_indicators(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"MZ" + b" powershell downloadstring " + bytes(range(64)))
            analysis = analyze_file(path)
            self.assertEqual(analysis.magic, "windows-pe")
            self.assertEqual(len(analysis.sha256), 64)
            self.assertIn("contains:powershell", analysis.indicators)
            self.assertEqual(analysis.classification, "suspicious")

    def test_quarantine_defaults_to_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.bin"
            source.write_bytes(b"harmless test data")
            result = quarantine_file(source, Path(directory) / "quarantine")
            self.assertFalse(result.applied)
            self.assertTrue(source.exists())

    def test_quarantine_apply_moves_file_and_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.bin"
            quarantine_dir = root / "quarantine"
            source.write_bytes(b"harmless test data")
            result = quarantine_file(source, quarantine_dir, apply=True)
            self.assertTrue(result.applied)
            self.assertFalse(source.exists())
            self.assertTrue(result.destination.exists())
            self.assertTrue((quarantine_dir / "manifest.jsonl").exists())

    def test_report_contains_evidence_and_limitations(self) -> None:
        context = build_context([{
            "title": "Suspicious activity detected",
            "severity": "high",
            "rule_id": "event.suspicious-type",
            "reason": "Suspicious event type observed.",
            "recommended_action": "Review the host.",
        }], {"classification": "suspicious", "sha256": "abc123", "magic": "elf", "indicators": ["high-entropy"]})
        report = render_markdown(context)
        self.assertIn("Suspicious activity detected", report)
        self.assertIn("abc123", report)
        self.assertIn("does not establish maliciousness", report)

    def test_sqlite_store_indexes_and_searches_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqliteEventStore(Path(directory) / "siem.db")
            store.append(SecurityEvent.now(
                source="endpoint-1", event_type="login.failed",
                message="Invalid password", severity="medium",
            ))
            results = store.search(text="password", severity="medium")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["event_type"], "login.failed")

    def test_syslog_line_is_normalized(self) -> None:
        event = parse_syslog_line("<34>Sep 23 10:20:30 workstation sshd[1234]: Failed password for user")
        self.assertEqual(event.host, "workstation")
        self.assertEqual(event.event_type, "syslog.sshd")
        self.assertEqual(event.attributes["pid"], 1234)

    def test_syslog_file_is_ingested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "auth.log"
            output_path = root / "events.jsonl"
            input_path.write_text("<34>Sep 23 10:20:30 host sshd: Accepted publickey\n", encoding="utf-8")
            self.assertEqual(ingest_syslog(input_path, output_path), 1)

    def test_invalid_syslog_line_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("invalid\n", encoding="utf-8")
            with self.assertRaises(SyslogParseError):
                list(collect_syslog(path))

    def test_correlation_detects_failed_login_burst_and_success(self) -> None:
        events = []
        for index in range(3):
            events.append({
                "event_id": f"failure-{index}", "event_type": "login.failed",
                "observed_at": f"2026-09-23T10:0{index}:00+00:00", "source": "auth",
                "attributes": {"username": "alice"},
            })
        events.append({
            "event_id": "success", "event_type": "login.success",
            "observed_at": "2026-09-23T10:03:00+00:00", "source": "auth",
            "attributes": {"username": "alice"},
        })
        alerts = correlate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "correlation.failed-then-success")

    def test_read_only_api_health_and_event_search(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "siem.db"
            store = SqliteEventStore(database)
            store.append(SecurityEvent.now(
                source="api-test", event_type="login.failed",
                message="Invalid password", severity="medium",
            ))
            try:
                server = create_server("127.0.0.1", 0, database)
            except PermissionError:
                self.skipTest("environment does not permit local listening sockets")
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(base + "/health") as response:
                    self.assertEqual(json.loads(response.read())["status"], "ok")
                with urlopen(base + "/events?text=password") as response:
                    payload = json.loads(response.read())
                    self.assertEqual(payload["count"], 1)
            finally:
                server.shutdown()
                server.server_close()

    def test_api_key_authentication_supports_bearer_and_header(self) -> None:
        self.assertFalse(is_authorized({}, "secret"))
        self.assertTrue(is_authorized({"X-API-Key": "secret"}, "secret"))
        self.assertTrue(is_authorized({"Authorization": "Bearer secret"}, "secret"))
        self.assertFalse(is_authorized({"Authorization": "Bearer wrong"}, "secret"))

    def test_api_key_roles_are_enforced(self) -> None:
        keys = parse_api_keys("view=viewer,work=analyst,root=admin")
        self.assertEqual(role_for_request({"X-API-Key": "view"}, None, keys), "viewer")
        self.assertEqual(role_for_request({"X-API-Key": "work"}, None, keys), "analyst")
        self.assertIsNone(role_for_request({"X-API-Key": "bad"}, None, keys))

    def test_metrics_are_prometheus_compatible(self) -> None:
        metrics = render_metrics({"security_events": 3, "open_incidents": 1})
        self.assertIn("siem_up 1", metrics)
        self.assertIn("siem_security_events 3", metrics)

    def test_alert_api_data_filters_jsonl_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.jsonl"
            path.write_text(json.dumps({"title": "Test", "severity": "high", "reason": "evidence"}) + "\n", encoding="utf-8")
            alerts = _read_jsonl([path], text="evidence", severity="high", limit=10)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["title"], "Test")

    def test_incident_lifecycle_writes_audit_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqliteEventStore(Path(directory) / "siem.db")
            incident = store.create_incident("Login investigation", "high", ["alert-1"], actor="analyst")
            incident_id = incident["incident_id"]
            updated = store.update_incident(incident_id, actor="analyst", status="investigating", assignee="bob")
            self.assertEqual(updated["status"], "investigating")
            self.assertEqual(updated["assignee"], "bob")
            self.assertEqual(len(store.audit_for_incident(incident_id)), 2)

    def test_dashboard_is_available_as_static_html(self) -> None:
        self.assertIn("SIEM Dashboard", DASHBOARD_HTML)
        self.assertIn("/alerts", DASHBOARD_HTML)

    def test_ai_prompt_is_bounded_and_evidence_based(self) -> None:
        prompt = build_ai_prompt({"alerts": [{"reason": "x" * 10000}]})
        self.assertIn("Separate observed facts from inferences", prompt)
        self.assertLess(len(prompt), 10000)

    def test_local_intelligence_matches_event_indicator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IOCStore(Path(directory) / "intel.db")
            store.add("sha256", "ABC123", source="test-feed", confidence=90)
            alerts = match_event({"event_id": "event-1", "attributes": {"sha256": "abc123"}}, store)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].rule_id, "intel.local-match")

    def test_virustotal_response_is_normalized(self) -> None:
        reputation = parse_file_response("a" * 64, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 6},
            "tags": ["peexe"],
        }}})
        self.assertEqual(reputation.malicious, 3)
        self.assertEqual(reputation.total_engines, 10)

    def test_processing_pipeline_combines_detection_and_ioc_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            output = root / "alerts.jsonl"
            ioc_db = root / "intel.db"
            IOCStore(ioc_db).add("sha256", "abc123", source="test", confidence=90)
            events.write_text(json.dumps({
                "event_id": "event-1", "source": "endpoint", "event_type": "malware.detected",
                "message": "Suspicious file", "severity": "high", "observed_at": "2026-09-23T10:00:00+00:00",
                "attributes": {"sha256": "abc123"},
            }) + "\n", encoding="utf-8")
            self.assertEqual(process_events(events, output, ioc_database=ioc_db), 3)

    def test_processing_accepts_unormalized_jsonl_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            output = root / "alerts.jsonl"
            events.write_text(json.dumps({"type": "malware.detected", "message": "x"}) + "\n", encoding="utf-8")
            self.assertGreaterEqual(process_events(events, output), 1)

    def test_pipeline_deduplicates_and_creates_incident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event = {"event_id": "e1", "source": "endpoint", "event_type": "malware.detected", "message": "x", "severity": "high", "observed_at": "2026-09-23T10:00:00+00:00", "attributes": {}}
            alerts = process_event_records([event])
            self.assertEqual(len(deduplicate_alerts(alerts + alerts)), len(alerts))
            database = Path(directory) / "incidents.db"
            self.assertEqual(create_incidents_for_alerts(alerts, database), 1)
            self.assertEqual(len(SqliteEventStore(database).list_incidents()), 1)

    def test_worker_runs_one_processing_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            output = root / "alerts.jsonl"
            events.write_text(json.dumps({
                "event_id": "event-1", "source": "test", "event_type": "login.failed",
                "message": "failed", "severity": "medium", "observed_at": "2026-09-23T10:00:00+00:00",
                "attributes": {},
            }) + "\n", encoding="utf-8")
            self.assertEqual(run_once(events, output), 1)

    def test_incremental_worker_checkpoint_avoids_duplicate_processing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            output = root / "alerts.jsonl"
            state = root / "worker-state.json"
            record = {"event_id": "event-1", "source": "test", "event_type": "login.failed", "message": "failed", "severity": "medium", "observed_at": "2026-09-23T10:00:00+00:00", "attributes": {}}
            events.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertEqual(run_incremental(events, output, state), 1)
            self.assertEqual(run_incremental(events, output, state), 0)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(run_incremental(events, output, state), 0)

    def test_incremental_worker_creates_incidents_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            output = root / "alerts.jsonl"
            state = root / "worker-state.json"
            incidents = root / "siem.db"
            report = root / "reports" / "current.md"
            events.write_text(json.dumps({
                "event_id": "event-1", "source": "test", "event_type": "malware.detected",
                "message": "malware", "severity": "high", "observed_at": "2026-09-23T10:00:00+00:00",
                "attributes": {},
            }) + "\n", encoding="utf-8")
            self.assertEqual(run_incremental(events, output, state, incident_database=incidents, report_path=report), 2)
            self.assertEqual(len(SqliteEventStore(incidents).list_incidents()), 1)
            self.assertEqual(len(SqliteEventStore(incidents).search()), 1)
            self.assertIn("SIEM Incident Report", report.read_text(encoding="utf-8"))

    def test_worker_ingests_raw_syslog_incrementally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "auth.log"
            output = root / "alerts.jsonl"
            state = root / "state.json"
            source.write_text("<34>Sep 23 10:20:30 workstation sshd: Failed password for alice\n", encoding="utf-8")
            self.assertEqual(run_incremental(source, output, state, input_format="syslog", source="auth"), 1)
            self.assertEqual(run_incremental(source, output, state, input_format="syslog", source="auth"), 0)

    def test_worker_raw_line_id_is_stable_across_checkpoint_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, state, database = (root / name for name in ("events.log", "alerts.jsonl", "state.json", "siem.db"))
            source.write_text("<34>Sep 23 10:20:30 workstation sshd: Failed password for alice\n", encoding="utf-8")
            self.assertEqual(run_incremental(source, output, state, input_format="syslog", incident_database=database), 1)
            state.unlink()
            self.assertEqual(run_incremental(source, output, state, input_format="syslog", incident_database=database), 0)
            self.assertEqual(len(SqliteEventStore(database).list_incidents()), 1)

    def test_external_intelligence_is_cached_and_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def lookup(sha256, api_key):
                calls.append(sha256)
                return parse_file_response(sha256, {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 0}, "tags": ["peexe"]}}})
            event = {"event_id": "e1", "attributes": {"sha256": "a" * 64}}
            cache = Path(directory) / "cache.json"
            self.assertEqual(len(enrich_events([event], api_key="secret", cache_path=cache, lookup=lookup)), 1)
            self.assertEqual(len(enrich_events([event], api_key="secret", cache_path=cache, lookup=lookup)), 1)
            self.assertEqual(calls, ["a" * 64])

    def test_webhook_notification_posts_alert_batch(self) -> None:
        calls = []
        class Response:
            status = 202
            def __enter__(self): return self
            def __exit__(self, *args): return False
        def opener(request, timeout):
            calls.append((request, timeout))
            return Response()
        send_webhook("https://alerts.example/siem", [{"title": "test"}], token="secret", opener=opener)
        self.assertEqual(calls[0][0].get_header("Authorization"), "Bearer secret")
        self.assertIn('"title": "test"', calls[0][0].data.decode())

    def test_sqlite_backup_is_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.db"
            backup = root / "backup" / "siem.db"
            store = SqliteEventStore(source)
            store.append(SecurityEvent.now(source="test", event_type="test.event", message="test"))
            backup_database(source, backup)
            copied = SqliteEventStore(backup)
            self.assertEqual(len(copied.search(text="test.event")), 1)

    def test_sqlite_database_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "siem.db"
            SqliteEventStore(path)
            result = verify_database(path)
            self.assertTrue(result["valid"])

    def test_retention_defaults_to_preview_and_can_delete_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "siem.db"
            store = SqliteEventStore(path)
            store.append(SecurityEvent(
                source="test", event_type="old.event", message="old",
                observed_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            ))
            self.assertEqual(prune_events(path, older_than_days=1), 1)
            self.assertEqual(len(store.search(text="old")), 1)
            self.assertEqual(prune_events(path, older_than_days=1, apply=True), 1)
            self.assertEqual(len(store.search(text="old")), 0)

    def test_sandbox_submission_creates_pending_job_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            spool = root / "sandbox"
            sample.write_bytes(b"harmless test sample")
            job = create_job(sample, spool)
            self.assertEqual(job.status, "pending")
            self.assertIsNone(job.sample_path)
            self.assertTrue((spool / "jobs.jsonl").exists())
            self.assertTrue(sample.exists())

    def test_sandbox_result_is_hash_checked_and_normalized(self) -> None:
        result = {
            "job_id": "job-1", "sha256": "abc123", "status": "completed",
            "findings": [{"type": "network.connection", "message": "Observed connection", "severity": "high"}],
        }
        validate_result(result, expected_sha256="ABC123")
        events = result_to_events(result)
        self.assertEqual(events[1].event_type, "sandbox.network.connection")
        with self.assertRaises(SandboxResultError):
            validate_result(result, expected_sha256="wrong")

    def test_windows_event_export_is_normalized(self) -> None:
        event = parse_windows_event({
            "Event": {"System": {"EventID": 4625, "TimeCreated": "2026-09-23T10:00:00Z", "Computer": "WIN-01", "Provider": {"Name": "Security-Auditing"}},
                      "EventData": {"Data": [{"Name": "TargetUserName", "#text": "alice"}]}},
            "Message": "An account failed to log on",
        })
        self.assertEqual(event.event_type, "windows.event.4625")
        self.assertEqual(event.severity, "medium")
        self.assertEqual(event.attributes["TargetUserName"], "alice")

    def test_network_logs_are_normalized(self) -> None:
        firewall = parse_ufw_line("Jan 1 00:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.2 DST=10.0.0.1 PROTO=TCP SPT=1234 DPT=22")
        access = parse_access_line("10.0.0.2 - - [23/Sep/2026:10:00:00 +0000] \"GET /admin HTTP/1.1\" 403 123")
        self.assertEqual(firewall.event_type, "firewall.block")
        self.assertEqual(firewall.attributes["dst_port"], 22)
        self.assertEqual(access.event_type, "web.request")
        self.assertEqual(access.attributes["status"], 403)


if __name__ == "__main__":
    unittest.main()
