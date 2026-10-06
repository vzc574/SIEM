"""Command-line interface for the SIEM foundation."""

import argparse
from pathlib import Path
import sys
import json
import os

from siem.ingestion.json_lines import JsonLogParseError
from siem.ingestion.runner import ingest_file
from siem.ingestion.syslog import SyslogParseError
from siem.ingestion.syslog_runner import ingest_syslog
from siem.ingestion.windows import WindowsEventError
from siem.ingestion.windows_runner import ingest_windows_json
from siem.ingestion.network import NetworkLogError
from siem.ingestion.network_runner import ingest_network
from siem.api.server import create_server
from siem.detection.engine import detect_file
from siem.detection.correlation import correlate
from siem.analysis.static import analyze_file
from siem.response.quarantine import quarantine_file
from siem.reporting.report import build_context, generate_report
from siem.storage.sqlite import SqliteEventStore
from siem.reporting.report import load_jsonl
from siem.ai.openai_reports import AIIntegrationError, generate_ai_report
from siem.intel.store import IOCStore
from siem.intel.matcher import match_events
from siem.intel.virustotal import VirusTotalError, lookup_hash
from siem.pipeline.run import create_incidents_for_alerts, process_event_records, process_events
from siem.pipeline.worker import run_forever
from siem.storage.backup import backup_database
from siem.storage.verify import verify_database
from siem.storage.retention import prune_events
from siem.sandbox.jobs import create_job
from siem.sandbox.results import SandboxResultError, result_to_events, validate_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="siem", description="Defensive SIEM utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ingest_parser = subparsers.add_parser("ingest-jsonl", help="import newline-delimited JSON logs")
    ingest_parser.add_argument("input", type=Path, help="input JSONL log file")
    ingest_parser.add_argument("--source", default="jsonl-import", help="source name when a record omits source")
    ingest_parser.add_argument("--output", type=Path, default=Path("data/events.jsonl"), help="event store path")
    syslog_parser = subparsers.add_parser("ingest-syslog", help="import a Linux syslog file")
    syslog_parser.add_argument("input", type=Path, help="syslog file path")
    syslog_parser.add_argument("--source", default="linux-syslog", help="collector source name")
    syslog_parser.add_argument("--output", type=Path, default=Path("data/events.jsonl"), help="event store path")
    windows_parser = subparsers.add_parser("ingest-windows-json", help="import exported Windows Event Log JSON")
    windows_parser.add_argument("input", type=Path)
    windows_parser.add_argument("--source", default="windows-eventlog")
    windows_parser.add_argument("--output", type=Path, default=Path("data/events.jsonl"))
    network_parser = subparsers.add_parser("ingest-network", help="import UFW or web access logs")
    network_parser.add_argument("input", type=Path)
    network_parser.add_argument("--format", choices=["ufw", "access"], required=True)
    network_parser.add_argument("--source", default="network-log")
    network_parser.add_argument("--output", type=Path, default=Path("data/events.jsonl"))
    detect_parser = subparsers.add_parser("detect", help="evaluate stored events with built-in rules")
    detect_parser.add_argument("input", type=Path, help="normalized event JSONL file")
    detect_parser.add_argument("--output", type=Path, default=Path("data/alerts.jsonl"), help="alert output path")
    correlate_parser = subparsers.add_parser("correlate", help="correlate event sequences and time windows")
    correlate_parser.add_argument("input", type=Path, help="normalized event JSONL file")
    correlate_parser.add_argument("--output", type=Path, default=Path("data/correlation-alerts.jsonl"), help="alert output path")
    analyze_parser = subparsers.add_parser("analyze-file", help="perform non-executing static file analysis")
    analyze_parser.add_argument("input", type=Path, help="file to analyze")
    analyze_parser.add_argument("--output", type=Path, help="optional JSON report path")
    quarantine_parser = subparsers.add_parser("quarantine", help="plan or apply file quarantine")
    quarantine_parser.add_argument("input", type=Path, help="file to quarantine")
    quarantine_parser.add_argument("--directory", type=Path, default=Path("quarantine"), help="quarantine directory")
    quarantine_parser.add_argument("--apply", action="store_true", help="actually move the file")
    report_parser = subparsers.add_parser("report", help="generate an evidence-based Markdown report")
    report_parser.add_argument("alerts", type=Path, help="alerts JSONL file")
    report_parser.add_argument("--analysis", type=Path, help="optional static-analysis JSON report")
    report_parser.add_argument("--output", type=Path, default=Path("reports/incident.md"), help="Markdown output path")
    index_parser = subparsers.add_parser("index-events", help="import normalized JSONL events into SQLite")
    index_parser.add_argument("input", type=Path, help="normalized event JSONL file")
    index_parser.add_argument("--database", type=Path, default=Path("data/siem.db"), help="SQLite database path")
    search_parser = subparsers.add_parser("search", help="search indexed security events")
    search_parser.add_argument("--database", type=Path, default=Path("data/siem.db"), help="SQLite database path")
    search_parser.add_argument("--text", help="search event text, type, or source")
    search_parser.add_argument("--severity", help="filter by severity")
    search_parser.add_argument("--limit", type=int, default=100)
    serve_parser = subparsers.add_parser("serve", help="start the local read-only REST API")
    serve_parser.add_argument("--host", default="127.0.0.1", help="bind address")
    serve_parser.add_argument("--port", type=int, default=8080, help="bind port")
    serve_parser.add_argument("--database", type=Path, default=Path("data/siem.db"), help="SQLite database path")
    serve_parser.add_argument("--alerts", type=Path, action="append", default=[], help="alert JSONL path; may be repeated")
    ai_parser = subparsers.add_parser("ai-report", help="generate an optional AI-assisted report")
    ai_parser.add_argument("alerts", type=Path, help="alerts JSONL file")
    ai_parser.add_argument("--analysis", type=Path, help="optional static-analysis JSON report")
    ai_parser.add_argument("--output", type=Path, default=Path("reports/ai-incident.md"), help="report output path")
    ai_parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-5"), help="OpenAI model name")
    ioc_add = subparsers.add_parser("ioc-add", help="add a local threat-intelligence indicator")
    ioc_add.add_argument("kind", choices=["md5", "sha1", "sha256", "ip", "domain", "url"])
    ioc_add.add_argument("value")
    ioc_add.add_argument("--source", default="local")
    ioc_add.add_argument("--confidence", type=int, default=50)
    ioc_add.add_argument("--database", type=Path, default=Path("data/threat-intel.db"))
    ioc_scan = subparsers.add_parser("ioc-scan-events", help="match events against local indicators")
    ioc_scan.add_argument("input", type=Path)
    ioc_scan.add_argument("--database", type=Path, default=Path("data/threat-intel.db"))
    ioc_scan.add_argument("--output", type=Path, default=Path("data/intel-alerts.jsonl"))
    vt_parser = subparsers.add_parser("vt-hash", help="look up a hash without uploading a file")
    vt_parser.add_argument("sha256")
    vt_parser.add_argument("--api-key", default=os.getenv("VIRUSTOTAL_API_KEY"))
    process_parser = subparsers.add_parser("process", help="run detection, correlation, and IOC matching")
    process_parser.add_argument("input", type=Path, help="normalized event JSONL file")
    process_parser.add_argument("--output", type=Path, default=Path("data/all-alerts.jsonl"))
    process_parser.add_argument("--ioc-database", type=Path, help="optional local IOC database")
    process_parser.add_argument("--incident-database", type=Path, help="optional database for automatic incidents")
    worker_parser = subparsers.add_parser("worker", help="run the processing pipeline continuously")
    worker_parser.add_argument("input", type=Path, help="normalized event JSONL file")
    worker_parser.add_argument("--format", dest="input_format", choices=["normalized", "jsonl", "syslog", "windows-json", "ufw", "access"], default="normalized",
                               help="input log format (default: normalized)")
    worker_parser.add_argument("--source", default="worker-input", help="source label for raw log formats")
    worker_parser.add_argument("--external-api-key", default=os.getenv("VIRUSTOTAL_API_KEY"), help="optional VirusTotal API key")
    worker_parser.add_argument("--external-cache", type=Path, default=Path("data/external-intel-cache.json"))
    worker_parser.add_argument("--external-max-hashes", type=int, default=10)
    worker_parser.add_argument("--webhook-url", help="optional HTTPS endpoint for fresh alert batches")
    worker_parser.add_argument("--webhook-token", default=os.getenv("SIEM_WEBHOOK_TOKEN"), help="optional webhook bearer token")
    worker_parser.add_argument("--output", type=Path, default=Path("data/all-alerts.jsonl"))
    worker_parser.add_argument("--ioc-database", type=Path)
    worker_parser.add_argument("--incident-database", type=Path, help="SQLite database for automatic incidents")
    worker_parser.add_argument("--report", type=Path, help="write a deterministic Markdown report each cycle")
    worker_parser.add_argument("--interval", type=float, default=30.0, help="seconds between cycles")
    worker_parser.add_argument("--state", type=Path, default=Path("data/worker-state.json"), help="checkpoint file")
    backup_parser = subparsers.add_parser("backup-db", help="create a consistent SQLite backup")
    backup_parser.add_argument("database", type=Path)
    backup_parser.add_argument("output", type=Path)
    verify_parser = subparsers.add_parser("verify-db", help="verify SQLite integrity and schema")
    verify_parser.add_argument("database", type=Path)
    retention_parser = subparsers.add_parser("prune-events", help="preview or apply event retention")
    retention_parser.add_argument("database", type=Path)
    retention_parser.add_argument("--older-than-days", type=int, required=True)
    retention_parser.add_argument("--apply", action="store_true", help="delete matching events")
    retention_parser.add_argument("--backup", type=Path, help="backup database before deletion")
    sandbox_parser = subparsers.add_parser("sandbox-submit", help="create a job for an external isolated sandbox")
    sandbox_parser.add_argument("input", type=Path, help="file to hand off")
    sandbox_parser.add_argument("--spool", type=Path, default=Path("data/sandbox"), help="sandbox job spool directory")
    sandbox_parser.add_argument("--spool-sample", action="store_true", help="copy the sample into the spool")
    result_parser = subparsers.add_parser("sandbox-ingest-result", help="validate an external sandbox result")
    result_parser.add_argument("input", type=Path, help="sandbox result JSON file")
    result_parser.add_argument("--output", type=Path, default=Path("data/sandbox-events.jsonl"))
    result_parser.add_argument("--sha256", help="expected submitted sample hash")
    result_parser.add_argument("--signing-key", help="HMAC verification key")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "ingest-jsonl":
        try:
            result = ingest_file(args.input, args.output, default_source=args.source)
        except (FileNotFoundError, JsonLogParseError, OSError) as exc:
            print(f"ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {result.events_written} event(s) to {result.output_path}")
        return 0
    if args.command == "ingest-syslog":
        try:
            count = ingest_syslog(args.input, args.output, source=args.source)
        except (FileNotFoundError, SyslogParseError, OSError) as exc:
            print(f"syslog ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {count} event(s) to {args.output}")
        return 0
    if args.command == "ingest-windows-json":
        try:
            count = ingest_windows_json(args.input, args.output, source=args.source)
        except (FileNotFoundError, WindowsEventError, OSError) as exc:
            print(f"Windows event ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {count} event(s) to {args.output}")
        return 0
    if args.command == "ingest-network":
        try:
            count = ingest_network(args.input, args.output, format_name=args.format, source=args.source)
        except (FileNotFoundError, NetworkLogError, OSError) as exc:
            print(f"network log ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {count} event(s) to {args.output}")
        return 0
    if args.command == "detect":
        try:
            alerts = detect_file(args.input, args.output)
        except (OSError, ValueError) as exc:
            print(f"detection failed: {exc}", file=sys.stderr)
            return 1
        print(f"generated {len(alerts)} alert(s) in {args.output}")
        return 0
    if args.command == "correlate":
        try:
            events = load_jsonl(args.input)
            alerts = correlate(events)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text("\n".join(json.dumps(alert.to_record(), sort_keys=True) for alert in alerts) + ("\n" if alerts else ""), encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"correlation failed: {exc}", file=sys.stderr)
            return 1
        print(f"generated {len(alerts)} correlation alert(s) in {args.output}")
        return 0
    if args.command == "analyze-file":
        try:
            analysis = analyze_file(args.input)
            record = json.dumps(analysis.to_record(), indent=2, sort_keys=True)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(record + "\n", encoding="utf-8")
                print(f"wrote static analysis report to {args.output}")
            else:
                print(record)
            return 0
        except (OSError, ValueError) as exc:
            print(f"file analysis failed: {exc}", file=sys.stderr)
            return 1
    if args.command == "quarantine":
        try:
            result = quarantine_file(args.input, args.directory, apply=args.apply)
        except (OSError, ValueError) as exc:
            print(f"quarantine failed: {exc}", file=sys.stderr)
            return 1
        mode = "moved" if result.applied else "planned (dry-run)"
        print(f"{mode}: {result.source} -> {result.destination}")
        print(f"sha256: {result.sha256}")
        return 0
    if args.command == "report":
        try:
            context = generate_report(args.alerts, args.output, args.analysis)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"report generation failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote report with {context['alert_count']} alert(s) to {args.output}")
        return 0
    if args.command == "index-events":
        try:
            count = SqliteEventStore(args.database).append_records(load_jsonl(args.input))
        except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
            print(f"indexing failed: {exc}", file=sys.stderr)
            return 1
        print(f"indexed {count} event(s) in {args.database}")
        return 0
    if args.command == "search":
        try:
            results = SqliteEventStore(args.database).search(text=args.text, severity=args.severity, limit=args.limit)
        except (OSError, ValueError) as exc:
            print(f"search failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0
    if args.command == "serve":
        try:
            server = create_server(args.host, args.port, args.database, os.getenv("SIEM_API_KEY"), args.alerts)
        except (OSError, ValueError) as exc:
            print(f"API startup failed: {exc}", file=sys.stderr)
            return 1
        print(f"SIEM API listening on http://{args.host}:{server.server_address[1]}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    if args.command == "ai-report":
        try:
            analysis = json.loads(args.analysis.read_text(encoding="utf-8")) if args.analysis else None
            context = build_context(load_jsonl(args.alerts), analysis)
            report = generate_ai_report(context, model=args.model)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report + "\n", encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError, AIIntegrationError) as exc:
            print(f"AI report generation failed: {exc}", file=sys.stderr)
            return 1
        print(f"wrote AI-assisted report to {args.output}")
        return 0
    if args.command == "ioc-add":
        try:
            IOCStore(args.database).add(args.kind, args.value, source=args.source, confidence=args.confidence)
        except (OSError, ValueError) as exc:
            print(f"IOC add failed: {exc}", file=sys.stderr)
            return 1
        print(f"stored {args.kind} indicator in {args.database}")
        return 0
    if args.command == "ioc-scan-events":
        try:
            alerts = match_events(load_jsonl(args.input), IOCStore(args.database))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text("\n".join(json.dumps(alert.to_record(), sort_keys=True) for alert in alerts) + ("\n" if alerts else ""), encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"IOC scan failed: {exc}", file=sys.stderr)
            return 1
        print(f"generated {len(alerts)} intelligence alert(s) in {args.output}")
        return 0
    if args.command == "vt-hash":
        if not args.api_key:
            print("VirusTotal lookup requires VIRUSTOTAL_API_KEY or --api-key", file=sys.stderr)
            return 1
        try:
            print(json.dumps(lookup_hash(args.sha256, args.api_key).to_record(), indent=2, sort_keys=True))
        except (ValueError, VirusTotalError) as exc:
            print(f"VirusTotal lookup failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "process":
        try:
            alerts = process_event_records(load_jsonl(args.input), ioc_database=args.ioc_database)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text("\n".join(json.dumps(alert.to_record(), sort_keys=True) for alert in alerts) + ("\n" if alerts else ""), encoding="utf-8")
            incidents = create_incidents_for_alerts(alerts, args.incident_database) if args.incident_database else 0
            count = len(alerts)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"processing failed: {exc}", file=sys.stderr)
            return 1
        print(f"generated {count} alert(s) and {incidents} incident(s) in {args.output}")
        return 0
    if args.command == "worker":
        try:
            print(f"worker started; processing every {args.interval:g} seconds")
            run_forever(args.input, args.output, ioc_database=args.ioc_database, incident_database=args.incident_database,
                        report_path=args.report, state_path=args.state, interval_seconds=args.interval,
                        input_format=args.input_format, source=args.source,
                        external_api_key=args.external_api_key, external_cache=args.external_cache,
                        external_max_hashes=args.external_max_hashes,
                        webhook_url=args.webhook_url, webhook_token=args.webhook_token,
                        on_cycle=lambda count: print(f"generated {count} alert(s)"))
        except KeyboardInterrupt:
            print("worker stopped")
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"worker failed: {exc}", file=sys.stderr)
            return 1
    if args.command == "backup-db":
        try:
            backup_database(args.database, args.output)
        except (OSError, ValueError) as exc:
            print(f"database backup failed: {exc}", file=sys.stderr)
            return 1
        print(f"created database backup at {args.output}")
        return 0
    if args.command == "verify-db":
        try:
            result = verify_database(args.database)
        except OSError as exc:
            print(f"database verification failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    if args.command == "prune-events":
        try:
            count = prune_events(args.database, older_than_days=args.older_than_days, apply=args.apply, backup_path=args.backup)
        except (OSError, ValueError) as exc:
            print(f"retention operation failed: {exc}", file=sys.stderr)
            return 1
        mode = "deleted" if args.apply else "would delete"
        print(f"{mode} {count} event(s)")
        return 0
    if args.command == "sandbox-submit":
        try:
            job = create_job(args.input, args.spool, spool_sample=args.spool_sample)
        except OSError as exc:
            print(f"sandbox submission failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(job.to_record(), indent=2, sort_keys=True))
        return 0
    if args.command == "sandbox-ingest-result":
        try:
            result = json.loads(args.input.read_text(encoding="utf-8"))
            validate_result(result, expected_sha256=args.sha256, signing_key=args.signing_key or os.getenv("SANDBOX_RESULT_KEY"))
            events = result_to_events(result)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text("\n".join(json.dumps(event.to_record(), sort_keys=True) for event in events) + "\n", encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError, SandboxResultError) as exc:
            print(f"sandbox result ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(f"ingested {len(events)} sandbox event(s) into {args.output}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
