"""SIEM-3: Threat Detection & Correlation Engine.

Entry point for the detection module: per-event alert rules, cross-event
brute-force correlation, IOC matching, incident creation, and the
continuous detection worker.

Examples:
    python detector.py rules [--rules rules.toml]
    python detector.py check-rules rules.toml
    python detector.py detect data/events.jsonl --output data/alerts.jsonl --database data/siem.db
    python detector.py worker /var/log/auth.log --format syslog --database data/siem.db --rules rules.toml

Rules are configured in TOML (see rules.example.toml); built-in defaults apply
to anything the file does not set. $SIEM_RULES is used when --rules is absent.

The worker indexes each batch into the database and correlates it together
with the last few minutes of stored logins, so attacks that span several
worker cycles are still detected. Malformed lines are logged and skipped.
"""

import argparse
import json
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from siem.detection.config import RulesConfig, RulesConfigError, load_rules  # noqa: E402
from siem.detection.correlation import (  # noqa: E402
    correlate, correlate_failed_logins, correlate_failure_then_success, correlate_privilege_failures,
    correlate_source_spray,
)
from siem.detection.engine import detect  # noqa: E402
from siem.ingestion.formats import PARSERS  # noqa: E402
from siem.pipeline.run import create_incidents_for_alerts, deduplicate_alerts, process_event_records  # noqa: E402
from siem.pipeline.worker import run_forever, run_incremental  # noqa: E402
from siem.reporting.report import load_jsonl  # noqa: E402
from siem.storage.sqlite import SqliteEventStore  # noqa: E402

__all__ = ["describe_rules", "load_rules", "detect", "correlate", "correlate_failed_logins", "correlate_source_spray",
           "correlate_failure_then_success", "correlate_privilege_failures", "deduplicate_alerts",
           "process_event_records", "create_incidents_for_alerts", "run_incremental", "run_forever"]


def describe_rules(config: RulesConfig) -> list[tuple[str, str]]:
    """(rule_id, description) for every enabled rule in `config`."""
    rows: list[tuple[str, str]] = []
    if config.high_severity:
        rows.append(("event.high-severity", "Any event recorded with high or critical severity."))
    if config.suspicious_types is not None:
        rows.append(("event.suspicious-type", f"Event types: {', '.join(sorted(config.suspicious_types))}."))
    if config.failed_login:
        rows.append(("auth.failed-login", "Each failed login (medium)."))
    for rule_id, rule, text in (
        ("correlation.failed-login-burst", config.failed_login_burst, "failed logins for one account (high)"),
        ("correlation.source-login-spray", config.source_spray, "failed logins from one IP across accounts (high)"),
        ("correlation.failed-then-success", config.failed_then_success, "failures, then a successful login (critical)"),
        ("correlation.privilege-failures", config.privilege_failures, "failed sudo/su passwords by one user (high)"),
    ):
        if rule.enabled:
            rows.append((rule_id, f"{rule.threshold}+ {text} within {rule.window_seconds}s."))
    rows.extend((rule.id, f"{rule.title} [{rule.severity}] on {rule.event_type}") for rule in config.match)
    rows.append(("intel.local-match", "Event hash/IP/domain/URL matches a local IOC (with --ioc-database)."))
    rows.append(("intel.external-reputation", "VirusTotal flags an event's SHA-256 (optional)."))
    return rows


def detect_events(events_path: Path, output_path: Path, *, ioc_database: Path | None = None,
                  incident_database: Path | None = None, rules: RulesConfig | None = None) -> tuple[int, int]:
    """One-shot detection over a normalized events file. Returns (alerts, incidents).

    With `incident_database`, the events and alerts are also stored there so
    the dashboard can search and pivot on them.
    """
    events = load_jsonl(events_path)
    alerts = process_event_records(events, ioc_database=ioc_database, rules=rules)
    if incident_database:
        store = SqliteEventStore(incident_database)
        store.append_records(events)
        store.append_alerts([alert.to_record() for alert in alerts])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
    incidents = create_incidents_for_alerts(alerts, incident_database) if incident_database else 0
    return len(alerts), incidents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detector", description="SIEM detection and correlation engine")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rules", help="list enabled detection rules").add_argument("--rules", type=Path, help="rules TOML file")
    commands.add_parser("check-rules", help="validate a rules TOML file").add_argument("file", type=Path)
    once = commands.add_parser("detect", help="run all detection stages once over normalized events")
    once.add_argument("input", type=Path)
    once.add_argument("--output", type=Path, default=Path("data/alerts.jsonl"))
    once.add_argument("--ioc-database", type=Path)
    once.add_argument("--database", type=Path, help="create incidents in this SIEM database")
    once.add_argument("--rules", type=Path, help="rules TOML file")
    worker = commands.add_parser("worker", help="continuously detect on a growing log or events file")
    worker.add_argument("input", type=Path)
    worker.add_argument("--format", dest="input_format", choices=["normalized", *sorted(PARSERS)], default="normalized")
    worker.add_argument("--source", default="worker-input")
    worker.add_argument("--database", type=Path, default=Path("data/siem.db"), help="event index + incidents")
    worker.add_argument("--output", type=Path, default=Path("data/all-alerts.jsonl"))
    worker.add_argument("--state", type=Path, default=Path("data/worker-state.json"))
    worker.add_argument("--ioc-database", type=Path)
    worker.add_argument("--report", type=Path)
    worker.add_argument("--interval", type=float, default=30.0)
    worker.add_argument("--rules", type=Path, help="rules TOML file (re-read every cycle)")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.file if args.command == "check-rules" else args.rules)
    except (OSError, RulesConfigError) as exc:
        print(f"invalid rules: {exc}", file=sys.stderr)
        return 1
    if args.command == "check-rules":
        print(f"{args.file}: OK ({len(describe_rules(rules))} rules enabled)")
        return 0
    if args.command == "rules":
        for rule_id, description in describe_rules(rules):
            print(f"{rule_id:36} {description}")
        return 0
    if args.command == "detect":
        try:
            alerts, incidents = detect_events(args.input, args.output, ioc_database=args.ioc_database,
                                              incident_database=args.database, rules=rules)
        except (OSError, ValueError, KeyError) as exc:
            print(f"detection failed: {exc}", file=sys.stderr)
            return 1
        print(f"{alerts} alert(s) written to {args.output}; {incidents} incident(s) created or extended")
        return 0

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(f"detector worker on {args.input} ({args.input_format}) every {args.interval:g}s")
    try:
        run_forever(args.input, args.output, state_path=args.state, input_format=args.input_format,
                    source=args.source, incident_database=args.database, ioc_database=args.ioc_database,
                    report_path=args.report, interval_seconds=args.interval, rules_path=args.rules,
                    on_cycle=lambda count: count and print(f"{count} new alert(s)"))
    except KeyboardInterrupt:
        print("detector stopped")
    except ValueError as exc:
        print(f"detector failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
