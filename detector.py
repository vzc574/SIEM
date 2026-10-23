"""SIEM-3: Threat Detection & Correlation Engine.

Entry point for the detection module: per-event alert rules, cross-event
brute-force correlation, IOC matching, incident creation, and the
continuous detection worker.

Examples:
    python detector.py rules
    python detector.py detect data/events.jsonl --output data/alerts.jsonl --database data/siem.db
    python detector.py worker /var/log/auth.log --format syslog --database data/siem.db

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

from siem.detection.correlation import (  # noqa: E402
    correlate, correlate_failed_logins, correlate_failure_then_success, correlate_source_spray,
)
from siem.detection.engine import detect  # noqa: E402
from siem.ingestion.formats import PARSERS  # noqa: E402
from siem.pipeline.run import create_incidents_for_alerts, deduplicate_alerts, process_event_records  # noqa: E402
from siem.pipeline.worker import run_forever, run_incremental  # noqa: E402
from siem.reporting.report import load_jsonl  # noqa: E402

__all__ = ["RULES", "detect", "correlate", "correlate_failed_logins", "correlate_source_spray",
           "correlate_failure_then_success", "deduplicate_alerts", "process_event_records",
           "create_incidents_for_alerts", "run_incremental", "run_forever"]

RULES: dict[str, str] = {
    "event.high-severity": "Any event recorded with high or critical severity.",
    "event.suspicious-type": "Event types such as malware.detected or credential.theft.",
    "auth.failed-login": "Each failed login (medium).",
    "correlation.failed-login-burst": "5+ failed logins for one account within 5 minutes (high).",
    "correlation.source-login-spray": "10+ failed logins from one source IP across accounts within 5 minutes (high).",
    "correlation.failed-then-success": "A successful login after 3+ failures for the account within 5 minutes (critical).",
    "intel.local-match": "Event hash/IP/domain/URL matches a local IOC.",
    "intel.external-reputation": "VirusTotal flags an event's SHA-256 (optional).",
}


def detect_events(events_path: Path, output_path: Path, *, ioc_database: Path | None = None,
                  incident_database: Path | None = None) -> tuple[int, int]:
    """One-shot detection over a normalized events file. Returns (alerts, incidents)."""
    alerts = process_event_records(load_jsonl(events_path), ioc_database=ioc_database)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
    incidents = create_incidents_for_alerts(alerts, incident_database) if incident_database else 0
    return len(alerts), incidents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detector", description="SIEM detection and correlation engine")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rules", help="list detection rules")
    once = commands.add_parser("detect", help="run all detection stages once over normalized events")
    once.add_argument("input", type=Path)
    once.add_argument("--output", type=Path, default=Path("data/alerts.jsonl"))
    once.add_argument("--ioc-database", type=Path)
    once.add_argument("--database", type=Path, help="create incidents in this SIEM database")
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
    args = parser.parse_args(argv)

    if args.command == "rules":
        for rule_id, description in RULES.items():
            print(f"{rule_id:36} {description}")
        return 0
    if args.command == "detect":
        try:
            alerts, incidents = detect_events(args.input, args.output, ioc_database=args.ioc_database,
                                              incident_database=args.database)
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
                    report_path=args.report, interval_seconds=args.interval,
                    on_cycle=lambda count: count and print(f"{count} new alert(s)"))
    except KeyboardInterrupt:
        print("detector stopped")
    except ValueError as exc:
        print(f"detector failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
