"""Simple continuously-running pipeline worker."""

from pathlib import Path
import json
import hashlib
import time
from typing import Callable
from typing import Any

from siem.ingestion.network import parse_access_line, parse_ufw_line
from siem.ingestion.json_lines import parse_json_record
from siem.ingestion.syslog import parse_syslog_line
from siem.ingestion.windows import parse_windows_event
from siem.pipeline.run import create_incidents_for_alerts, process_event_records, process_events
from siem.reporting.report import generate_report
from siem.response.notify import NotificationError, send_webhook
from siem.storage.sqlite import SqliteEventStore


def _alert_key(record: dict[str, Any]) -> str:
    evidence = json.dumps(record.get("evidence", {}), sort_keys=True, separators=(",", ":"))
    return "|".join(str(record.get(field, "")) for field in ("rule_id", "title", "event_id", "reason")) + "|" + evidence


def _existing_alert_keys(path: Path) -> set[str]:
    if not path.exists():
        return set()
    keys: set[str] = set()
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                try:
                    keys.add(_alert_key(json.loads(line)))
                except json.JSONDecodeError:
                    continue
    return keys


def run_once(input_path: Path, output_path: Path, ioc_database: Path | None = None) -> int:
    return process_events(input_path, output_path, ioc_database=ioc_database)


def _parse_worker_line(line: str, input_format: str, source: str) -> dict[str, Any]:
    if input_format in {"normalized", "jsonl"}:
        import json as _json
        record = _json.loads(line)
        if not record.get("event_id"):
            record["event_id"] = "worker-" + hashlib.sha256(line.encode("utf-8")).hexdigest()
        return record
    if input_format == "syslog":
        record = parse_syslog_line(line, source=source).to_record()
    elif input_format == "windows-json":
        import json as _json
        record = parse_windows_event(_json.loads(line), source=source).to_record()
    elif input_format == "ufw":
        record = parse_ufw_line(line, source=source).to_record()
    elif input_format == "access":
        record = parse_access_line(line, source=source).to_record()
    else:
        raise ValueError(f"unsupported worker input format: {input_format}")
    record["event_id"] = "worker-" + hashlib.sha256(line.encode("utf-8")).hexdigest()
    return record


def _normalize_worker_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events:
        if "observed_at" not in event or "event_id" not in event:
            parsed = parse_json_record(event, default_source="worker-input").to_record()
            if event.get("event_id"):
                parsed["event_id"] = event["event_id"]
            normalized.append(parsed)
        else:
            normalized.append(event)
    return normalized


def run_incremental(
    input_path: Path,
    output_path: Path,
    state_path: Path,
    *,
    ioc_database: Path | None = None,
    incident_database: Path | None = None,
    report_path: Path | None = None,
    input_format: str = "normalized",
    source: str = "worker-input",
    external_api_key: str | None = None,
    external_cache: Path | None = None,
    external_max_hashes: int = 10,
    webhook_url: str | None = None,
    webhook_token: str | None = None,
) -> int:
    """Process only lines after the durable checkpoint."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"line_offset": 0}
    offset = int(state.get("line_offset", 0))
    lines = input_path.read_text(encoding="utf-8").splitlines()
    if offset > len(lines):
        offset = 0
    events = _normalize_worker_events([_parse_worker_line(line, input_format, source) for line in lines[offset:] if line.strip()])
    alerts = process_event_records(events, ioc_database=ioc_database, external_api_key=external_api_key,
                                   external_cache=external_cache, external_max_hashes=external_max_hashes)
    if incident_database and events:
        # The incident database is also the durable event index used by the
        # dashboard. INSERT OR IGNORE makes replay safe after a crash.
        SqliteEventStore(incident_database).append_records(events)
    existing = _existing_alert_keys(output_path)
    fresh_alerts = [alert for alert in alerts if _alert_key(alert.to_record()) not in existing]
    if fresh_alerts:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as stream:
            for alert in fresh_alerts:
                stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
        if incident_database:
            create_incidents_for_alerts(fresh_alerts, incident_database)
        if webhook_url:
            try:
                send_webhook(webhook_url, [alert.to_record() for alert in fresh_alerts], token=webhook_token)
            except NotificationError:
                # Alerts remain durable in output_path; operators can retry
                # delivery from that append-only stream independently.
                pass
    if report_path:
        generate_report(output_path, report_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps({"line_offset": len(lines)}, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(state_path)
    return len(fresh_alerts)


def run_forever(
    input_path: Path,
    output_path: Path,
    *,
    ioc_database: Path | None = None,
    incident_database: Path | None = None,
    report_path: Path | None = None,
    input_format: str = "normalized",
    source: str = "worker-input",
    external_api_key: str | None = None,
    external_cache: Path | None = None,
    external_max_hashes: int = 10,
    webhook_url: str | None = None,
    webhook_token: str | None = None,
    state_path: Path | None = None,
    interval_seconds: float = 30.0,
    on_cycle: Callable[[int], None] | None = None,
) -> None:
    if interval_seconds < 1:
        raise ValueError("interval must be at least one second")
    while True:
        try:
            count = run_incremental(
                input_path, output_path, state_path or output_path.with_suffix(".state.json"),
                ioc_database=ioc_database, incident_database=incident_database, report_path=report_path,
                input_format=input_format, source=source,
                external_api_key=external_api_key, external_cache=external_cache,
                external_max_hashes=external_max_hashes,
                webhook_url=webhook_url, webhook_token=webhook_token,
            )
        except FileNotFoundError:
            # A newly deployed worker may start before its first collector
            # creates the input file. Keep the service alive and retry.
            count = 0
        if on_cycle:
            on_cycle(count)
        time.sleep(interval_seconds)
