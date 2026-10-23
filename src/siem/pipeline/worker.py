"""Simple continuously-running pipeline worker."""

from datetime import timedelta
from pathlib import Path
import json
import hashlib
import logging
import time
from typing import Callable
from typing import Any

from siem.detection.config import RulesConfig, RulesConfigError, load_rules
from siem.detection.correlation import HISTORY_EVENT_TYPES, _time
from siem.ingestion.formats import LogLineError, parse_line
from siem.ingestion.json_lines import parse_json_record
from siem.domain.alerts import alert_record_key
from siem.pipeline.run import create_incidents_for_alerts, process_event_records, process_events
from siem.reporting.report import generate_report
from siem.response.notify import NotificationError, Notifier, send_webhook
from siem.storage.sqlite import SqliteEventStore


logger = logging.getLogger(__name__)
MAX_BYTES_PER_CYCLE = 16 * 1024 * 1024


def _existing_alert_keys(path: Path) -> set[str]:
    if not path.exists():
        return set()
    keys: set[str] = set()
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                try:
                    keys.add(alert_record_key(json.loads(line)))
                except json.JSONDecodeError:
                    continue
    return keys


def run_once(input_path: Path, output_path: Path, ioc_database: Path | None = None) -> int:
    return process_events(input_path, output_path, ioc_database=ioc_database)


def _parse_worker_line(line: str, input_format: str, source: str) -> dict[str, Any]:
    if input_format in {"normalized", "jsonl"}:
        record = json.loads(line)
        if not isinstance(record, dict):
            raise LogLineError("record must be a JSON object")
        if not record.get("event_id"):
            record["event_id"] = "worker-" + hashlib.sha256(line.encode("utf-8")).hexdigest()
        return record
    record = parse_line(line, input_format, source=source).to_record()
    record["event_id"] = "worker-" + hashlib.sha256(line.encode("utf-8")).hexdigest()
    return record


def _load_state(state_path: Path, input_path: Path) -> dict[str, int]:
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    if "offset" in state:
        return {"inode": int(state.get("inode", 0)), "offset": int(state["offset"])}
    # Upgrade a version-1 line checkpoint to a byte offset once.
    offset = 0
    remaining = int(state.get("line_offset", 0))
    with input_path.open("rb") as stream:
        while remaining > 0 and (line := stream.readline()):
            offset += len(line)
            remaining -= 1
    return {"inode": input_path.stat().st_ino, "offset": offset}


def _read_new_lines(input_path: Path, state: dict[str, int]) -> tuple[list[str], dict[str, int]]:
    """Complete lines written since the checkpoint, and the advanced checkpoint."""
    stat = input_path.stat()
    offset = state["offset"]
    if state["inode"] not in (0, stat.st_ino) or stat.st_size < offset:
        offset = 0  # rotated or truncated
    with input_path.open("rb") as stream:
        stream.seek(offset)
        chunk = stream.read(MAX_BYTES_PER_CYCLE)
    end = chunk.rfind(b"\n") + 1
    lines = [raw.decode("utf-8", errors="replace") for raw in chunk[:end].splitlines()]
    return lines, {"inode": stat.st_ino, "offset": offset + end}


def _parse_lines(lines: list[str], input_format: str, source: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            events.append(_parse_worker_line(line, input_format, source))
        except (LogLineError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
            logger.warning("skipped malformed %s line: %s", input_format, exc)
    return events


def _normalize_worker_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events:
        if "observed_at" not in event or "event_id" not in event:
            try:
                parsed = parse_json_record(event, default_source="worker-input").to_record()
            except ValueError as exc:
                logger.warning("skipped invalid event record: %s", exc)
                continue
            if event.get("event_id"):
                parsed["event_id"] = event["event_id"]
            normalized.append(parsed)
        else:
            normalized.append(event)
    return normalized


def _login_history(store: SqliteEventStore, events: list[dict[str, Any]], window_seconds: int) -> list[dict[str, Any]]:
    """Recent stored login/privilege events that correlation windows may still need."""
    times = []
    for event in events:
        try:
            times.append(_time(event))
        except (KeyError, ValueError):
            continue
    if not times or window_seconds <= 0:
        return []
    return store.events_since(min(times) - timedelta(seconds=window_seconds), event_types=HISTORY_EVENT_TYPES)


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
    rules: RulesConfig | None = None,
    notifier: Notifier | None = None,
) -> int:
    """Process only input appended after the durable checkpoint.

    With `incident_database`, events are indexed first and correlation also
    sees recent logins from earlier cycles, so slow brute force is detected.
    """
    rules = rules or load_rules()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    lines, new_state = _read_new_lines(input_path, _load_state(state_path, input_path))
    events = _normalize_worker_events(_parse_lines(lines, input_format, source))
    history: list[dict[str, Any]] = []
    store = SqliteEventStore(incident_database) if incident_database else None
    if store and events:
        # The incident database is also the durable event index used by the
        # dashboard. INSERT OR IGNORE makes replay safe after a crash.
        history = _login_history(store, events, rules.max_window_seconds())
        store.append_records(events)
    alerts = process_event_records(events, ioc_database=ioc_database, external_api_key=external_api_key,
                                   external_cache=external_cache, external_max_hashes=external_max_hashes,
                                   history=history, rules=rules)
    if store:
        # The alerts table's unique key decides what is new: no full re-read
        # of the alert file each cycle.
        new_ids = {record["alert_id"] for record in store.append_alerts([alert.to_record() for alert in alerts])}
        fresh_alerts = [alert for alert in alerts if str(alert.alert_id) in new_ids]
    else:
        existing = _existing_alert_keys(output_path)
        fresh_alerts = [alert for alert in alerts if alert_record_key(alert.to_record()) not in existing]
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
            except NotificationError as exc:
                # Alerts remain durable in output_path; operators can retry
                # delivery from that append-only stream independently.
                logger.warning("webhook delivery failed: %s", exc)
        if notifier:
            # Failures are logged per channel; alerts stay durable in the database and file.
            notifier.notify([alert.to_record() for alert in fresh_alerts])
    if report_path and output_path.exists():
        generate_report(output_path, report_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps(new_state, sort_keys=True) + "\n", encoding="utf-8")
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
    rules_path: Path | None = None,
) -> None:
    """Run cycles forever. The rules file is re-read every cycle, so edits apply
    without a restart; an invalid edit is logged and the last good rules kept."""
    if interval_seconds < 1:
        raise ValueError("interval must be at least one second")
    rules = load_rules(rules_path)  # fail fast on a bad file at startup
    notifier = Notifier.from_env()
    if notifier.channels:
        logger.info("notifying %s for %s+ alerts", ", ".join(notifier.channels), notifier.min_severity)
    while True:
        try:
            rules = load_rules(rules_path)
        except (OSError, RulesConfigError) as exc:
            logger.error("rules reload failed; keeping previous rules: %s", exc)
        try:
            count = run_incremental(
                input_path, output_path, state_path or output_path.with_suffix(".state.json"),
                ioc_database=ioc_database, incident_database=incident_database, report_path=report_path,
                input_format=input_format, source=source,
                external_api_key=external_api_key, external_cache=external_cache,
                external_max_hashes=external_max_hashes,
                webhook_url=webhook_url, webhook_token=webhook_token,
                rules=rules, notifier=notifier,
            )
        except FileNotFoundError:
            # A newly deployed worker may start before its first collector
            # creates the input file. Keep the service alive and retry.
            count = 0
        except Exception:  # noqa: BLE001 - one failed cycle must not stop monitoring
            logger.exception("worker cycle failed; retrying next interval")
            count = 0
        if on_cycle:
            on_cycle(count)
        time.sleep(interval_seconds)
