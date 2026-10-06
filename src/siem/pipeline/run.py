"""Run the deterministic SIEM processing stages over an event batch."""

import json
from pathlib import Path
from typing import Any

from siem.detection.correlation import correlate
from siem.detection.engine import detect
from siem.ingestion.json_lines import parse_json_record
from siem.intel.matcher import match_events
from siem.intel.external import enrich_events
from siem.intel.store import IOCStore
from siem.reporting.report import load_jsonl
from siem.domain.alerts import Alert
from siem.storage.sqlite import SqliteEventStore


def process_event_records(events: list[dict[str, Any]], *, ioc_database: Path | None = None,
                          external_api_key: str | None = None, external_cache: Path | None = None,
                          external_max_hashes: int = 10):
    normalized: list[dict[str, Any]] = []
    for event in events:
        if "observed_at" not in event or "event_id" not in event:
            parsed = parse_json_record(event, default_source="jsonl-import").to_record()
            if event.get("event_id"):
                parsed["event_id"] = event["event_id"]
            normalized.append(parsed)
        else:
            normalized.append(event)
    alerts = detect(normalized) + correlate(normalized)
    if ioc_database:
        alerts.extend(match_events(normalized, IOCStore(ioc_database)))
    if external_api_key:
        if external_cache is None:
            raise ValueError("external_cache is required when external_api_key is configured")
        alerts.extend(enrich_events(normalized, api_key=external_api_key, cache_path=external_cache,
                                    max_hashes=external_max_hashes))
    return deduplicate_alerts(alerts)


def deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    unique: list[Alert] = []
    seen: set[str] = set()
    for alert in alerts:
        identity = alert.evidence.get("identity") or alert.evidence.get("value") or alert.evidence.get("source") or alert.event_id
        key = f"{alert.rule_id}|{alert.title}|{identity}|{alert.reason}"
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique


def create_incidents_for_alerts(alerts: list[Alert], database: Path, *, actor: str = "pipeline") -> int:
    store = SqliteEventStore(database)
    grouped: dict[str, list[Alert]] = {}
    for alert in alerts:
        if alert.severity in {"high", "critical"}:
            key = str(alert.evidence.get("host") or alert.evidence.get("identity") or alert.event_id)
            grouped.setdefault(key, []).append(alert)
    for key, group in grouped.items():
        severity = "critical" if any(alert.severity == "critical" for alert in group) else "high"
        store.create_incident(f"Automated investigation: {key}", severity, [str(alert.alert_id) for alert in group], actor=actor)
    return len(grouped)


def process_events(input_path: Path, output_path: Path, *, ioc_database: Path | None = None) -> int:
    events: list[dict[str, Any]] = load_jsonl(input_path)
    alerts = process_event_records(events, ioc_database=ioc_database)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
    return len(alerts)
