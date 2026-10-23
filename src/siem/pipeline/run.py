"""Run the deterministic SIEM processing stages over an event batch."""

import json
from pathlib import Path
from typing import Any

from siem.detection.config import RulesConfig, load_rules
from siem.detection.correlation import correlate
from siem.detection.engine import detect
from siem.detection.rules import build_event_rules
from siem.ingestion.json_lines import parse_json_record
from siem.intel.matcher import match_events
from siem.intel.external import enrich_events
from siem.intel.store import IOCStore
from siem.reporting.report import load_jsonl
from siem.domain.alerts import Alert, alert_record_key
from siem.storage.sqlite import SqliteEventStore


def process_event_records(events: list[dict[str, Any]], *, ioc_database: Path | None = None,
                          external_api_key: str | None = None, external_cache: Path | None = None,
                          external_max_hashes: int = 10, history: list[dict[str, Any]] | None = None,
                          rules: RulesConfig | None = None):
    """Run every detection stage over `events`.

    `history` holds earlier, already-processed events (e.g. the last few
    minutes of logins from the database). Correlation sees history plus the
    new events, so an attack spanning several batches is still detected, but
    only alerts triggered by a new event are returned. `rules` defaults to
    the built-in rules merged with $SIEM_RULES.
    """
    rules = rules or load_rules()
    normalized: list[dict[str, Any]] = []
    for event in events:
        if "observed_at" not in event or "event_id" not in event:
            parsed = parse_json_record(event, default_source="jsonl-import").to_record()
            if event.get("event_id"):
                parsed["event_id"] = event["event_id"]
            normalized.append(parsed)
        else:
            normalized.append(event)
    if history:
        new_ids = {str(event["event_id"]) for event in normalized}
        context = [event for event in history if str(event["event_id"]) not in new_ids] + normalized
        correlated = [alert for alert in correlate(context, rules) if alert.event_id in new_ids]
    else:
        correlated = correlate(normalized, rules)
    alerts = detect(normalized, build_event_rules(rules)) + correlated
    if ioc_database:
        alerts.extend(match_events(normalized, IOCStore(ioc_database)))
    if external_api_key:
        if external_cache is None:
            raise ValueError("external_cache is required when external_api_key is configured")
        alerts.extend(enrich_events(normalized, api_key=external_api_key, cache_path=external_cache,
                                    max_hashes=external_max_hashes))
    return deduplicate_alerts(alerts)


def alert_key(alert: Alert) -> str:
    return alert_record_key({"rule_id": alert.rule_id, "event_id": alert.event_id, "evidence": alert.evidence})


def deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    unique: list[Alert] = []
    seen: set[str] = set()
    for alert in alerts:
        key = alert_key(alert)
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique


def _incident_subject(alert: Alert) -> str:
    attributes = alert.evidence.get("attributes") or {}
    return str(alert.evidence.get("host") or alert.evidence.get("identity") or attributes.get("src_ip")
               or alert.evidence.get("source") or alert.event_id)


def create_incidents_for_alerts(alerts: list[Alert], database: Path, *, actor: str = "pipeline") -> int:
    """Group high/critical alerts by subject into incidents.

    An open incident for the same subject is extended instead of creating a
    new one each cycle. Returns the number of incidents created or extended.
    """
    store = SqliteEventStore(database)
    grouped: dict[str, list[Alert]] = {}
    for alert in alerts:
        if alert.severity in {"high", "critical"}:
            grouped.setdefault(_incident_subject(alert), []).append(alert)
    for subject, group in grouped.items():
        severity = "critical" if any(alert.severity == "critical" for alert in group) else "high"
        title = f"Automated investigation: {subject}"
        alert_ids = [str(alert.alert_id) for alert in group]
        existing = store.find_open_incident(title)
        if existing:
            store.attach_alerts(existing["incident_id"], alert_ids, actor=actor, severity=severity)
        else:
            store.create_incident(title, severity, alert_ids, actor=actor)
    return len(grouped)


def process_events(input_path: Path, output_path: Path, *, ioc_database: Path | None = None) -> int:
    events: list[dict[str, Any]] = load_jsonl(input_path)
    alerts = process_event_records(events, ioc_database=ioc_database)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
    return len(alerts)
