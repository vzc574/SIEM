"""Match normalized evidence against local indicators."""

from typing import Any

from siem.domain.alerts import Alert
from siem.intel.store import IOCStore


def _candidate_values(event: dict[str, Any]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for key, value in event.get("attributes", {}).items():
        if key in {"md5", "sha1", "sha256", "domain", "url"} and isinstance(value, str):
            values.append((key, value))
        elif key in {"ip", "src_ip", "dst_ip"} and isinstance(value, str):
            values.append(("ip", value))
    return values


def match_event(event: dict[str, Any], store: IOCStore) -> list[Alert]:
    alerts: list[Alert] = []
    for kind, value in _candidate_values(event):
        indicator = store.find(kind, value)
        if not indicator:
            continue
        confidence = int(indicator["confidence"])
        alerts.append(Alert(
            rule_id="intel.local-match",
            title=f"Threat-intelligence {kind} match",
            severity="high" if confidence >= 70 else "medium",
            event_id=str(event.get("event_id", "unknown")),
            reason=f"Event matched {kind} indicator from {indicator['source']} with {confidence}% confidence.",
            recommended_action="Validate the indicator, preserve evidence, and investigate the affected host.",
            evidence={"kind": kind, "value": value, "indicator": indicator},
        ))
    return alerts


def match_events(events: list[dict[str, Any]], store: IOCStore) -> list[Alert]:
    return [alert for event in events for alert in match_event(event, store)]

