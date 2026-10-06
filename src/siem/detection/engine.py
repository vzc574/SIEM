"""Rule evaluation service."""

import json
from pathlib import Path
from typing import Iterable

from siem.domain.alerts import Alert
from siem.detection.rules import DEFAULT_RULES, EventRecord, RuleFunction


def detect(events: Iterable[EventRecord], rules: Iterable[RuleFunction] = DEFAULT_RULES) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        for rule in rules:
            alert = rule(event)
            if alert is not None:
                alerts.append(alert)
    return alerts


def detect_file(event_path: Path, alert_path: Path) -> list[Alert]:
    with event_path.open("r", encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    alerts = detect(events)
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    with alert_path.open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert.to_record(), sort_keys=True) + "\n")
    return alerts

