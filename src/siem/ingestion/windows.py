"""Parser for exported Windows Event Log JSON records."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterator

from siem.domain.events import SecurityEvent


class WindowsEventError(ValueError):
    """Raised when an exported Windows event cannot be normalized."""


def parse_windows_event(record: dict[str, Any], *, source: str = "windows-eventlog") -> SecurityEvent:
    try:
        system = record["Event"]["System"]
        event_id = str(system["EventID"])
        timestamp = datetime.fromisoformat(system["TimeCreated"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        computer = str(system.get("Computer", "unknown"))
        provider = str(system.get("Provider", {}).get("Name", "unknown"))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise WindowsEventError("invalid Windows Event Log JSON structure") from exc

    data: dict[str, Any] = {}
    raw_data = record.get("Event", {}).get("EventData", {}).get("Data", [])
    if isinstance(raw_data, dict):
        raw_data = [raw_data]
    for item in raw_data:
        if isinstance(item, dict) and "Name" in item:
            data[str(item["Name"])] = item.get("#text", item.get("Value"))
    message = str(record.get("Message") or f"Windows event {event_id} from {provider}")
    severity = "medium" if event_id in {"4625", "4688", "4104"} else "info"
    return SecurityEvent(
        source=source,
        event_type=f"windows.event.{event_id}",
        message=message,
        observed_at=timestamp,
        severity=severity,
        host=computer,
        attributes={"event_id": event_id, "provider": provider, **data},
    )


def collect_windows_json(path: Path, *, source: str = "windows-eventlog") -> Iterator[SecurityEvent]:
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                yield parse_windows_event(json.loads(line), source=source)
            except (json.JSONDecodeError, WindowsEventError) as exc:
                raise WindowsEventError(f"{path}:{line_number}: {exc}") from exc

