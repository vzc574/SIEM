"""Ingestion of newline-delimited JSON logs.

This collector only parses data. It never executes commands, opens payloads, or
performs response actions.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterator

from siem.domain.events import SecurityEvent


class JsonLogParseError(ValueError):
    """Raised when one JSON log record cannot be normalized."""


def _observed_at(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, str):
        raise JsonLogParseError("timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise JsonLogParseError("timestamp is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise JsonLogParseError("timestamp must include a timezone")
    return parsed


def parse_json_record(record: dict[str, Any], *, default_source: str) -> SecurityEvent:
    """Normalize one JSON object from a collector."""
    if not isinstance(record, dict):
        raise JsonLogParseError("record must be a JSON object")

    source = record.get("source", default_source)
    event_type = record.get("event_type", record.get("type"))
    message = record.get("message")
    if not isinstance(source, str) or not isinstance(event_type, str) or not isinstance(message, str):
        raise JsonLogParseError("source, event_type/type, and message are required strings")

    known_fields = {"source", "event_type", "type", "message", "observed_at", "timestamp", "severity", "host"}
    attributes = {key: value for key, value in record.items() if key not in known_fields}
    timestamp = record.get("observed_at", record.get("timestamp"))
    return SecurityEvent(
        source=source,
        event_type=event_type,
        message=message,
        observed_at=_observed_at(timestamp),
        severity=str(record.get("severity", "info")).lower(),
        host=record.get("host"),
        attributes=attributes,
    )


def collect_json_lines(path: Path, *, default_source: str) -> Iterator[SecurityEvent]:
    """Yield normalized events from a UTF-8 newline-delimited JSON file."""
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                yield parse_json_record(record, default_source=default_source)
            except (json.JSONDecodeError, JsonLogParseError) as exc:
                raise JsonLogParseError(f"{path}:{line_number}: {exc}") from exc

