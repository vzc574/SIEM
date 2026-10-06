"""Read-only parser for common Linux RFC 3164 syslog lines."""

from datetime import datetime
import re
from pathlib import Path
from typing import Iterator

from siem.domain.events import SecurityEvent


_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_SEVERITIES = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "info", 7: "debug"}
_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp", 16: "local0", 17: "local1", 18: "local2",
    19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


class SyslogParseError(ValueError):
    """Raised when a syslog line cannot be normalized."""


def parse_syslog_line(line: str, *, source: str = "syslog") -> SecurityEvent:
    match = _SYSLOG.match(line.strip())
    if not match:
        raise SyslogParseError("line does not match a supported RFC 3164 format")
    values = match.groupdict()
    priority = int(values["pri"]) if values["pri"] else 13
    severity_code = priority & 7
    facility_code = priority >> 3
    current_year = datetime.now().year
    observed_at = datetime.strptime(f"{current_year} {values['timestamp']}", "%Y %b %d %H:%M:%S").astimezone()
    attributes = {
        "facility": _FACILITIES.get(facility_code, f"facility-{facility_code}"),
        "priority": priority,
    }
    if values["pid"]:
        attributes["pid"] = int(values["pid"])
    return SecurityEvent(
        source=source,
        event_type=f"syslog.{values['tag']}",
        message=values["message"] or values["tag"],
        observed_at=observed_at,
        severity=_SEVERITIES.get(severity_code, "info"),
        host=values["host"],
        attributes=attributes,
    )


def collect_syslog(path: Path, *, source: str = "syslog") -> Iterator[SecurityEvent]:
    """Yield events from a syslog file without changing it."""
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                yield parse_syslog_line(line, source=source)
            except SyslogParseError as exc:
                raise SyslogParseError(f"{path}:{line_number}: {exc}") from exc

