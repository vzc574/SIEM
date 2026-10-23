"""Read-only parser for common Linux RFC 3164 syslog lines."""

from datetime import datetime, timedelta, timezone
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


_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<username>\S+)(?: from (?P<src_ip>\S+))?(?: port (?P<src_port>\d+))?"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<username>\S+)(?: from (?P<src_ip>\S+))?(?: port (?P<src_port>\d+))?"
)
_SEVERITY_ORDER = ("debug", "info", "low", "medium", "high", "critical")


class SyslogParseError(ValueError):
    """Raised when a syslog line cannot be normalized."""


def _observed_at(timestamp: str, now: datetime) -> datetime:
    """Resolve a year-less RFC 3164 timestamp to an aware UTC datetime.

    Syslog omits the year, so a December line read in January would land in
    the future; such timestamps are moved back one year.
    """
    local_now = now.astimezone()
    parsed = datetime.strptime(f"{local_now.year} {timestamp}", "%Y %b %d %H:%M:%S").astimezone()
    if parsed - local_now > timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed.astimezone(timezone.utc)


def _classify_auth(tag: str, message: str) -> tuple[str, dict[str, object]] | None:
    """Map sshd authentication results onto the shared login event types."""
    if tag != "sshd":
        return None
    for pattern, event_type in ((_SSH_FAILED, "login.failed"), (_SSH_ACCEPTED, "login.success")):
        match = pattern.match(message)
        if match:
            fields = {key: value for key, value in match.groupdict().items() if value}
            if "src_port" in fields:
                fields["src_port"] = int(fields["src_port"])
            return event_type, fields
    return None


def parse_syslog_line(line: str, *, source: str = "syslog", now: datetime | None = None) -> SecurityEvent:
    match = _SYSLOG.match(line.strip())
    if not match:
        raise SyslogParseError("line does not match a supported RFC 3164 format")
    values = match.groupdict()
    priority = int(values["pri"]) if values["pri"] else 13
    severity_code = priority & 7
    facility_code = priority >> 3
    severity = _SEVERITIES.get(severity_code, "info")
    message = values["message"] or values["tag"]
    attributes: dict[str, object] = {
        "facility": _FACILITIES.get(facility_code, f"facility-{facility_code}"),
        "priority": priority,
        "program": values["tag"],
    }
    if values["pid"]:
        attributes["pid"] = int(values["pid"])
    event_type = f"syslog.{values['tag']}"
    auth = _classify_auth(values["tag"], message)
    if auth:
        event_type, fields = auth
        attributes.update(fields)
        if event_type == "login.failed" and _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index("medium"):
            severity = "medium"
    return SecurityEvent(
        source=source,
        event_type=event_type,
        message=message,
        observed_at=_observed_at(values["timestamp"], now or datetime.now(timezone.utc)),
        severity=severity,
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

