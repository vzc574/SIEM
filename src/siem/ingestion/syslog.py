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
_SUDO = re.compile(
    r"^(?P<username>\S+) : (?:(?P<denied>user NOT in sudoers) ; )?(?P<gave_up>\d+ incorrect password attempts? ; )?"
    r"TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<target_user>\S+) ;(?: [A-Z]+=[^;]*;)* COMMAND=(?P<command>.*)$"
)
_PAM_FAILURE = re.compile(r"^pam_unix\((?P<service>sudo|su|su-l):auth\): authentication failure;(?P<fields>.*)$")
_PAM_FIELD = re.compile(r"(\w+)=(\S*)")
_SU_SUCCESS = re.compile(r"^\(to (?P<target_user>\S+)\) (?P<username>\S+) on (?P<tty>\S+)$")
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


def _classify_privilege(tag: str, message: str) -> tuple[str, dict[str, object]] | None:
    """Map sudo/su results onto privilege.sudo / privilege.su / privilege.failed / privilege.denied.

    Each pam_unix auth failure is one wrong password; sudo's later
    "N incorrect password attempts" summary is left unclassified so attempts
    are not counted twice.
    """
    pam = _PAM_FAILURE.match(message)
    if pam and tag in {"sudo", "su"}:
        fields = dict(_PAM_FIELD.findall(pam["fields"]))
        username = fields.get("ruser") or fields.get("logname") or fields.get("user")
        result: dict[str, object] = {"service": pam["service"]}
        if pam["service"] != "sudo":
            # For su, pam's user= is the target account; for sudo it is the caller.
            result["target_user"] = fields.get("user") or "root"
        if username:
            result["username"] = username
        if fields.get("rhost"):
            result["src_ip"] = fields["rhost"]
        return "privilege.failed", result
    if tag == "sudo" and (match := _SUDO.match(message)) and not match["gave_up"]:
        fields = {key: value for key, value in match.groupdict().items() if value and key not in {"denied", "gave_up"}}
        return ("privilege.denied" if match["denied"] else "privilege.sudo"), fields
    if tag == "su" and (match := _SU_SUCCESS.match(message)):
        return "privilege.su", match.groupdict()
    return None


def _classify_auth(tag: str, message: str) -> tuple[str, dict[str, object]] | None:
    """Map sshd, sudo and su results onto the shared login/privilege event types."""
    if tag in {"sudo", "su"}:
        return _classify_privilege(tag, message)
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
        floor = {"login.failed": "medium", "privilege.failed": "medium", "privilege.denied": "high"}.get(event_type)
        if floor and _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(floor):
            severity = floor
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

