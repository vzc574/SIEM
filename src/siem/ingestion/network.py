"""Parsers for common firewall and web access logs."""

from datetime import datetime, timezone
import re
from pathlib import Path
from typing import Iterator

from siem.domain.events import SecurityEvent


class NetworkLogError(ValueError):
    """Raised when a network log line cannot be normalized."""


_UFW = re.compile(r".*\[UFW (?P<action>BLOCK|ALLOW)\].*SRC=(?P<src>\S+) DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+)(?:.*SPT=(?P<sport>\d+))?(?:.*DPT=(?P<dport>\d+))?.*")
_ACCESS = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: HTTP/[^\"]+)?" (?P<status>\d{3}) (?P<size>\S+)')


def parse_ufw_line(line: str, *, source: str = "ufw") -> SecurityEvent:
    match = _UFW.match(line.strip())
    if not match:
        raise NetworkLogError("line does not match UFW format")
    values = match.groupdict()
    action = values["action"].lower()
    return SecurityEvent.now(
        source=source,
        event_type=f"firewall.{action}",
        message=f"Firewall {action} {values['proto']} traffic from {values['src']} to {values['dst']}",
        severity="medium" if action == "block" else "info",
        attributes={
            "src_ip": values["src"], "dst_ip": values["dst"], "protocol": values["proto"],
            "src_port": int(values["sport"]) if values["sport"] else None,
            "dst_port": int(values["dport"]) if values["dport"] else None,
        },
    )


def parse_access_line(line: str, *, source: str = "web-access") -> SecurityEvent:
    match = _ACCESS.match(line.strip())
    if not match:
        raise NetworkLogError("line does not match web access-log format")
    values = match.groupdict()
    try:
        timestamp = datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise NetworkLogError("invalid access-log timestamp") from exc
    status = int(values["status"])
    severity = "medium" if status >= 400 else "info"
    return SecurityEvent(
        source=source,
        event_type="web.request",
        message=f"{values['method']} {values['path']} returned {status}",
        observed_at=timestamp.astimezone(timezone.utc),
        severity=severity,
        host=None,
        attributes={"src_ip": values["ip"], "method": values["method"], "path": values["path"], "status": status, "size": values["size"]},
    )


def collect_network(path: Path, *, format_name: str, source: str) -> Iterator[SecurityEvent]:
    parser = parse_ufw_line if format_name == "ufw" else parse_access_line if format_name == "access" else None
    if parser is None:
        raise NetworkLogError("format must be 'ufw' or 'access'")
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                yield parser(line, source=source)
            except NetworkLogError as exc:
                raise NetworkLogError(f"{path}:{line_number}: {exc}") from exc

