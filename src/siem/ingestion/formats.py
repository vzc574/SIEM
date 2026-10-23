"""Single entry point for parsing one raw log line in any supported format."""

import json
from typing import Callable

from siem.domain.events import SecurityEvent
from siem.ingestion.json_lines import JsonLogParseError, parse_json_record
from siem.ingestion.network import NetworkLogError, parse_access_line, parse_ufw_line
from siem.ingestion.syslog import SyslogParseError, parse_syslog_line
from siem.ingestion.windows import WindowsEventError, parse_windows_event


class LogLineError(ValueError):
    """Raised when one raw line cannot be normalized in the requested format."""


def _jsonl(line: str, source: str) -> SecurityEvent:
    return parse_json_record(json.loads(line), default_source=source)


def _windows(line: str, source: str) -> SecurityEvent:
    return parse_windows_event(json.loads(line), source=source)


PARSERS: dict[str, Callable[[str, str], SecurityEvent]] = {
    "jsonl": _jsonl,
    "syslog": lambda line, source: parse_syslog_line(line, source=source),
    "windows-json": _windows,
    "ufw": lambda line, source: parse_ufw_line(line, source=source),
    "access": lambda line, source: parse_access_line(line, source=source),
}

_PARSE_ERRORS = (json.JSONDecodeError, JsonLogParseError, SyslogParseError, WindowsEventError, NetworkLogError, ValueError)


def parse_line(line: str, input_format: str, *, source: str) -> SecurityEvent:
    parser = PARSERS.get(input_format)
    if parser is None:
        raise ValueError(f"unsupported log format: {input_format}")
    try:
        return parser(line, source)
    except _PARSE_ERRORS as exc:
        raise LogLineError(str(exc)) from exc
