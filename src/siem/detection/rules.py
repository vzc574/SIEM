"""Small, explainable first-generation detection rules."""

from dataclasses import dataclass
from typing import Any, Callable

from siem.domain.alerts import Alert


EventRecord = dict[str, Any]
RuleFunction = Callable[[EventRecord], Alert | None]


def _alert(event: EventRecord, *, rule_id: str, title: str, severity: str,
           reason: str, recommended_action: str) -> Alert:
    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        event_id=str(event.get("event_id", "unknown")),
        reason=reason,
        recommended_action=recommended_action,
        evidence={
            "source": event.get("source"),
            "event_type": event.get("event_type"),
            "host": event.get("host"),
            "attributes": event.get("attributes", {}),
        },
    )


def high_severity_event(event: EventRecord) -> Alert | None:
    severity = str(event.get("severity", "info")).lower()
    if severity not in {"high", "critical"}:
        return None
    return _alert(
        event,
        rule_id="event.high-severity",
        title="High-severity security event",
        severity=severity,
        reason=f"The event was recorded with {severity} severity.",
        recommended_action="Review the event and related host activity.",
    )


def suspicious_event_type(event: EventRecord) -> Alert | None:
    event_type = str(event.get("event_type", "")).lower()
    suspicious_types = {"malware.detected", "suspicious.process", "ransomware.detected", "credential.theft"}
    if event_type not in suspicious_types:
        return None
    return _alert(
        event,
        rule_id="event.suspicious-type",
        title="Suspicious activity detected",
        severity="high",
        reason=f"The event type '{event_type}' is classified as suspicious.",
        recommended_action="Preserve evidence and isolate the affected host for investigation.",
    )


def failed_login(event: EventRecord) -> Alert | None:
    if str(event.get("event_type", "")).lower() != "login.failed":
        return None
    return _alert(
        event,
        rule_id="auth.failed-login",
        title="Failed authentication attempt",
        severity="medium",
        reason="A failed login event was observed.",
        recommended_action="Check for repeated attempts and verify the account owner.",
    )


DEFAULT_RULES: tuple[RuleFunction, ...] = (high_severity_event, suspicious_event_type, failed_login)

