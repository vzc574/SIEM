"""Small, explainable first-generation detection rules."""

from fnmatch import fnmatchcase
import re
from typing import Any, Callable, Iterable

from siem.detection.config import MatchRule, RulesConfig
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


def suspicious_event_type_rule(suspicious_types: Iterable[str]) -> RuleFunction:
    types = frozenset(suspicious_types)

    def suspicious_event_type(event: EventRecord) -> Alert | None:
        event_type = str(event.get("event_type", "")).lower()
        if event_type not in types:
            return None
        return _alert(
            event,
            rule_id="event.suspicious-type",
            title="Suspicious activity detected",
            severity="high",
            reason=f"The event type '{event_type}' is classified as suspicious.",
            recommended_action="Preserve evidence and isolate the affected host for investigation.",
        )
    return suspicious_event_type


suspicious_event_type = suspicious_event_type_rule(
    {"malware.detected", "suspicious.process", "ransomware.detected", "credential.theft"})


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

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _render(template: str, event: EventRecord) -> str:
    """Fill {field} from the event's attributes or top-level fields; '?' when absent."""
    attributes = event.get("attributes", {})
    def value(match: re.Match[str]) -> str:
        found = attributes.get(match[1], event.get(match[1]))
        return "?" if found in (None, "") else str(found)
    return _PLACEHOLDER.sub(value, template)


def match_rule(rule: MatchRule) -> RuleFunction:
    """A configurable rule: event type glob plus optional message/attribute conditions."""
    def evaluate(event: EventRecord) -> Alert | None:
        if not fnmatchcase(str(event.get("event_type", "")).lower(), rule.event_type):
            return None
        if rule.message_regex and not rule.message_regex.search(str(event.get("message", ""))):
            return None
        attributes = event.get("attributes", {})
        if any(str(attributes.get(key, event.get(key, ""))) != expected for key, expected in rule.attributes):
            return None
        if any(not pattern.search(str(attributes.get(key, event.get(key, "")))) for key, pattern in rule.attribute_regex):
            return None
        return _alert(event, rule_id=rule.id, title=rule.title, severity=rule.severity,
                      reason=_render(rule.reason, event), recommended_action=rule.recommended_action)
    return evaluate


def build_event_rules(config: RulesConfig) -> list[RuleFunction]:
    rules: list[RuleFunction] = []
    if config.high_severity:
        rules.append(high_severity_event)
    if config.suspicious_types is not None:
        rules.append(suspicious_event_type_rule(config.suspicious_types))
    if config.failed_login:
        rules.append(failed_login)
    rules.extend(match_rule(rule) for rule in config.match)
    return rules

