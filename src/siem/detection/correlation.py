"""Cross-event correlation rules."""

from datetime import datetime, timedelta
from typing import Any, Iterable

from siem.domain.alerts import Alert


def _time(event: dict[str, Any]) -> datetime:
    value = str(event["observed_at"]).replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def _identity(event: dict[str, Any]) -> str:
    attributes = event.get("attributes", {})
    return str(attributes.get("username") or event.get("host") or event.get("source") or "unknown")


def correlate_failed_logins(
    events: Iterable[dict[str, Any]], *, threshold: int = 5, window_seconds: int = 300
) -> list[Alert]:
    """Alert on repeated failed logins for the same account/host identity."""
    ordered = sorted(events, key=_time)
    failures: dict[str, list[dict[str, Any]]] = {}
    alerts: list[Alert] = []
    already_alerted: set[tuple[str, str]] = set()
    window = timedelta(seconds=window_seconds)

    for event in ordered:
        if str(event.get("event_type", "")).lower() != "login.failed":
            continue
        identity = _identity(event)
        history = [item for item in failures.setdefault(identity, []) if _time(event) - _time(item) <= window]
        history.append(event)
        failures[identity] = history
        if len(history) >= threshold:
            key = (identity, str(history[0].get("event_id", "")))
            if key in already_alerted:
                continue
            already_alerted.add(key)
            alerts.append(Alert(
                rule_id="correlation.failed-login-burst",
                title="Repeated failed login attempts",
                severity="high",
                event_id=str(event.get("event_id", "unknown")),
                reason=f"{len(history)} failed logins for {identity} within {window_seconds} seconds.",
                recommended_action="Verify the account, investigate the source host, and consider temporary containment.",
                evidence={"identity": identity, "event_ids": [str(item.get("event_id")) for item in history]},
            ))
    return alerts


def correlate_failure_then_success(
    events: Iterable[dict[str, Any]], *, minimum_failures: int = 3, window_seconds: int = 300
) -> list[Alert]:
    """Alert when a successful login follows repeated failures for an identity."""
    ordered = sorted(events, key=_time)
    failures: dict[str, list[dict[str, Any]]] = {}
    alerts: list[Alert] = []
    window = timedelta(seconds=window_seconds)
    for event in ordered:
        identity = _identity(event)
        event_type = str(event.get("event_type", "")).lower()
        if event_type == "login.failed":
            failures.setdefault(identity, []).append(event)
            continue
        if event_type != "login.success":
            continue
        recent = [item for item in failures.get(identity, []) if _time(event) - _time(item) <= window]
        if len(recent) >= minimum_failures:
            alerts.append(Alert(
                rule_id="correlation.failed-then-success",
                title="Successful login after repeated failures",
                severity="high",
                event_id=str(event.get("event_id", "unknown")),
                reason=f"A successful login for {identity} followed {len(recent)} failed attempts.",
                recommended_action="Validate the login with the account owner and review subsequent activity.",
                evidence={"identity": identity, "failed_event_ids": [str(item.get("event_id")) for item in recent]},
            ))
    return alerts


def correlate(events: Iterable[dict[str, Any]]) -> list[Alert]:
    materialized = list(events)
    return correlate_failed_logins(materialized) + correlate_failure_then_success(materialized)

