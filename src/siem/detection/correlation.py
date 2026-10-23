"""Cross-event correlation rules."""

from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from siem.detection.config import RulesConfig, load_rules
from siem.domain.alerts import Alert


LOGIN_EVENT_TYPES = ("login.failed", "login.success")
# Event types correlation rules consume; the worker reloads recent ones from storage.
HISTORY_EVENT_TYPES = (*LOGIN_EVENT_TYPES, "privilege.failed")
# Default longest window; with a rules config use config.max_window_seconds().
MAX_WINDOW_SECONDS = 300


def _time(event: dict[str, Any]) -> datetime:
    value = str(event["observed_at"]).replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def _identity(event: dict[str, Any]) -> str:
    attributes = event.get("attributes", {})
    return str(attributes.get("username") or attributes.get("src_ip") or event.get("host") or event.get("source") or "unknown")


def _source_ip(event: dict[str, Any]) -> str | None:
    value = event.get("attributes", {}).get("src_ip")
    return str(value) if value else None


def _burst(
    events: list[dict[str, Any]],
    *,
    key: Callable[[dict[str, Any]], str | None],
    threshold: int,
    window_seconds: int,
    make_alert: Callable[[str, list[dict[str, Any]]], Alert],
    event_type: str = "login.failed",
) -> list[Alert]:
    """Sliding-window counter over `event_type` events grouped by `key`.

    After an alert, the group is suppressed for one window so a long attack
    produces one alert per window instead of one per additional failure.
    """
    window = timedelta(seconds=window_seconds)
    history: dict[str, list[dict[str, Any]]] = {}
    suppressed_until: dict[str, datetime] = {}
    alerts: list[Alert] = []
    for event in events:
        if str(event.get("event_type", "")).lower() != event_type:
            continue
        group = key(event)
        if group is None:
            continue
        now = _time(event)
        recent = [item for item in history.get(group, []) if now - _time(item) <= window]
        recent.append(event)
        history[group] = recent
        if len(recent) >= threshold and now >= suppressed_until.get(group, now):
            suppressed_until[group] = now + window
            alerts.append(make_alert(group, recent))
    return alerts


def correlate_failed_logins(
    events: Iterable[dict[str, Any]], *, threshold: int = 5, window_seconds: int = 300
) -> list[Alert]:
    """Alert on repeated failed logins for the same account (brute force)."""
    def make_alert(identity: str, recent: list[dict[str, Any]]) -> Alert:
        return Alert(
            rule_id="correlation.failed-login-burst",
            title="Repeated failed login attempts",
            severity="high",
            event_id=str(recent[-1].get("event_id", "unknown")),
            reason=f"{len(recent)} failed logins for {identity} within {window_seconds} seconds.",
            recommended_action="Verify the account, investigate the source host, and consider temporary containment.",
            evidence={"identity": identity, "event_ids": [str(item.get("event_id")) for item in recent],
                      "src_ips": sorted({ip for item in recent if (ip := _source_ip(item))})},
        )
    return _burst(sorted(events, key=_time), key=_identity, threshold=threshold,
                  window_seconds=window_seconds, make_alert=make_alert)


def correlate_source_spray(
    events: Iterable[dict[str, Any]], *, threshold: int = 10, window_seconds: int = 300
) -> list[Alert]:
    """Alert when one source IP fails logins at volume, across any accounts (spraying)."""
    def make_alert(src_ip: str, recent: list[dict[str, Any]]) -> Alert:
        users = sorted({str(item.get("attributes", {}).get("username")) for item in recent if item.get("attributes", {}).get("username")})
        return Alert(
            rule_id="correlation.source-login-spray",
            title="Failed logins from one source across accounts",
            severity="high",
            event_id=str(recent[-1].get("event_id", "unknown")),
            reason=f"{len(recent)} failed logins from {src_ip} against {len(users)} account(s) within {window_seconds} seconds.",
            recommended_action="Consider blocking the source address and check whether any targeted account logged in successfully.",
            evidence={"identity": src_ip, "src_ip": src_ip, "usernames": users[:50],
                      "event_ids": [str(item.get("event_id")) for item in recent]},
        )
    return _burst(sorted(events, key=_time), key=_source_ip, threshold=threshold,
                  window_seconds=window_seconds, make_alert=make_alert)


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
        recent = [item for item in failures.pop(identity, []) if _time(event) - _time(item) <= window]
        if len(recent) >= minimum_failures:
            alerts.append(Alert(
                rule_id="correlation.failed-then-success",
                title="Successful login after repeated failures",
                severity="critical",
                event_id=str(event.get("event_id", "unknown")),
                reason=f"A successful login for {identity} followed {len(recent)} failed attempts.",
                recommended_action="Validate the login with the account owner and review subsequent activity.",
                evidence={"identity": identity, "failed_event_ids": [str(item.get("event_id")) for item in recent],
                          "src_ip": _source_ip(event)},
            ))
    return alerts


def correlate_privilege_failures(
    events: Iterable[dict[str, Any]], *, threshold: int = 3, window_seconds: int = 300
) -> list[Alert]:
    """Alert on repeated failed sudo/su authentication by one user."""
    def make_alert(username: str, recent: list[dict[str, Any]]) -> Alert:
        return Alert(
            rule_id="correlation.privilege-failures",
            title="Repeated privilege escalation failures",
            severity="high",
            event_id=str(recent[-1].get("event_id", "unknown")),
            reason=f"{len(recent)} failed sudo/su authentications by {username} within {window_seconds} seconds.",
            recommended_action="Confirm with the user; repeated failures can mean password guessing on a compromised account.",
            evidence={"identity": username, "hosts": sorted({str(item.get("host")) for item in recent if item.get("host")}),
                      "event_ids": [str(item.get("event_id")) for item in recent]},
        )
    return _burst(sorted(events, key=_time), key=_identity, threshold=threshold, window_seconds=window_seconds,
                  make_alert=make_alert, event_type="privilege.failed")


def correlate(events: Iterable[dict[str, Any]], config: RulesConfig | None = None) -> list[Alert]:
    config = config or load_rules()
    materialized = list(events)
    alerts: list[Alert] = []
    if (rule := config.failed_login_burst).enabled:
        alerts += correlate_failed_logins(materialized, threshold=rule.threshold, window_seconds=rule.window_seconds)
    if (rule := config.source_spray).enabled:
        alerts += correlate_source_spray(materialized, threshold=rule.threshold, window_seconds=rule.window_seconds)
    if (rule := config.failed_then_success).enabled:
        alerts += correlate_failure_then_success(materialized, minimum_failures=rule.threshold, window_seconds=rule.window_seconds)
    if (rule := config.privilege_failures).enabled:
        alerts += correlate_privilege_failures(materialized, threshold=rule.threshold, window_seconds=rule.window_seconds)
    return alerts
