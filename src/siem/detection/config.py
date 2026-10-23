"""Detection rules configuration (TOML).

The built-in defaults below are always loaded; a rules file only needs the
settings it changes. Unknown keys are rejected so a typo cannot silently
disable a rule. See rules.example.toml for every option.
"""

from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
import tomllib
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")

DEFAULTS: dict[str, Any] = {
    "rules": {
        "high_severity": {"enabled": True},
        "failed_login": {"enabled": True},
        "suspicious_type": {"enabled": True, "event_types": [
            "malware.detected", "suspicious.process", "ransomware.detected", "credential.theft"]},
    },
    "correlation": {
        "failed_login_burst": {"enabled": True, "threshold": 5, "window_seconds": 300},
        "source_spray": {"enabled": True, "threshold": 10, "window_seconds": 300},
        "failed_then_success": {"enabled": True, "threshold": 3, "window_seconds": 300},
        "privilege_failures": {"enabled": True, "threshold": 3, "window_seconds": 300},
    },
    "match": [
        {"id": "privilege.not-in-sudoers", "title": "sudo attempted by a user not in sudoers", "severity": "high",
         "event_type": "privilege.denied",
         "reason": "{username} tried to run '{command}' as {target_user} without sudo rights.",
         "recommended_action": "Confirm whether this was the account owner; a compromised account often probes sudo."},
        {"id": "privilege.root-shell", "title": "Interactive root shell via sudo", "severity": "medium",
         "event_type": "privilege.sudo", "attribute_regex": {"command": r"(^|/)(ba|z|da|k)?sh( |$)|(^|/)su( |$)"},
         "reason": "{username} opened a shell as {target_user} with: {command}",
         "recommended_action": "Verify the change was planned; prefer specific sudo commands over shells."},
        {"id": "windows.account-created", "title": "Windows user account created", "severity": "medium",
         "event_type": "windows.event.4720", "reason": "A new account was created on {host}.",
         "recommended_action": "Confirm the account was requested through the normal process."},
        {"id": "windows.admin-group-add", "title": "Member added to a privileged Windows group", "severity": "high",
         "event_type": "windows.event.4732", "reason": "A member was added to a security-enabled local group on {host}.",
         "recommended_action": "Verify the group change and who made it (SubjectUserName)."},
        {"id": "windows.audit-log-cleared", "title": "Windows security log cleared", "severity": "critical",
         "event_type": "windows.event.1102", "reason": "The security audit log was cleared on {host}.",
         "recommended_action": "Treat as possible anti-forensics: preserve remaining evidence and investigate the host."},
    ],
    "disabled_match": [],
}

_WINDOW_KEYS = {"enabled", "threshold", "window_seconds"}
_MATCH_KEYS = {"id", "title", "severity", "event_type", "message_regex", "attributes", "attribute_regex",
               "reason", "recommended_action"}


class RulesConfigError(ValueError):
    """Raised when a rules file is invalid."""


@dataclass(frozen=True, slots=True)
class WindowRule:
    enabled: bool
    threshold: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class MatchRule:
    id: str
    title: str
    severity: str
    event_type: str
    reason: str
    recommended_action: str
    message_regex: re.Pattern[str] | None = None
    attributes: tuple[tuple[str, str], ...] = ()
    attribute_regex: tuple[tuple[str, re.Pattern[str]], ...] = ()


@dataclass(frozen=True, slots=True)
class RulesConfig:
    high_severity: bool
    failed_login: bool
    suspicious_types: frozenset[str] | None
    failed_login_burst: WindowRule
    source_spray: WindowRule
    failed_then_success: WindowRule
    privilege_failures: WindowRule
    match: tuple[MatchRule, ...]

    def max_window_seconds(self) -> int:
        windows = [rule.window_seconds for rule in (self.failed_login_burst, self.source_spray,
                                                    self.failed_then_success, self.privilege_failures) if rule.enabled]
        return max(windows, default=0)


def _window(name: str, value: dict[str, Any]) -> WindowRule:
    unknown = set(value) - _WINDOW_KEYS
    if unknown:
        raise RulesConfigError(f"correlation.{name}: unknown setting(s) {sorted(unknown)}")
    threshold, window = value.get("threshold"), value.get("window_seconds")
    if not isinstance(threshold, int) or threshold < 1 or not isinstance(window, int) or window < 1:
        raise RulesConfigError(f"correlation.{name}: threshold and window_seconds must be positive integers")
    return WindowRule(bool(value.get("enabled", True)), threshold, window)


def _regex(where: str, pattern: Any) -> re.Pattern[str]:
    try:
        return re.compile(str(pattern))
    except re.error as exc:
        raise RulesConfigError(f"{where}: invalid regular expression: {exc}") from exc


def _match_rule(value: dict[str, Any]) -> MatchRule:
    rule_id = value.get("id")
    where = f"match rule {rule_id!r}"
    unknown = set(value) - _MATCH_KEYS
    if unknown:
        raise RulesConfigError(f"{where}: unknown setting(s) {sorted(unknown)}")
    for key in ("id", "title", "event_type"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise RulesConfigError(f"{where}: '{key}' is required")
    if value.get("severity", "medium") not in SEVERITIES:
        raise RulesConfigError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    return MatchRule(
        id=rule_id, title=value["title"], severity=value.get("severity", "medium"),
        event_type=value["event_type"].lower(),
        reason=value.get("reason", "The event matched rule {rule_id}.").replace("{rule_id}", rule_id),
        recommended_action=value.get("recommended_action", "Review the event."),
        message_regex=_regex(where, value["message_regex"]) if "message_regex" in value else None,
        attributes=tuple((str(k), str(v)) for k, v in value.get("attributes", {}).items()),
        attribute_regex=tuple((str(k), _regex(where, v)) for k, v in value.get("attribute_regex", {}).items()),
    )


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    unknown = set(override) - {"rules", "correlation", "match", "disabled_match"}
    if unknown:
        raise RulesConfigError(f"unknown section(s) {sorted(unknown)}")
    merged = deepcopy(base)
    for section in ("rules", "correlation"):
        for name, settings in override.get(section, {}).items():
            if name not in merged[section]:
                raise RulesConfigError(f"{section}.{name}: unknown rule (known: {', '.join(sorted(merged[section]))})")
            merged[section][name].update(settings)
    merged["match"] = merged["match"] + list(override.get("match", []))
    merged["disabled_match"] = list(override.get("disabled_match", []))
    return merged


def parse_rules(data: dict[str, Any]) -> RulesConfig:
    merged = _merge(DEFAULTS, data)
    rules = merged["rules"]
    disabled = set(merged["disabled_match"])
    match_rules = [_match_rule(item) for item in merged["match"] if item.get("id") not in disabled]
    ids = [rule.id for rule in match_rules]
    if len(ids) != len(set(ids)):
        raise RulesConfigError("match rule ids must be unique")
    suspicious = rules["suspicious_type"]
    return RulesConfig(
        high_severity=bool(rules["high_severity"].get("enabled", True)),
        failed_login=bool(rules["failed_login"].get("enabled", True)),
        suspicious_types=frozenset(str(t).lower() for t in suspicious.get("event_types", [])) if suspicious.get("enabled", True) else None,
        failed_login_burst=_window("failed_login_burst", merged["correlation"]["failed_login_burst"]),
        source_spray=_window("source_spray", merged["correlation"]["source_spray"]),
        failed_then_success=_window("failed_then_success", merged["correlation"]["failed_then_success"]),
        privilege_failures=_window("privilege_failures", merged["correlation"]["privilege_failures"]),
        match=tuple(match_rules),
    )


def load_rules(path: Path | None = None) -> RulesConfig:
    """Defaults merged with `path` (or $SIEM_RULES when no path is given)."""
    path = path or (Path(os.environ["SIEM_RULES"]) if os.getenv("SIEM_RULES") else None)
    if path is None:
        return parse_rules({})
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except tomllib.TOMLDecodeError as exc:
        raise RulesConfigError(f"{path}: {exc}") from exc
    try:
        return parse_rules(data)
    except RulesConfigError as exc:
        raise RulesConfigError(f"{path}: {exc}") from exc
