"""Bounded, cached external threat-intelligence enrichment."""

from pathlib import Path
import json
import time
from typing import Callable, Any

from siem.domain.alerts import Alert
from siem.intel.virustotal import HashReputation, VirusTotalError, lookup_hash


class ReputationCache:
    def __init__(self, path: Path, ttl_seconds: float = 86400.0) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.records: dict[str, dict[str, Any]] = {}
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    self.records = value
            except (OSError, json.JSONDecodeError):
                self.records = {}

    def get(self, sha256: str) -> HashReputation | None:
        record = self.records.get(sha256.lower())
        if not isinstance(record, dict) or time.time() - float(record.get("checked_at", 0)) > self.ttl_seconds:
            return None
        value = record.get("reputation")
        if not isinstance(value, dict):
            return None
        return HashReputation(
            sha256=str(value["sha256"]), found=bool(value["found"]),
            malicious=int(value.get("malicious", 0)), suspicious=int(value.get("suspicious", 0)),
            total_engines=int(value.get("total_engines", 0)), tags=tuple(value.get("tags", ())),
        )

    def put(self, reputation: HashReputation) -> None:
        self.records[reputation.sha256.lower()] = {
            "checked_at": time.time(), "reputation": reputation.to_record(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.records, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.path)


def _hashes(events: list[dict[str, Any]]) -> list[tuple[str, str]]:
    found: set[str] = set()
    result: list[tuple[str, str]] = []
    for event in events:
        value = event.get("attributes", {}).get("sha256")
        if isinstance(value, str) and len(value) == 64 and value.lower() not in found:
            found.add(value.lower())
            result.append((value.lower(), str(event.get("event_id", "unknown"))))
    return result


def enrich_events(
    events: list[dict[str, Any]],
    *,
    api_key: str,
    cache_path: Path,
    max_hashes: int = 10,
    cache_ttl: float = 86400.0,
    retries: int = 2,
    backoff_seconds: float = 1.0,
    request_interval: float = 0.25,
    sleep: Callable[[float], None] = time.sleep,
    lookup: Callable[[str, str], HashReputation] = lookup_hash,
) -> list[Alert]:
    """Look up bounded unique hashes and emit alerts for suspicious results."""
    if max_hashes < 1 or retries < 0 or backoff_seconds < 0 or request_interval < 0:
        raise ValueError("invalid external lookup limits")
    cache = ReputationCache(cache_path, cache_ttl)
    alerts: list[Alert] = []
    last_request = 0.0
    for sha256, event_id in _hashes(events)[:max_hashes]:
        reputation = cache.get(sha256)
        if reputation is None:
            for attempt in range(retries + 1):
                try:
                    wait = request_interval - (time.monotonic() - last_request)
                    if wait > 0:
                        sleep(wait)
                    last_request = time.monotonic()
                    reputation = lookup(sha256, api_key)
                    cache.put(reputation)
                    break
                except (VirusTotalError, OSError):
                    if attempt == retries:
                        reputation = None
                    else:
                        sleep(backoff_seconds * (2 ** attempt))
            if reputation is None:
                continue
        if reputation.malicious or reputation.suspicious:
            severity = "critical" if reputation.malicious else "high"
            alerts.append(Alert(
                rule_id="intel.external-reputation",
                title="External threat-intelligence reputation match",
                severity=severity,
                event_id=event_id,
                reason=(f"VirusTotal reported {reputation.malicious} malicious and "
                        f"{reputation.suspicious} suspicious engine result(s) for the SHA-256 hash."),
                recommended_action="Validate the reputation, preserve evidence, and investigate the affected host.",
                evidence={"sha256": reputation.sha256, "malicious": reputation.malicious,
                          "suspicious": reputation.suspicious, "total_engines": reputation.total_engines,
                          "tags": list(reputation.tags)},
            ))
    return alerts
