"""Analyst workbench behind the dashboard: file triage, reputation, IOCs, reports.

Uploaded samples are stored as inert bytes (no execute permission, no
original extension) and are only ever read by the static analyzer.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

from siem.ai.openai_reports import AIIntegrationError, generate_ai_report
from siem.analysis.static import analyze_file
from siem.domain.alerts import Alert
from siem.domain.events import SecurityEvent
from siem.intel.external import ReputationCache, reputation_alert
from siem.intel.matcher import match_event, match_events
from siem.intel.store import IOCStore
from siem.intel.virustotal import lookup_hash
from siem.reporting.report import build_context, render_markdown
from siem.response.quarantine import quarantine_file
from siem.storage.sqlite import SqliteEventStore


MAX_SAMPLE_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEVERITY = {"suspicious": "high", "potentially-suspicious": "medium"}


class WorkbenchError(ValueError):
    """A request the workbench cannot fulfil; the message is safe to show."""


class FeatureUnavailable(WorkbenchError):
    """An optional integration (VirusTotal, AI) is not configured."""


def ai_available() -> bool:
    if not os.getenv("OPENAI_API_KEY"):
        return False
    try:
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


class Workbench:
    def __init__(self, root: Path, store: SqliteEventStore) -> None:
        self.store = store
        self.samples = root / "samples"
        self.quarantine_dir = root / "quarantine"
        self.analyses_path = root / "file-analyses.json"
        self.iocs = IOCStore(root / "threat-intel.db")
        self.reputation = ReputationCache(root / "external-intel-cache.json")
        self.lock = threading.Lock()
        self.records: dict[str, dict[str, Any]] = {}
        if self.analyses_path.exists():
            try:
                self.records = json.loads(self.analyses_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.records = {}

    @staticmethod
    def capabilities() -> dict[str, bool]:
        return {"virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")), "ai": ai_available()}

    def _save(self) -> None:
        self.analyses_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.analyses_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.records, sort_keys=True), encoding="utf-8")
        temporary.replace(self.analyses_path)

    def _record(self, sha256: str) -> dict[str, Any]:
        sha256 = sha256.lower()
        if not _SHA256.match(sha256) or sha256 not in self.records:
            raise WorkbenchError("unknown sample; analyze the file first")
        return self.records[sha256]

    def analyses(self) -> list[dict[str, Any]]:
        return sorted(self.records.values(), key=lambda record: record["analyzed_at"], reverse=True)

    def analyze_upload(self, filename: str, content: bytes, actor: str) -> dict[str, Any]:
        if not content:
            raise WorkbenchError("the file is empty")
        if len(content) > MAX_SAMPLE_BYTES:
            raise WorkbenchError(f"files larger than {MAX_SAMPLE_BYTES // (1024 * 1024)} MiB are not accepted")
        name = Path(filename.replace("\\", "/")).name[:128] or "upload"
        sha256 = hashlib.sha256(content).hexdigest()
        self.samples.mkdir(parents=True, exist_ok=True)
        sample = self.samples / f"{sha256}.sample"
        if not sample.exists():
            descriptor = os.open(sample, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
        record = analyze_file(sample).to_record()
        record.update(path=name, filename=name, extension=Path(name).suffix.lower(), analyst=actor,
                      analyzed_at=datetime.now(timezone.utc).isoformat(), quarantined=False,
                      ioc=self.iocs.find("sha256", sha256), virustotal=None)
        with self.lock:
            previous = self.records.get(sha256, {})
            record["virustotal"] = previous.get("virustotal")
            self.records[sha256] = record
            self._save()

        # The analysis is itself evidence: an event the IOC matcher and reports can see.
        event = SecurityEvent.now(
            source="siem-workbench", event_type="file.analyzed",
            message=f"{name} analyzed by {actor}: {record['classification']}",
            severity=_SEVERITY.get(record["classification"], "info"),
            attributes={"sha256": sha256, "filename": name, "classification": record["classification"],
                        "capabilities": sorted(record["capabilities"]), "analyst": actor},
        ).to_record()
        self.store.append_records([event])
        alerts = [alert.to_record() for alert in match_event(event, self.iocs)]
        if record["classification"] == "suspicious":
            reasons = ", ".join(sorted(record["capabilities"])) or ", ".join(record["indicators"])
            alerts.append(Alert(
                rule_id="file.suspicious", title=f"Suspicious file: {name}", severity="high",
                event_id=event["event_id"], reason=f"Static analysis found: {reasons}.",
                recommended_action="Check the hash reputation, find where the file came from, and quarantine it if confirmed.",
                evidence={"sha256": sha256, "indicators": record["indicators"]},
            ).to_record())
        record["alerts"] = len(self.store.append_alerts(alerts))
        return record

    def check_reputation(self, sha256: str) -> dict[str, Any]:
        record = self._record(sha256)
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise FeatureUnavailable("VirusTotal is not configured: set VIRUSTOTAL_API_KEY and restart the server")
        reputation = self.reputation.get(record["sha256"])
        if reputation is None:
            reputation = lookup_hash(record["sha256"], api_key)
            self.reputation.put(reputation)
        result = reputation.to_record()
        result["permalink"] = f"https://www.virustotal.com/gui/file/{reputation.sha256}"
        with self.lock:
            record["virustotal"] = result
            self._save()
        if alert := reputation_alert(reputation, f"file:{reputation.sha256}"):
            self.store.append_alerts([alert.to_record()])
        return result

    def quarantine(self, sha256: str, actor: str) -> dict[str, Any]:
        record = self._record(sha256)
        if record["quarantined"]:
            raise WorkbenchError("this sample is already quarantined")
        result = quarantine_file(self.samples / f"{record['sha256']}.sample", self.quarantine_dir, apply=True)
        with self.lock:
            record.update(quarantined=True, quarantined_by=actor, quarantine_path=result.destination.name)
            self._save()
        self.store.append(SecurityEvent.now(
            source="siem-workbench", event_type="file.quarantined", severity="medium",
            message=f"{record['filename']} quarantined by {actor}",
            attributes={"sha256": record["sha256"], "filename": record["filename"], "analyst": actor},
        ))
        return record

    def add_indicator(self, kind: str, value: str, source: str, confidence: int) -> None:
        self.iocs.add(kind, value, source=source, confidence=confidence)
        if kind == "sha256" and (record := self.records.get(value.strip().lower())):
            with self.lock:
                record["ioc"] = self.iocs.find("sha256", value)
                self._save()

    def scan_events(self, limit: int = 10000) -> dict[str, int]:
        events = self.store.search(limit=limit)
        stored = self.store.append_alerts([alert.to_record() for alert in match_events(events, self.iocs)])
        return {"events_scanned": len(events), "new_alerts": len(stored)}

    def _analysis(self, sha256: str | None) -> dict[str, Any] | None:
        if not sha256:
            return None
        return {key: value for key, value in self._record(sha256).items() if key != "strings"}

    def report_context(self, sha256: str | None = None, alert_limit: int = 100) -> dict[str, Any]:
        return build_context(self.store.search_alerts(limit=alert_limit), self._analysis(sha256))

    def ai_context(self, sha256: str | None = None) -> dict[str, Any]:
        """Compact evidence for the AI: counts per rule plus the high/critical alerts.

        Hundreds of near-identical raw alerts overflow small (local) models,
        which then invent findings; the counts keep the full picture.
        """
        alerts = self.store.search_alerts(limit=10000)
        important = [{key: alert.get(key) for key in ("severity", "title", "reason")}
                     for alert in alerts if alert.get("severity") in {"critical", "high"}][:25]
        context = build_context(important, self._analysis(sha256))
        context["alert_count"] = len(alerts)
        context["alerts_by_rule"] = [{"severity": severity, "rule": rule, "count": count}
                                     for (severity, rule), count in Counter(
                                         (alert.get("severity"), alert.get("rule_id")) for alert in alerts).most_common()]
        context["limitations"].append("'alerts' lists only high and critical alerts; 'alerts_by_rule' counts all of them.")
        return context

    def report(self, sha256: str | None = None) -> str:
        return render_markdown(self.report_context(sha256))

    def ai_report(self, sha256: str | None = None) -> str:
        if not ai_available():
            raise FeatureUnavailable("AI reporting is not configured: install the 'openai' package, "
                                     "set OPENAI_API_KEY and restart the server")
        try:
            return generate_ai_report(self.ai_context(sha256),
                                      model=os.getenv("OPENAI_MODEL", "gpt-5"))
        except AIIntegrationError as exc:
            raise WorkbenchError(str(exc)) from exc
