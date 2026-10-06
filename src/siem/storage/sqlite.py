"""SQLite persistence for normalized security events."""

import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable
from datetime import datetime, timezone
from uuid import uuid4

from siem.domain.events import SecurityEvent


class SqliteEventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT,
                    attributes_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_observed_at ON security_events(observed_at);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee TEXT,
                    alert_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
            """)

    def append(self, event: SecurityEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO security_events
                (event_id, source, event_type, message, observed_at, severity, host, attributes_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(event.event_id), event.source, event.event_type, event.message,
                 event.observed_at.isoformat(), event.severity, event.host,
                 json.dumps(event.attributes, sort_keys=True)),
            )

    def append_records(self, records: Iterable[dict[str, Any]]) -> int:
        count = 0
        with self._connect() as connection:
            for record in records:
                connection.execute(
                    """INSERT OR IGNORE INTO security_events
                    (event_id, source, event_type, message, observed_at, severity, host, attributes_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (str(record["event_id"]), record["source"], record["event_type"], record["message"],
                     record["observed_at"], record.get("severity", "info"), record.get("host"),
                     json.dumps(record.get("attributes", {}), sort_keys=True)),
                )
                count += 1
        return count

    def search(self, *, text: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if text:
            clauses.append("(message LIKE ? OR event_type LIKE ? OR source LIKE ?)")
            needle = f"%{text}%"
            parameters.extend([needle, needle, needle])
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity.lower())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 1000)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_events" + where + " ORDER BY observed_at DESC LIMIT ?",
                parameters,
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["attributes"] = json.loads(item.pop("attributes_json"))
            results.append(item)
        return results

    def create_incident(self, title: str, severity: str, alert_ids: list[str], *, actor: str) -> dict[str, Any]:
        if not title.strip():
            raise ValueError("incident title must not be empty")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid incident severity")
        now = datetime.now(timezone.utc).isoformat()
        incident_id = str(uuid4())
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO incidents VALUES (?, ?, ?, 'open', NULL, ?, ?, ?)",
                (incident_id, title, severity, json.dumps(alert_ids), now, now),
            )
            self._audit(connection, incident_id, "created", actor, {"alert_ids": alert_ids})
        return self.get_incident(incident_id)  # type: ignore[return-value]

    def list_incidents(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents"
        parameters: list[Any] = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY updated_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 1000)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._incident_record(row) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._incident_record(row) if row else None

    def update_incident(self, incident_id: str, *, actor: str, status: str | None = None, assignee: str | None = None) -> dict[str, Any] | None:
        if status is not None and status not in {"open", "investigating", "resolved", "closed"}:
            raise ValueError("invalid incident status")
        current = self.get_incident(incident_id)
        if current is None:
            return None
        changes: dict[str, Any] = {}
        if status is not None:
            changes["status"] = status
        if assignee is not None:
            changes["assignee"] = assignee
        if not changes:
            return current
        now = datetime.now(timezone.utc).isoformat()
        assignments = ", ".join(f"{key} = ?" for key in changes)
        values = list(changes.values()) + [now, incident_id]
        with self._connect() as connection:
            connection.execute(f"UPDATE incidents SET {assignments}, updated_at = ? WHERE incident_id = ?", values)
            self._audit(connection, incident_id, "updated", actor, changes)
        return self.get_incident(incident_id)

    def audit_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_log WHERE incident_id = ? ORDER BY created_at", (incident_id,)).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def metrics(self) -> dict[str, int]:
        with self._connect() as connection:
            events = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            incidents = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_incidents = connection.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')").fetchone()[0]
            audit_entries = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {"security_events": events, "incidents": incidents, "open_incidents": open_incidents, "audit_entries": audit_entries}

    @staticmethod
    def _audit(connection: sqlite3.Connection, incident_id: str, action: str, actor: str, details: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid4()), incident_id, action, actor, json.dumps(details, sort_keys=True), datetime.now(timezone.utc).isoformat()),
        )

    @staticmethod
    def _incident_record(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["alert_ids"] = json.loads(item.pop("alert_ids_json"))
        return item
