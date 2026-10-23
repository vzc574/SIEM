"""SQLite persistence for normalized security events."""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Iterator
from datetime import datetime, timezone
from uuid import uuid4

from siem.domain.events import SecurityEvent


SCHEMA_VERSION = 2
# Attribute fields promoted to indexed generated columns for fast pivots.
INDEXED_ATTRIBUTES = ("username", "src_ip")
_PIVOT_COLUMNS = {"source", "host", "event_type", "severity", *INDEXED_ATTRIBUTES}


def to_utc(value: str | datetime) -> str:
    """Normalize a timestamp to UTC ISO-8601 so text order equals time order."""
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection, commit (or roll back) the block, and always close it."""
    connection = sqlite3.connect(path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


class SqliteEventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        return connect(self.path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            # WAL lets the API read while the worker writes to the same file.
            connection.execute("PRAGMA journal_mode = WAL")
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
                CREATE INDEX IF NOT EXISTS idx_incidents_title ON incidents(title);
                CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
            """)
            if connection.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
                self._migrate(connection)

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        columns = {row["name"] for row in connection.execute("PRAGMA table_xinfo(security_events)")}
        for name in INDEXED_ATTRIBUTES:
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE security_events ADD COLUMN {name} TEXT "
                    f"GENERATED ALWAYS AS (json_extract(attributes_json, '$.{name}')) VIRTUAL"
                )
            connection.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{name} ON security_events({name}, observed_at)")
        # Version 1 stored mixed UTC offsets, which broke ordering and retention.
        rows = connection.execute("SELECT event_id, observed_at FROM security_events WHERE observed_at NOT LIKE '%+00:00'").fetchall()
        for row in rows:
            try:
                connection.execute("UPDATE security_events SET observed_at = ? WHERE event_id = ?",
                                   (to_utc(row["observed_at"]), row["event_id"]))
            except ValueError:
                continue
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def append(self, event: SecurityEvent) -> None:
        self.append_records([event.to_record()])

    def append_records(self, records: Iterable[dict[str, Any]]) -> int:
        count = 0
        with self._connect() as connection:
            for record in records:
                connection.execute(
                    """INSERT OR IGNORE INTO security_events
                    (event_id, source, event_type, message, observed_at, severity, host, attributes_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (str(record["event_id"]), record["source"], record["event_type"], record["message"],
                     to_utc(record["observed_at"]), record.get("severity", "info"), record.get("host"),
                     json.dumps(record.get("attributes", {}), sort_keys=True)),
                )
                count += 1
        return count

    @staticmethod
    def _event_record(row: sqlite3.Row) -> dict[str, Any]:
        item = {key: row[key] for key in row.keys() if key not in INDEXED_ATTRIBUTES}
        item["attributes"] = json.loads(item.pop("attributes_json"))
        return item

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
        return [self._event_record(row) for row in rows]

    def events_since(self, since: datetime, *, event_types: Iterable[str] | None = None, limit: int = 50000) -> list[dict[str, Any]]:
        """Events observed at or after `since`, oldest first (correlation lookback)."""
        query = "SELECT * FROM security_events WHERE observed_at >= ?"
        parameters: list[Any] = [to_utc(since)]
        types = list(event_types or [])
        if types:
            query += f" AND event_type IN ({', '.join('?' for _ in types)})"
            parameters.extend(types)
        query += " ORDER BY observed_at ASC LIMIT ?"
        parameters.append(max(1, limit))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._event_record(row) for row in rows]

    def top_values(self, column: str, *, since: datetime | None = None, event_type: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        """Most frequent values of one pivot column, e.g. top attacking `src_ip`."""
        if column not in _PIVOT_COLUMNS:
            raise ValueError(f"unsupported pivot column: {column}")
        clauses = [f"{column} IS NOT NULL"]
        parameters: list[Any] = []
        if since:
            clauses.append("observed_at >= ?")
            parameters.append(to_utc(since))
        if event_type:
            clauses.append("event_type = ?")
            parameters.append(event_type)
        parameters.append(max(1, min(limit, 100)))
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {column} AS value, COUNT(*) AS count FROM security_events WHERE {' AND '.join(clauses)} "
                "GROUP BY value ORDER BY count DESC, value LIMIT ?",
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def severity_counts(self, *, since: datetime | None = None) -> dict[str, int]:
        query = "SELECT severity, COUNT(*) FROM security_events"
        parameters: list[Any] = []
        if since:
            query += " WHERE observed_at >= ?"
            parameters.append(to_utc(since))
        with self._connect() as connection:
            return {row[0]: row[1] for row in connection.execute(query + " GROUP BY severity", parameters)}

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

    def find_open_incident(self, title: str) -> dict[str, Any] | None:
        """The most recent open/investigating incident with this exact title."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE title = ? AND status IN ('open', 'investigating') ORDER BY updated_at DESC LIMIT 1",
                (title,),
            ).fetchone()
        return self._incident_record(row) if row else None

    def attach_alerts(self, incident_id: str, alert_ids: list[str], *, actor: str, severity: str | None = None) -> dict[str, Any] | None:
        """Add alerts to an existing incident, optionally escalating its severity."""
        current = self.get_incident(incident_id)
        if current is None:
            return None
        ranks = ["low", "medium", "high", "critical"]
        new_severity = current["severity"]
        if severity in ranks and ranks.index(severity) > ranks.index(new_severity):
            new_severity = severity
        merged = current["alert_ids"] + [alert_id for alert_id in alert_ids if alert_id not in current["alert_ids"]]
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("UPDATE incidents SET alert_ids_json = ?, severity = ?, updated_at = ? WHERE incident_id = ?",
                               (json.dumps(merged), new_severity, now, incident_id))
            self._audit(connection, incident_id, "alerts_attached", actor, {"alert_ids": alert_ids, "severity": new_severity})
        return self.get_incident(incident_id)

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
        if assignee is not None and (not isinstance(assignee, str) or len(assignee) > 200):
            raise ValueError("assignee must be a string of at most 200 characters")
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
